using System;
using System.Security.Cryptography;

namespace Confuzzle
{
    /// <summary>
    ///     Handles the encryption and decryption of data using AES CTR mode transformation.
    /// </summary>
    /// <remarks>
    ///     AES CTR mode works differently to most encryption methods. Rather than encrypting the data directly, CTR
    ///     mode encrypts blocks of data containing a nonce and a counter value. The encrypted block is then XOR'd with
    ///     the data to encrypt or decrypt it.
    ///
    ///     The biggest benefit of CTR mode is that the encrypted data does not need to be processed sequentially. This
    ///     allows for random access, and for blocks to be potentially decrypted in parallel.
    /// </remarks>
    internal class CtrModeTransform : IDisposable
    {
        /// <summary>
        ///     The preferred size of the CTR transformation block, in bytes.
        /// </summary>
        /// <remarks>
        ///     After some performance tuning, it appears this is the optimum transform length.
        /// </remarks>
        private const int PreferredTransformLength = 4096;

        private readonly CipherStream _stream;
        private readonly int _blockLength;
        private readonly int _blocksPerTransform;
        private readonly int _ctrTransformLength;

        private ICryptoTransform _cryptoTransform;
        private byte[] _ctrSeed;
        private byte[] _ctrTransform;
        private long _startBlock = -1;
        private long _endBlock = -1;

        public CtrModeTransform(CipherStream stream)
        {
            if (stream == null) throw new ArgumentNullException(nameof(stream));

            _stream = stream;

            _blockLength = _stream.BlockLength;
            _blocksPerTransform = PreferredTransformLength / _blockLength;
            _ctrTransformLength = _blockLength * _blocksPerTransform;
        }

        /// <summary>
        ///     Performs an in-place transformation of a block of data.
        /// </summary>
        /// <param name="fromPosition">
        ///     The position of the first byte of data to transform, relative to the start of the steam.
        /// </param>
        /// <param name="data">The data to be transformed.</param>
        /// <param name="offset">The offset into the data at which to start transformation.</param>
        /// <param name="length">The length of data to be transformed.</param>
        public void Transform(long fromPosition, byte[] data, int offset, int length)
        {
            if (data == null) throw new ArgumentNullException(nameof(data));

            while (length > 0)
            {
                // Prepare the transformation for the current initial position.
                PrepareTransform(fromPosition);

                // Calculate where in the CTR transformation to start and how much can be processed.
                var xorIndex = (int)(fromPosition % _ctrTransformLength);
                var xorCount = Math.Min(_ctrTransformLength - xorIndex, length);

                // Do the XOR transformation based on the CTR transformation block.
                for (var index = 0; index < xorCount; ++index)
                    data[offset + index] ^= _ctrTransform[xorIndex + index];

                // Update the count and offsets based on the amount of data copied this round.
                fromPosition += xorCount;
                offset += xorCount;
                length -= xorCount;
            }
        }

        /// <summary>
        ///     Initializes the CTR mode transformation.
        /// </summary>
        /// <remarks>
        ///     This is designed as a late initialization, so that the stream has an opportunity to correctly set up the
        ///     key and nonce.
        /// </remarks>
        private void Initialize()
        {
            // Create the symmetric block cipher used to transform CTR blocks.
            using (var cipher = _stream.CipherFactory.CreateCipher())
            {
                // Each block is encrypted independently (ECB mode).
                cipher.Mode = CipherMode.ECB;
                // No padding is needed.
                cipher.Padding = PaddingMode.None;

                // Get the key and IV.
                var key = _stream.Key.GetKeyBytes(cipher);
                var iv = CreateIV();

                _cryptoTransform = cipher.CreateEncryptor(key, iv);
            }

            // Fill as much of the CTR seed as possible using the nonce. The nonce should take up between 50% and 100%
            // of the seed block.
            _ctrSeed = new byte[_blockLength];
            Array.Copy(_stream.Nonce, 0, _ctrSeed, 0, Math.Min(_stream.Nonce.Length, 8));

            // Allocate the entire transformation block.
            _ctrTransform = new byte[_ctrTransformLength];
        }

        /// <summary>
        ///     Creates an initialization vector for the symmetric block cipher.
        /// </summary>
        private byte[] CreateIV()
        {
            var iv = new byte[_blockLength];

            using (var hashFunction = _stream.CipherFactory.CreateHash())
            {
                // The IV is based on the nonce and any associated user data.
                var ivSeed = new byte[_stream.Nonce.Length + _stream.PasswordSalt.Length];
                Array.Copy(_stream.Nonce, 0, ivSeed, 0, _stream.Nonce.Length);
                Array.Copy(_stream.PasswordSalt, 0, ivSeed, _stream.Nonce.Length, _stream.PasswordSalt.Length);

                // Fill the IV using the hash of the seed. This may use only part of the hash, or may repeat some or all
                // of the hash.
                iv.Fill(hashFunction.ComputeHash(ivSeed));
            }

            return iv;
        }

        /// <summary>
        ///     Prepares to transform a block of data starting at a given offset.
        /// </summary>
        /// <param name="fromPosition">The position of the first byte in the data to be transformed.</param>
        private void PrepareTransform(long fromPosition)
        {
            if (fromPosition < 0) throw new ArgumentException("Stream position cannot be less than 0.", nameof(fromPosition));

            if (_cryptoTransform == null)
                Initialize();

            // Get the block number for the position. If it's within the current range, there's nothing to do.
            var blockNumber = (fromPosition / _blockLength);
            if (blockNumber <= _startBlock && blockNumber < _endBlock)
                return;

            // Calculate the start and end block indices for the transform.
            var startBlock = (blockNumber / _blocksPerTransform) * _blocksPerTransform;
            var endBlock = startBlock + _blocksPerTransform;

            // Allocate memory for the seed blocks.
            var blockInit = new byte[_ctrTransformLength];

            // Modify each block with the counter value.
            for (var blockIndex = 0; blockIndex < _blocksPerTransform; ++blockIndex)
            {
                // Array segment for the seed block.
                var ctrBlock = new ArraySegment<byte>(blockInit, blockIndex * _blockLength, _blockLength);
                // 1-based number of the block, relative to the start of the stream.
                var ctrNumber = startBlock + blockIndex + 1;
                // Fill the block.
                FillCtrSeedBlock(ctrBlock, ctrNumber);
            }

            // Encrypt the seed blocks to create the transformation block.
            _cryptoTransform.TransformBlock(blockInit, 0, _ctrTransformLength, _ctrTransform, 0);

            // Clear the initialization block.
            Array.Clear(blockInit, 0, blockInit.Length);

            // Save the start and end block indices.
            _startBlock = startBlock;
            _endBlock = endBlock;
        }

        /// <summary>
        ///     Fills a CTR seed block with the nonce and CTR block number.
        /// </summary>
        /// <param name="block">
        ///     An array segment representing the CTR seed block to fill.
        /// </param>
        /// <param name="blockNumber">
        ///     A 1-based index of the CTR block from the start of the data.
        /// </param>
        private void FillCtrSeedBlock(ArraySegment<byte> block, long blockNumber)
        {
            // Copy in the empty seed data.
            Array.Copy(_ctrSeed, 0, block.Array, block.Offset, _blockLength);

            // Update the CTR seed block with the block number. This starts at the end of the block and works backwards.
            for (var offset = block.Offset + _blockLength - 1;
                offset >= block.Offset && blockNumber != 0;
                --offset)
            {
                // The least significant byte of the block number.
                var blockNumberByte = (byte) (blockNumber & 0xFF);
                blockNumber >>= 8;

                // XOR the counter byte value into the block.
                block.Array[offset] ^= blockNumberByte;
            }
        }

        #region IDisposable

        private bool _isDisposed = false; // To detect redundant calls

        protected virtual void Dispose(bool disposing)
        {
            if (!_isDisposed)
            {
                if (disposing)
                {
                    // Free managed resources.

                    if (_cryptoTransform != null)
                    {
                        _cryptoTransform.Dispose();
                        _cryptoTransform = null;
                    }

                    if (_ctrTransform != null)
                    {
                        Array.Clear(_ctrTransform, 0, _ctrTransform.Length);
                        _ctrTransform = null;
                    }
                }

                _isDisposed = true;
            }
        }

        // This code added to correctly implement the disposable pattern.
        public void Dispose()
        {
            // Do not change this code. Put cleanup code in Dispose(bool disposing) above.
            Dispose(true);
        }
        #endregion
    }
}
