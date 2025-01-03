﻿using System.Security.Cryptography;

namespace ConfuzzleCore
{
    /// <summary>
    ///     A filter stream that encrypts and decrypts data to/from an underlying stream.
    /// </summary>
    /// <remarks>
    ///     The encrypted data starts with a header that contains information necessary to perform the decryption.
    ///     The layout of the header is as follows:
    ///     * A 16-bit unsigned integer saying how much data is in the rest of the header.
    ///     * A 16-bit unsigned integer saying how long the nonce is.
    ///     * Variable length nonce.
    ///     * A 16-bit unsigned integer saying how long the password salt is.
    ///     * Variable length password salt.
    /// </remarks>
    public class CipherStream : Stream
    {
        /// <summary>
        ///     The number of bytes in the header that's used by the data length fields.
        /// </summary>
        private const int HeaderOverhead = 2 * sizeof(ushort);

        private Stream stream;
        private CtrModeTransform ctrTransform;
        private long position;
        private long startPosition;

        /// <summary>
        ///     Creates a new <see cref="CipherStream" />.
        /// </summary>
        /// <param name="stream">The underlying stream for storing encrypted data.</param>
        /// <param name="key">The key used to encrypt the data.</param>
        /// <param name="cipherFactory">
        ///     A factory for creating cryptographic algorithms. If <c>null</c> is provided, a default factory will be
        ///     used.
        /// </param>
        private CipherStream(Stream stream, KeyStretcher key, ICipherFactory? cipherFactory)
        {
            this.stream = stream;
            Key = key;
            CipherFactory = cipherFactory ?? ConfuzzleCore.CipherFactory.Default;

            using (var cipher = CipherFactory.CreateCipher())
            {
                BlockLength = cipher.BlockSize / 8;
            }

            this.ctrTransform = new CtrModeTransform(this);
        }

        /// <summary>
        ///     The length of cipher processing blocks in bytes.
        /// </summary>
        internal int BlockLength { get; }

        /// <summary>
        ///     Indicates whether the current stream supports reading.
        /// </summary>
        public override bool CanRead
        {
            get
            {
                OutputStreamDisposed();
                return this.stream.CanRead;
            }
        }

        private void OutputStreamDisposed()
        {
            if (this.stream == null)
            {
                throw new ObjectDisposedException("Underlying output stream has been disposed.");
            }
        }

        /// <summary>
        ///     Indicates whether the current stream supports seeking.
        /// </summary>
        public override bool CanSeek
        {
            get
            {
                OutputStreamDisposed();
                return this.stream.CanSeek;
            }
        }

        /// <summary>
        ///     Indicates whether the stream operations can timeout.
        /// </summary>
        public override bool CanTimeout
        {
            get
            {
                OutputStreamDisposed();
                return this.stream.CanTimeout;
            }
        }

        /// <summary>
        ///     Indicates whether the current stream supports writing.
        /// </summary>
        public override bool CanWrite
        {
            get
            {
                OutputStreamDisposed();
                return this.stream.CanWrite;
            }
        }

        /// <summary>
        ///     The factory used to create cryptographic algorithms.
        /// </summary>
        internal ICipherFactory CipherFactory { get; }

        /// <summary>
        ///     The key used during cryptographic transformations.
        /// </summary>
        internal KeyStretcher Key { get; }

        /// <summary>
        ///     Gets the length of the plaintext data, in bytes.
        /// </summary>
        /// <remarks>
        ///     The length of the underlying stream will differ due to the presence of the cryptographic header.
        /// </remarks>
        public override long Length
        {
            get
            {
                OutputStreamDisposed();
                return this.stream.Length - this.startPosition;
            }
        }

        /// <summary>
        ///     The maximum length of the nonce in bytes.
        /// </summary>
        public int MaxNonceLength => BlockLength;

        /// <summary>
        ///     The minimum length of the nonce in bytes.
        /// </summary>
        public int MinNonceLength => BlockLength / 2;

        /// <summary>
        ///     A random value used to ensure that each encrypted file has different ciphertext.
        /// </summary>
        public byte[]? Nonce { get; private set; }

        /// <summary>
        ///     Any user-supplied data that should be saved with the stream.
        /// </summary>
        /// <remarks>
        ///     The password salt is stored in this field.
        /// </remarks>
        public byte[] PasswordSalt => Key.Salt;

        /// <summary>
        ///     Gets or sets the current position in the plaintext data stream.
        /// </summary>
        /// <remarks>
        ///     The position the underlying stream will differ due to the presence of the cryptographic header.
        /// </remarks>
        public override long Position
        {
            get
            {
                OutputStreamDisposed();
                return this.position;
            }
            set => Seek(value, SeekOrigin.Begin);
        }

        /// <summary>
        ///     A random number generator for creating nonces.
        /// </summary>
        public static RandomNumberGenerator Rng { get; set; } = new RNGCryptoServiceProvider();

        /// <summary>
        ///     Creates a new <see cref="CipherStream" /> over a data stream.
        /// </summary>
        /// <param name="stream">The stream that will hold the encrypted data.</param>
        /// <param name="key">The key used to encrypt the data.</param>
        /// <param name="cipherFactory">
        ///     A factory for creating cryptographic algorithms. If <c>null</c> is provided, a default factory will be
        ///     used.
        /// </param>
        /// <param name="nonce">
        ///     A random value that helps prevent the same plaintext from being converted to the same ciphertext every
        ///     time. If <c>null</c> is provided, a new nonce will be generated.
        /// </param>
        /// <returns>
        ///     A <see cref="CipherStream" /> ready to encrypt data.
        /// </returns>
        public static CipherStream Create(Stream stream, KeyStretcher key, ICipherFactory? cipherFactory = null, byte[]? nonce = null)
        {
            if (stream == null)
            {
                throw new ArgumentNullException(nameof(stream));
            }

            if (key == null)
            {
                throw new ArgumentNullException(nameof(key));
            }

            var ctrStream = new CipherStream(stream, key, cipherFactory);
            ctrStream.SetupParameters(nonce);
            return ctrStream;
        }

        /// <summary>
        ///     Creates a new <see cref="CipherStream" /> over a data stream.
        /// </summary>
        /// <param name="stream">The stream that will hold the encrypted data.</param>
        /// <param name="password">The password used to encrypt the data.</param>
        /// <param name="cipherFactory">
        ///     A factory for creating cryptographic algorithms. If <c>null</c> is provided, a default factory will be
        ///     used.
        /// </param>
        /// <param name="nonce">
        ///     A random value that helps prevent the same plaintext from being converted to the same ciphertext every
        ///     time. If <c>null</c> is passed, a new nonce will be generated.
        /// </param>
        /// <param name="salt">
        ///     A random value used when converting the password to a cryptographic key. If <c>null</c> is passed, a new
        ///     salt will be generated.
        /// </param>
        /// <returns>
        ///     A <see cref="CipherStream" /> ready to encrypt data.
        /// </returns>
        public static CipherStream Create(Stream stream, string password, ICipherFactory? cipherFactory = null, byte[]? nonce = null, byte[]? salt = null)
        {
            if (stream == null)
            {
                throw new ArgumentNullException(nameof(stream));
            }

            if (string.IsNullOrWhiteSpace(password))
            {
                throw new ArgumentNullException(nameof(password));
            }

            var key = new KeyStretcher(password, salt);
            var ctrStream = new CipherStream(stream, key, cipherFactory);
            ctrStream.SetupParameters(nonce);
            return ctrStream;
        }

        /// <summary>
        ///     Clears all buffers for this stream and causes any buffered data to be written.
        /// </summary>
        public override void Flush()
        {
            OutputStreamDisposed();
            this.stream.Flush();
        }

        /// <summary>
        ///     Creates a <see cref="CipherStream" /> over encrypted data stored in a data stream.
        /// </summary>
        /// <param name="stream">The stream that contains encrypted data.</param>
        /// <param name="key">The key used to encrypt the data.</param>
        /// <param name="cipherFactory">
        ///     A factory for creating cryptographic algorithms. If <c>null</c> is provided, a default factory will be
        ///     used.
        /// </param>
        /// <returns>
        ///     A <see cref="CipherStream" /> ready to encrypt and decrypt data.
        /// </returns>
        public static CipherStream Open(Stream stream, KeyStretcher key, ICipherFactory? cipherFactory = null)
        {
            var ctrStream = new CipherStream(stream, key, cipherFactory);
            ctrStream.LoadParameters();
            return ctrStream;
        }

        /// <summary>
        ///     Creates a <see cref="CipherStream" /> over encrypted data stored in a data stream.
        /// </summary>
        /// <param name="stream">The stream that contains encrypted data.</param>
        /// <param name="password">The password used to encrypt the data.</param>
        /// <param name="cipherFactory">
        ///     A factory for creating cryptographic algorithms. If <c>null</c> is provided, a default factory will be
        ///     used.
        /// </param>
        /// <returns>
        ///     A <see cref="CipherStream" /> ready to encrypt and decrypt data.
        /// </returns>
        public static CipherStream Open(Stream stream, string password, ICipherFactory cipherFactory = null)
        {
            var key = new KeyStretcher(password);
            var ctrStream = new CipherStream(stream, key, cipherFactory);
            ctrStream.LoadParameters();
            return ctrStream;
        }

        /// <summary>
        ///     Reads a sequence of plaintext bytes from the current stream and advances the position within the stream
        ///     by the number of bytes read.
        /// </summary>
        /// <param name="buffer">
        ///     An array of bytes. When this method returns, the buffer contains the specified byte array with the
        ///     values between <paramref name="offset" /> and ( <paramref name="offset" /> + <paramref name="count" /> - 1)
        ///     replaced by the bytes read from the current source.
        /// </param>
        /// <param name="offset">
        ///     The zero-based byte offset in <paramref name="buffer" /> at which to begin storing the data read from the
        ///     current stream.
        /// </param>
        /// <param name="count">
        ///     The maximum number of bytes to be read from the current stream.
        /// </param>
        /// <returns>
        ///     The total number of bytes read into the buffer. This can be less than the number of bytes requested if
        ///     that many bytes are not currently available, or zero (0) if the end of the stream has been reached.
        /// </returns>
        public override int Read(byte[] buffer, int offset, int count)
        {
            OutputStreamDisposed();
            // Read data into the buffer.
            var sizeRead = this.stream.Read(buffer, offset, count);

            // If data was available, transform it and update the stream position.
            if (sizeRead > 0)
            {
                this.ctrTransform.Transform(this.position, buffer, offset, sizeRead);
                this.position += sizeRead;
            }

            return sizeRead;
        }

        /// <summary>
        ///     Sets the position within the current plaintext data stream.
        /// </summary>
        /// <param name="offset">A byte offset relative to the <paramref name="origin" /> parameter.</param>
        /// <param name="origin">
        ///     A value of type <see cref="SeekOrigin" /> indicating the reference point used to obtain the new position.
        /// </param>
        /// <returns>The new position within the current stream.</returns>
        /// <remarks>
        ///     The position the underlying stream will differ due to the presence of the cryptographic header.
        /// </remarks>
        public override long Seek(long offset, SeekOrigin origin)
        {
            OutputStreamDisposed();
            if (!this.stream.CanSeek)
            {
                throw new NotSupportedException("Stream is not seekable.");
            }

            long streamPosition;

            switch (origin)
            {
                case SeekOrigin.Begin:
                    // Seek relative to the stream header.
                    streamPosition = this.stream.Seek(this.startPosition + offset, SeekOrigin.Begin);
                    break;

                default:
                    streamPosition = this.stream.Seek(offset, origin);
                    break;
            }

            // Ensure that the position does not precede the start of the encrypted data.
            if (streamPosition < this.startPosition)
            {
                streamPosition = this.stream.Seek(this.startPosition, SeekOrigin.Begin);
            }

            // Save the updated position, relative to the start of the encrypted data.
            this.position = streamPosition - this.startPosition;

            return this.position;
        }

        /// <summary>
        ///     Sets the length of the current stream.
        /// </summary>
        /// <param name="value">The desired length of the plaintext data stream in bytes.</param>
        /// <remarks>
        ///     The length of the underlying stream will differ due to the presence of the cryptographic header.
        /// </remarks>
        public override void SetLength(long value)
        {
            OutputStreamDisposed();
            this.stream.SetLength(this.startPosition + value);
        }

        /// <summary>
        ///     Writes a sequence of bytes to the current stream and advances the current position within this stream by
        ///     the number of bytes written.
        /// </summary>
        /// <param name="buffer">
        ///     An array of bytes.
        /// </param>
        /// <paramref name="count/">
        ///     bytes from <paramref name="buffer" /> to
        ///     the current stream.
        /// </paramref>
        /// <param name="offset">
        ///     The zero-based byte offset in <paramref name="buffer" /> at which to begin copying bytes to the current
        ///     stream.
        /// </param>
        /// <param name="count">The number of bytes to be written to the current stream.</param>
        public override void Write(byte[] buffer, int offset, int count)
        {
            OutputStreamDisposed();
            // Copy the data so that the original values are not modified.
            var writeBuffer = new byte[count];
            Array.Copy(buffer, offset, writeBuffer, 0, count);

            // Transform the data and write it.
            this.ctrTransform.Transform(this.position, writeBuffer, 0, count);
            this.stream.Write(writeBuffer);

            // Update the stream position.
            this.position += count;
        }

        /// <summary>
        ///     Releases the unmanaged resources used by the Stream and optionally releases the managed resources.
        /// </summary>
        /// <param name="disposing">
        ///     If <c>true</c>, managed resources should be released in addition to unmanaged resources.
        /// </param>
        protected override void Dispose(bool disposing)
        {
            base.Dispose(disposing);

            if (disposing)
            {
                if (this.ctrTransform != null)
                {
                    this.ctrTransform.Dispose();
                    this.ctrTransform = null;
                }

                if (this.stream != null)
                {
                    this.stream.Dispose();
                    this.stream = null;
                }
            }
        }

        /// <summary>
        ///     Loads existing cryptographic parameters from the underlying stream.
        /// </summary>
        private void LoadParameters()
        {
            // Save the start position in case of errors.
            var currentStartPosition = this.stream.CanSeek ? this.stream.Position : 0;

            try
            {
                // Read the header length and validate it.
                int headerLength = this.stream.ReadUShort();
                if (headerLength < HeaderOverhead + MinNonceLength)
                {
                    throw new InvalidDataException("Stream header is invalid.");
                }

                // Read the nonce length and validate it.
                int nonceLength = this.stream.ReadUShort();
                if ((HeaderOverhead / 2) + nonceLength > headerLength)
                {
                    throw new InvalidDataException("Stream header is invalid.");
                }

                if (nonceLength < MinNonceLength || nonceLength > MaxNonceLength)
                {
                    throw new InvalidDataException("Stream contains invalid nonce.");
                }

                // Read the nonce.
                var nonce = this.stream.ReadExact(nonceLength);

                // Read the password salt length and validate it.
                int passwordSaltLength = this.stream.ReadUShort();
                if (HeaderOverhead + nonceLength + passwordSaltLength != headerLength)
                {
                    throw new InvalidDataException("Stream header is invalid.");
                }

                // Read the password salt.
                var passwordSalt = this.stream.ReadExact(passwordSaltLength);

                // Set the current nonce and salt.
                Nonce = nonce;
                Key.Salt = passwordSalt;

                // Reset the position of the encrypted stream.
                this.startPosition = this.stream.CanSeek ? this.stream.Position : 0;
                this.position = 0;
            }
            catch
            {
                // If the stream is seekable, try to return to the starting position.
                if (this.stream.CanSeek)
                {
                    try
                    {
                        this.stream.Position = currentStartPosition;
                    }
                    catch
                    {
                        // ignored
                    }
                }

                // Re-throw the exception.
                throw;
            }
        }

        private void SetupParameters(byte[]? nonce = null)
        {
            // Ensure that there is a valid nonce, and that it's an acceptable length.
            if (nonce != null)
            {
                if (nonce.Length < MinNonceLength || nonce.Length > MaxNonceLength)
                {
                    throw new ArgumentException($"Nonce must be between {MinNonceLength} and {MaxNonceLength} bytes.");
                }

                // The maximum user data length is limited by the header format and the nonce length.
                if (HeaderOverhead + nonce.Length + Key.Salt.Length > ushort.MaxValue)
                {
                    var maxUserDataLength = 0xFFFF - (HeaderOverhead + nonce.Length);
                    throw new ApplicationException($"Password salt cannot exceed {maxUserDataLength} bytes.");
                }
            }
            else
            {
                // The nonce will be as long as possible, up to the maximum length.
                // It will always be at least the minimum length, due to an earlier check.
                var availableNonceLength = 0xFFFF - (Key.Salt.Length + HeaderOverhead);
                nonce = new byte[Math.Min(availableNonceLength, MaxNonceLength)];
                Rng.GetBytes(nonce);
            }

            // Set the nonce.
            Nonce = nonce;

            // Write the parameters to the stream.
            this.stream.WriteUShort((ushort)(HeaderOverhead + nonce.Length + Key.Salt.Length));
            this.stream.WriteUShort((ushort)nonce.Length);
            this.stream.Write(nonce);
            this.stream.WriteUShort((ushort)Key.Salt.Length);
            this.stream.Write(Key.Salt);

            // Reset the position of the encrypted stream.
            this.startPosition = this.stream.CanSeek ? this.stream.Position : 0;
            this.position = 0;
        }
    }
}
