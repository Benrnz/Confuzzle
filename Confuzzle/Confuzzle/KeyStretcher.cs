using System;
using System.Linq;
using System.Security.Cryptography;

namespace Confuzzle
{
    /// <summary>
    ///     Stretches passwords into cryptographic keys using PBKDF2 (RFC 2898).
    /// </summary>
    public class KeyStretcher : Rfc2898DeriveBytes
    {
        /// <summary>
        ///     The default number of iterations used during stretching.
        /// </summary>
        public const int DefaultIterationCount = 10000;

        /// <summary>
        ///     The default size of a password salt, in bytes.
        /// </summary>
        public const int DefaultSaltSize = 16;

        /// <summary>
        ///     A random number generator for creating random salts.
        /// </summary>
        public static RandomNumberGenerator Rng { get; set; } = new RNGCryptoServiceProvider();

        /// <summary>
        ///     Stretches a password using a random salt and the default iteration count.
        /// </summary>
        /// <param name="password">The password to stretch.</param>
        public KeyStretcher(string password)
            : base(password, GenerateSalt(DefaultSaltSize), DefaultIterationCount)
        {
        }

        /// <summary>
        ///     Stretches a password using a random salt and the specified iteration count.
        /// </summary>
        /// <param name="password">The password to stretch.</param>
        /// <param name="iterationCount">The number of iterations used during password stretching.</param>
        public KeyStretcher(string password, int iterationCount)
            : base(password, GenerateSalt(DefaultSaltSize), iterationCount)
        {
        }

        /// <summary>
        ///     Stretches a password using the specified salt and the default iteration count.
        /// </summary>
        /// <param name="password">The password to stretch.</param>
        /// <param name="salt">The salt used during password stretching.</param>
        public KeyStretcher(string password, byte[] salt)
            : base(password, salt ?? GenerateSalt(DefaultSaltSize), DefaultIterationCount)
        {
        }

        /// <summary>
        ///     Stretches a password using the specified salt and iteration count.
        /// </summary>
        /// <param name="password">The password to stretch.</param>
        /// <param name="salt">The salt used during password stretching.</param>
        /// <param name="iterationCount">The number of iterations used during password stretching.</param>
        public KeyStretcher(string password, byte[] salt, int iterationCount)
            : base(password, salt ?? GenerateSalt(DefaultSaltSize), iterationCount)
        {
        }

        /// <summary>
        ///     Stretches a password using a random salt and the default iteration count.
        /// </summary>
        /// <param name="password">The password to stretch.</param>
        public KeyStretcher(byte[] password)
            : base(password, GenerateSalt(DefaultSaltSize), DefaultIterationCount)
        {
        }

        /// <summary>
        ///     Stretches a password using a random salt and the specified iteration count.
        /// </summary>
        /// <param name="password">The password to stretch.</param>
        /// <param name="iterationCount">The number of iterations used during password stretching.</param>
        public KeyStretcher(byte[] password, int iterationCount)
            : base(password, GenerateSalt(DefaultSaltSize), iterationCount)
        {
        }

        /// <summary>
        ///     Stretches a password using the specified salt and the default iteration count.
        /// </summary>
        /// <param name="password">The password to stretch.</param>
        /// <param name="salt">The salt used during password stretching.</param>
        public KeyStretcher(byte[] password, byte[] salt)
            : base(password, salt ?? GenerateSalt(DefaultSaltSize), DefaultIterationCount)
        {
        }

        /// <summary>
        ///     Stretches a password using the specified salt and iteration count.
        /// </summary>
        /// <param name="password">The password to stretch.</param>
        /// <param name="salt">The salt used during password stretching.</param>
        /// <param name="iterationCount">The number of iterations used during password stretching.</param>
        public KeyStretcher(byte[] password, byte[] salt, int iterationCount)
            : base(password, salt ?? GenerateSalt(DefaultSaltSize), iterationCount)
        {
        }

        /// <summary>
        ///     Generates a new random salt.
        /// </summary>
        /// <param name="saltLength">The length of the salt, in bytes.</param>
        /// <returns>A new random salt.</returns>
        public static byte[] GenerateSalt(int saltLength)
        {
            if (saltLength < 8)
                throw new ArgumentException("The specified salt size is smaller than 8 bytes.", nameof(saltLength));

            var salt = new byte[saltLength];
            Rng.GetBytes(salt);
            return salt;
        }

        /// <summary>
        ///     Gets a key of the specified size.
        /// </summary>
        /// <param name="keySizeBits">The size of the key in bits.</param>
        /// <returns>A key of the specified size.</returns>
        public byte[] GetKeyBytes(int keySizeBits)
        {
            if (keySizeBits % 8 != 0)
                throw new ArgumentException("Key size must be a multiple of 8 bits.", nameof(keySizeBits));

            return GetBytes(keySizeBits / 8);
        }

        /// <summary>
        ///     Gets a key suitable for the specified algorithm, which is no stronger than the specified size.
        /// </summary>
        /// <param name="algorithm">The algorithm to generate the key for.</param>
        /// <returns>A key suitable for the specified algorithm.</returns>
        public byte[] GetKeyBytes(SymmetricAlgorithm algorithm)
        {
            return GetKeyBytes(algorithm, int.MaxValue);
        }

        /// <summary>
        ///     Gets a key suitable for the specified algorithm, which is no stronger than the specified size.
        /// </summary>
        /// <param name="algorithm">The algorithm to generate the key for.</param>
        /// <param name="maxKeySizeBits">The maximum key size in bits.</param>
        /// <returns>A key suitable for the specified algorithm.</returns>
        public byte[] GetKeyBytes(SymmetricAlgorithm algorithm, int maxKeySizeBits)
        {
            var maxLegalSize = algorithm.LegalKeySizes
                .Select(ks => GetMaxKeySize(ks, maxKeySizeBits))
                .Max();

            if (maxLegalSize == 0)
                throw new ArgumentException("Maximum key size is too low.", nameof(maxKeySizeBits));

            return GetKeyBytes(maxLegalSize);
        }

        /// <summary>
        ///     Gets the maximum key size that's no larger than a specified maximum.
        /// </summary>
        /// <param name="keySizes">A structure indicating valid key sizes.</param>
        /// <param name="maxKeySizeBits">The maximum key size in bits.</param>
        /// <returns>The maximum key size, or 0 if no suitable key size is available.</returns>
        private static int GetMaxKeySize(KeySizes keySizes, int maxKeySizeBits)
        {
            for (var keySize = keySizes.MaxSize; keySize >= keySizes.MinSize; keySize -= keySizes.SkipSize)
            {
                if (keySize <= maxKeySizeBits)
                    return keySize;
            }

            return 0;
        }
    }
}
