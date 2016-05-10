using System;
using System.Security.Cryptography;

namespace Confuzzle
{
    /// <summary>
    ///     A factory for creating cryptographic algorithms.
    /// </summary>
    public interface ICipherFactory
    {
        /// <summary>
        ///     Creates a new symmetric encryption algorithm.
        /// </summary>
        SymmetricAlgorithm CreateCipher();

        /// <summary>
        ///     Creates a new hashing algorithm.
        /// </summary>
        HashAlgorithm CreateHash();
    }

    ////////////////////////////////////////////////////////////////////////////

    /// <summary>
    ///     A factory for creating cryptographic algorithms.
    /// </summary>
    /// <typeparam name="TCipher">The type of symmetric encryption algorithm to create.</typeparam>
    /// <typeparam name="THash">The type of hash algorithm to create.</typeparam>
    public class CipherFactory<TCipher, THash> : ICipherFactory
        where TCipher : SymmetricAlgorithm, new()
        where THash : HashAlgorithm, new()
    {
        /// <summary>
        ///     Gets a default instance of the factory.
        /// </summary>
        public static ICipherFactory Default { get; } = new CipherFactory<TCipher, THash>();

        /// <summary>
        ///     Creates a new symmetric encryption algorithm.
        /// </summary>
        public SymmetricAlgorithm CreateCipher()
        {
            return new TCipher();
        }

        /// <summary>
        ///     Creates a new hashing algorithm.
        /// </summary>
        public HashAlgorithm CreateHash()
        {
            return new THash();
        }
    }

    ////////////////////////////////////////////////////////////////////////////

    /// <summary>
    ///     A factory for creating cryptographic algorithms, using sensible default algorithms.
    /// </summary>
    public class CipherFactory : CipherFactory<AesManaged, SHA256CryptoServiceProvider>
    {
        /// <summary>
        ///     Creates a cipher factory for the specified algorithms.
        /// </summary>
        /// <typeparam name="TCipher">The type of symmetric encryption algorithm to create.</typeparam>
        /// <typeparam name="THash">The type of hash algorithm to create.</typeparam>
        /// <returns>A factory for the specified algorithms.</returns>
        public static ICipherFactory For<TCipher, THash>()
            where TCipher : SymmetricAlgorithm, new()
            where THash : HashAlgorithm, new()
        {
            return CipherFactory<TCipher, THash>.Default;
        }
    }
}
