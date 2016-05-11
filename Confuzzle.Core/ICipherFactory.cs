using System.Security.Cryptography;

namespace Confuzzle.Core
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
}