using System.Security;

namespace ConfuzzleCore
{
    /// <summary>
    ///     A convenience helper class that simplifies encrypting and decrypting files and strings.
    ///     All strings are treated with UTF8 encoding.
    ///     Prefer using <see cref="SecureString" /> for passwords. This standard .NET class more securely handles passwords in
    ///     memory.
    ///     Prefer using file to file encryption and decryption over strings and byte arrays for large data sets.
    /// </summary>
    public static class Confuzzle
    {
        /// <summary>
        ///     Decrypt from a set of encrypted bytes. The byte array is expected to be a previously encrypted set of bytes using
        ///     one of the Encrypt overloads.
        ///     Warning: Using encryption with in memory constructs, such as a byte array, can be slow and inefficient for large
        ///     data sets.
        /// </summary>
        /// <param name="bytes">The byte array to decrypt.</param>
        public static PasswordRequiredDecryptExpression DecryptBytes(byte[] bytes)
        {
            return new PasswordRequiredDecryptExpression().FromBytes(bytes);
        }

        /// <summary>
        ///     Decrypt an existing encrypted file on the local disk.
        /// </summary>
        /// <param name="fileName">A full path and file name to the encrypted file. This file remains unchanged.</param>
        public static PasswordRequiredDecryptExpression DecryptFile(string fileName)
        {
            return new PasswordRequiredDecryptExpression().FromFile(fileName);
        }

        /// <summary>
        ///     Encrypt an existing file on the local disk.
        /// </summary>
        /// <param name="fileName">A full path and file name to the file you wish to encrypt. This file remains unchanged.</param>
        public static PasswordRequiredEncryptExpression EncryptFile(string fileName)
        {
            return new PasswordRequiredEncryptExpression().SetMode(fileName, SourceMode.File);
        }

        /// <summary>
        ///     Encrypt a string.
        ///     Warning: Using encryption with in memory strings can be slow and inefficient for large strings.
        /// </summary>
        /// <param name="inputData">
        ///     The string to encrypt. This text will be UTF8 encoded to convert it to a byte array for
        ///     encryption.
        /// </param>
        public static PasswordRequiredEncryptExpression EncryptString(string inputData)
        {
            return new PasswordRequiredEncryptExpression().SetMode(inputData, SourceMode.String);
        }
    }
}