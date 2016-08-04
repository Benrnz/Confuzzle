using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Security;
using System.Text;
using System.Threading.Tasks;

namespace ConfuzzleCore
{
    /// <summary>
    ///     A convenience static class contain simplified methods for encrypting and decrypting files and strings.
    ///     All strings are treated with UTF8 encoding.
    ///     Prefer overloads that use <see cref="SecureString"/> this standard .NET class more securely handles passwords in memory.
    /// </summary>
    public static class Confuzzle
    {
        /// <summary>
        ///     Decrypt an existing encrypted file and returns the result as a string. The file is expected to contain plain UTF8 text.
        /// </summary>
        /// <param name="inputFileName">A full path and file name to the encrypted file. This file remains unchanged.</param>
        /// <param name="password">The password to decrypt the file. If the password is incorrect the output will be garbled.</param>
        /// <returns>The plain UTF8 text result. If the password is incorrect this will be garbled.</returns>
        public static async Task<string> DecryptFileIntoStringAsync(string inputFileName, string password)
        {
            if (string.IsNullOrWhiteSpace(password)) throw new ArgumentNullException(nameof(password));
            return await DecryptFileIntoString(inputFileName, () => password);
        }

        /// <summary>
        /// Decrypt an existing encrypted file and returns the result as a string. The file is expected to contain plain UTF8 text.
        /// </summary>
        /// <param name="inputFileName">A full path and file name to the encrypted file.</param>
        /// <param name="password">The password to decrypt the file. If the password is incorrect the output will be garbled.</param>
        /// <returns>The plain UTF8 text result. If the password is incorrect this will be garbled.</returns>
        public static async Task<string> DecryptFileIntoStringAsync(string inputFileName, SecureString password)
        {
            return await DecryptFileIntoString(inputFileName, () => SecureStringToString(password));
        }
 
        /// <summary>
        ///     Decrypt an existing encrypted file on the local disk into another new file.
        /// </summary>
        /// <param name="inputFileName">A full path and file name to the encrypted file. This file remains unchanged.</param>
        /// <param name="outputFileName">A full path and file name to write the decrypted contents of the file. If the file exists, it will be overwritten.</param>
        /// <param name="password">The password to decrypt the file. If the password is incorrect the output will be garbled.</param>
        public static async Task DecryptFromFileIntoNewFileAsync(string inputFileName, string outputFileName, SecureString password)
        {
            await DecryptFromFileIntoNewFile(inputFileName, outputFileName, () => SecureStringToString(password));
        }

        /// <summary>
        ///     Decrypt an existing encrypted file on the local disk into another new file.
        /// </summary>
        /// <param name="inputFileName">A full path and file name to the encrypted file. This file remains unchanged.</param>
        /// <param name="outputFileName">A full path and file name to write the decrypted contents of the file. If the file exists, it will be overwritten.</param>
        /// <param name="password">The password to decrypt the file. If the password is incorrect the output will be garbled.</param>
        public static async Task DecryptFromFileIntoNewFileAsync(string inputFileName, string outputFileName, string password)
        {
            if (string.IsNullOrWhiteSpace(password)) throw new ArgumentNullException(nameof(password));
            await DecryptFromFileIntoNewFile(inputFileName, outputFileName, () => password);
        }

        /// <summary>
        ///     Decrypt from encrypted bytes into a string. The byte array is expected to be a previously encrypted set of bytes using one of the Encrypt overloads.
        ///     Warning: Using encryption with in memory strings can be slow and inefficient for large strings.
        /// </summary>
        /// <param name="inputData">The byte array to decrypt.</param>
        /// <param name="password">The password to decrypt the data. If the password is incorrect the output will be garbled.</param>
        public static async Task<string> DecryptFromBytesIntoStringAsync(byte[] inputData, string password)
        {
            if (string.IsNullOrWhiteSpace(password)) throw new ArgumentNullException(nameof(password));
            return await DecryptString(inputData, () => password);
        }

        /// <summary>
        ///     Decrypt from encrypted bytes into a string. The byte array is expected to be a previously encrypted set of bytes using one of the Encrypt overloads.
        ///     Warning: Using encryption with in memory strings can be slow and inefficient for large strings.
        /// </summary>
        /// <param name="inputData">The byte array to decrypt.</param>
        /// <param name="password">The password to decrypt the data. If the password is incorrect the output will be garbled.</param>
        public static async Task<string> DecryptFromBytesIntoStringAsync(byte[] inputData, SecureString password)
        {
            return await DecryptString(inputData, () => SecureStringToString(password));
        }


        /// <summary>
        ///     Encrypt a string and return an encrypted byte array. 
        ///     Warning: Using encryption with in memory strings can be slow and inefficient for large strings.
        /// </summary>
        /// <param name="inputData">The string to encrypt. This text will be UTF8 encoded.</param>
        /// <param name="outputFileName">A full path and file name to write the encrypted data into. If the file exists, it will be overwritten.</param>
        /// <param name="password">The password to encrypt the data.</param>
        public static async Task EncryptStringIntoFileAsync(string inputData, string outputFileName, string password)
        {
            if (string.IsNullOrWhiteSpace(password)) throw new ArgumentNullException(nameof(password));
            await EncryptStringIntoFile(inputData, outputFileName, () => password);
        }

        /// <summary>
        ///     Encrypt a string and return an encrypted byte array. 
        ///     Warning: Using encryption with in memory strings can be slow and inefficient for large strings.
        /// </summary>
        /// <param name="inputData">The string to encrypt. This text will be UTF8 encoded.</param>
        /// <param name="outputFileName">A full path and file name to write the encrypted data into. If the file exists, it will be overwritten.</param>
        /// <param name="password">The password to encrypt the data.</param>
        public static async Task EncryptStringIntoFileAsync(string inputData, string outputFileName, SecureString password)
        {
            await EncryptStringIntoFile(inputData, outputFileName, () => SecureStringToString(password));
        }

        /// <summary>
        ///     Encrypt an existing file on the local disk into a new binary encrypted file.
        /// </summary>
        /// <param name="inputFileName">A full path and file name to the file you wish to encrypt.</param>
        /// <param name="outputFileName">A full path and file name to write the encrypted data into. If the file exists, it will be overwritten.</param>
        /// <param name="password">The password to encrypt the file.</param>
        public static async Task EncryptFileIntoNewFileAsync(string inputFileName, string outputFileName, SecureString password)
        {
            await EncryptFile(inputFileName, outputFileName, () => SecureStringToString(password));
        }

        /// <summary>
        ///     Encrypt an existing file on the local disk into a new binary encrypted file.
        /// </summary>
        /// <param name="inputFileName">A full path and file name to the file you wish to encrypt.</param>
        /// <param name="outputFileName">A full path and file name to write the encrypted data into. If the file exists, it will be overwritten.</param>
        /// <param name="password">The password to encrypt the file.</param>
        public static async Task EncryptFileIntoNewFileAsync(string inputFileName, string outputFileName, string password)
        {
            if (string.IsNullOrWhiteSpace(password)) throw new ArgumentNullException(nameof(password));
            await EncryptFile(inputFileName, outputFileName, () => password);
        }

        /// <summary>
        ///     Encrypt a string.
        ///     Warning: Using encryption with in memory strings can be slow and inefficient for large strings.
        /// </summary>
        /// <param name="inputData">The string to encrypt. This text will be UTF8 encoded.</param>
        /// <param name="password">The password to encrypt the file.</param>
        public static async Task<byte[]> EncryptStringIntoBytesAsync(string inputData, string password)
        {
            if (string.IsNullOrWhiteSpace(password)) throw new ArgumentNullException(nameof(password));
            return await EncryptString(inputData, () => password);
        }

        /// <summary>
        ///     Encrypt a string.
        ///     Warning: Using encryption with in memory strings can be slow and inefficient for large strings.
        /// </summary>
        /// <param name="inputData">The string to encrypt. This text will be UTF8 encoded.</param>
        /// <param name="password">The password to encrypt the file.</param>
        public static async Task<byte[]> EncryptStringIntoBytesAsync(string inputData, SecureString password)
        {
            return await EncryptString(inputData, () => SecureStringToString(password));
        }

        internal static string SecureStringToString(SecureString password)
        {
            if (password == null) throw new ArgumentNullException(nameof(password));
            var valuePtr = IntPtr.Zero;
            try
            {
                valuePtr = Marshal.SecureStringToGlobalAllocUnicode(password);
                return Marshal.PtrToStringUni(valuePtr);
            }
            finally
            {
                Marshal.ZeroFreeGlobalAllocUnicode(valuePtr);
            }
        }

        private static async Task<string> DecryptFileIntoString(string inputFileName, Func<string> getPassword)
        {
            if (inputFileName == null) throw new ArgumentNullException(nameof(inputFileName));

            using (var inputStream = new FileStream(inputFileName, FileMode.Open, FileAccess.Read, FileShare.Read, 4096, true))
            {
                using (var outputStream = new MemoryStream())
                {
                    using (var cryptoStream = CipherStream.Open(inputStream, getPassword()))
                    {
                        await cryptoStream.CopyToAsync(outputStream);
                    }

                    outputStream.Position = 0;
                    using (var reader = new StreamReader(outputStream))
                    {
                        return await reader.ReadToEndAsync();
                    }
                }
            }
        }

        private static async Task DecryptFromFileIntoNewFile(string inputFileName, string outputFileName, Func<string> getPassword)
        {
            if (inputFileName == null) throw new ArgumentNullException(nameof(inputFileName));
            if (outputFileName == null) throw new ArgumentNullException(nameof(outputFileName));
            using (var inputStream = File.Open(inputFileName, FileMode.Open, FileAccess.Read, FileShare.Read))
            {
                using (var outputStream = File.Open(outputFileName, FileMode.Create, FileAccess.Write, FileShare.Read))
                {
                    using (var cryptoStream = CipherStream.Open(inputStream, getPassword()))
                    {
                        await cryptoStream.CopyToAsync(outputStream);
                    }
                }
            }
        }

        private static async Task<string> DecryptString(byte[] inputData, Func<string> getPassword)
        {
            if (inputData == null) throw new ArgumentNullException(nameof(inputData));
            using (var inputStream = new MemoryStream(inputData))
            {
                using (var outputStream = new MemoryStream())
                {
                    using (var cryptoStream = CipherStream.Open(inputStream, getPassword()))
                    {
                        await cryptoStream.CopyToAsync(outputStream);
                    }

                    outputStream.Position = 0;
                    using (var reader = new StreamReader(outputStream))
                    {
                        return await reader.ReadToEndAsync();
                    }
                }
            }
        }

        private static async Task EncryptFile(string inputFileName, string outputFileName, Func<string> getPassword)
        {
            if (inputFileName == null) throw new ArgumentNullException(nameof(inputFileName));
            if (outputFileName == null) throw new ArgumentNullException(nameof(outputFileName));
            using (var inputStream = File.Open(inputFileName, FileMode.Open, FileAccess.Read, FileShare.Read))
            {
                using (var outputStream = File.Open(outputFileName, FileMode.Create, FileAccess.Write, FileShare.Read))
                {
                    using (var cryptoStream = CipherStream.Create(outputStream, getPassword()))
                    {
                        await inputStream.CopyToAsync(cryptoStream);
                    }
                }
            }
        }

        private static async Task<byte[]> EncryptString(string inputData, Func<string> getPassword)
        {
            if (inputData == null) throw new ArgumentNullException(nameof(inputData));
            using (var inputStream = new MemoryStream(Encoding.UTF8.GetBytes(inputData)))
            {
                using (var outputStream = new MemoryStream())
                {
                    using (var cryptoStream = CipherStream.Create(outputStream, getPassword()))
                    {
                        await inputStream.CopyToAsync(cryptoStream);
                    }

                    outputStream.Position = 0;
                    return outputStream.ToArray();
                }
            }
        }

        private static async Task EncryptStringIntoFile(string inputData, string outputFileName, Func<string> getPassword)
        {
            if (inputData == null) throw new ArgumentNullException(nameof(inputData));
            if (outputFileName == null) throw new ArgumentNullException(nameof(outputFileName));

            using (var inputStream = new MemoryStream(Encoding.UTF8.GetBytes(inputData)))
            {
                using (var outputStream = new FileStream(outputFileName, FileMode.Create, FileAccess.Write, FileShare.Read, 4096, true))
                {
                    using (var cryptoStream = CipherStream.Create(outputStream, getPassword()))
                    {
                        await inputStream.CopyToAsync(cryptoStream);
                    }
                }
            }
        }
    }
}