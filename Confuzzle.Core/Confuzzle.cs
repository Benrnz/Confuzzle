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
    /// </summary>
    public static class Confuzzle
    {
        /// <summary>
        /// Decrypt an existing encrypted file on the local disk.
        /// Prefer this overload using files and the <see cref="SecureString"/> class to more safely store the password.
        /// </summary>
        /// <param name="inputFileName">A full path and file name to the encrypted file.</param>
        /// <param name="outputFileName">A full path and file name to write the decrypted contents of the file.</param>
        /// <param name="password">The password to decrypt the file.</param>
        public static async Task SimpleDecryptWithPasswordAsync(string inputFileName, string outputFileName, SecureString password)
        {
            await DecryptFile(inputFileName, outputFileName, () => SecureStringToString(password));
        }

        /// <summary>
        /// Decrypt an existing encrypted file on the local disk.
        /// Prefer the <see cref="SimpleDecryptWithPasswordAsync(string,string,SecureString)"/> overload over this one where possible.
        /// </summary>
        /// <param name="inputFileName">A full path and file name to the encrypted file.</param>
        /// <param name="outputFileName">A full path and file name to write the decrypted contents of the file.</param>
        /// <param name="password">The password to decrypt the file.</param>
        public static async Task SimpleDecryptWithPasswordAsync(string inputFileName, string outputFileName, string password)
        {
            await DecryptFile(inputFileName, outputFileName, () => password);
        }

        /// <summary>
        /// Decrypt a string.
        /// Prefer the <see cref="SimpleDecryptWithPasswordAsync(string,string,SecureString)"/> overload over this one where possible.
        /// Using encryption with in memory strings can be slow and inefficient for large strings.
        /// </summary>
        /// <param name="inputData">The string to decrypt</param>
        /// <param name="password">The password to decrypt the file.</param>
        public static async Task<string> SimpleDecryptWithPasswordAsync(string inputData, string password)
        {
            return await DecryptString(inputData, () => password);
        }

        /// <summary>
        /// Decrypt a string.
        /// Prefer the <see cref="SimpleDecryptWithPasswordAsync(string,string,SecureString)"/> overload over this one where possible.
        /// Using encryption with in memory strings can be slow and inefficient for large strings.
        /// </summary>
        /// <param name="inputData">The string to decrypt</param>
        /// <param name="password">The password to decrypt the file.</param>
        public static async Task<string> SimpleDecryptWithPasswordAsync(string inputData, SecureString password)
        {
            return await DecryptString(inputData, () => SecureStringToString(password));
        }

        /// <summary>
        /// Encrypt an existing file on the local disk.
        /// Prefer this overload using files and the <see cref="SecureString"/> class to more safely store the password.
        /// </summary>
        /// <param name="inputFileName">A full path and file name to the file you wish to encrypt.</param>
        /// <param name="outputFileName">A full path and file name to write the encrypted copy of the file.</param>
        /// <param name="password">The password to encrypt the file.</param>
        public static async Task SimpleEncryptWithPasswordAsync(string inputFileName, string outputFileName, SecureString password)
        {
            await EncryptFile(inputFileName, outputFileName, () => SecureStringToString(password));
        }

        /// <summary>
        /// Encrypt an existing file on the local disk.
        /// Prefer the <see cref="SimpleEncryptWithPasswordAsync(string,string,SecureString)"/> overload over this one where possible.
        /// </summary>
        /// <param name="inputFileName">A full path and file name to the file you wish to encrypt.</param>
        /// <param name="outputFileName">A full path and file name to write the encrypted copy of the file.</param>
        /// <param name="password">The password to encrypt the file.</param>
        public static async Task SimpleEncryptWithPasswordAsync(string inputFileName, string outputFileName, string password)
        {
            await EncryptFile(inputFileName, outputFileName, () => password);
        }

        /// <summary>
        /// Encrypt a string.
        /// Prefer the <see cref="SimpleEncryptWithPasswordAsync(string,string,SecureString)"/> overload over this one where possible.
        /// Using encryption with in memory strings can be slow and inefficient for large strings.
        /// </summary>
        /// <param name="inputData">The string to encrypt.</param>
        /// <param name="password">The password to encrypt the file.</param>
        public static async Task<string> SimpleEncryptWithPasswordAsync(string inputData, string password)
        {
            return await EncryptString(inputData, () => password);
        }

        /// <summary>
        /// Encrypt a string.
        /// Prefer the <see cref="SimpleEncryptWithPasswordAsync(string,string,SecureString)"/> overload over this one where possible.
        /// Using encryption with in memory strings can be slow and inefficient for large strings.
        /// </summary>
        /// <param name="inputData">The string to encrypt.</param>
        /// <param name="password">The password to encrypt the file.</param>
        public static async Task<string> SimpleEncryptWithPasswordAsync(string inputData, SecureString password)
        {
            return await EncryptString(inputData, () => SecureStringToString(password));
        }

        internal static string SecureStringToString(SecureString value)
        {
            var valuePtr = IntPtr.Zero;
            try
            {
                valuePtr = Marshal.SecureStringToGlobalAllocUnicode(value);
                return Marshal.PtrToStringUni(valuePtr);
            }
            finally
            {
                Marshal.ZeroFreeGlobalAllocUnicode(valuePtr);
            }
        }

        private static async Task DecryptFile(string inputFileName, string outputFileName, Func<string> getPassword)
        {
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

        private static async Task<string> DecryptString(string inputData, Func<string> getPassword)
        {
            using (var inputStream = new MemoryStream(Encoding.UTF8.GetBytes(inputData)))
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

        private static async Task<string> EncryptString(string inputData, Func<string> getPassword)
        {
            using (var inputStream = new MemoryStream(Encoding.UTF8.GetBytes(inputData)))
            {
                using (var outputStream = new MemoryStream())
                {
                    using (var cryptoStream = CipherStream.Create(outputStream, getPassword()))
                    {
                        await inputStream.CopyToAsync(cryptoStream);
                    }

                    outputStream.Position = 0;
                    using (var reader = new StreamReader(outputStream))
                    {
                        return await reader.ReadToEndAsync();
                    }
                }
            }
        }
    }
}