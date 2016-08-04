using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Security;
using System.Text;
using System.Threading.Tasks;

namespace ConfuzzleCore
{
    internal static class ConfuzzleInternal
    {
        public static async Task<string> DecryptFileIntoStringAsync(string inputFileName, string password)
        {
            if (string.IsNullOrWhiteSpace(password)) throw new ArgumentNullException(nameof(password));
            return await DecryptFileIntoString(inputFileName, () => password);
        }

        public static async Task<string> DecryptFileIntoStringAsync(string inputFileName, SecureString password)
        {
            return await DecryptFileIntoString(inputFileName, () => SecureStringToString(password));
        }
 
        public static async Task DecryptFromFileIntoNewFileAsync(string inputFileName, string outputFileName, SecureString password)
        {
            await DecryptFromFileIntoNewFile(inputFileName, outputFileName, () => SecureStringToString(password));
        }

        public static async Task DecryptFromFileIntoNewFileAsync(string inputFileName, string outputFileName, string password)
        {
            if (string.IsNullOrWhiteSpace(password)) throw new ArgumentNullException(nameof(password));
            await DecryptFromFileIntoNewFile(inputFileName, outputFileName, () => password);
        }

        public static async Task<string> DecryptFromBytesIntoStringAsync(byte[] inputData, string password)
        {
            if (string.IsNullOrWhiteSpace(password)) throw new ArgumentNullException(nameof(password));
            return await DecryptString(inputData, () => password);
        }

        public static async Task<string> DecryptFromBytesIntoStringAsync(byte[] inputData, SecureString password)
        {
            return await DecryptString(inputData, () => SecureStringToString(password));
        }

        public static async Task DecryptFromBytesIntoNewFileAsync(byte[] inputData, string outputFileName, SecureString password)
        {
            var data = await DecryptString(inputData, () => SecureStringToString(password));
            File.WriteAllText(outputFileName, data);
        }

        public static async Task DecryptFromBytesIntoNewFileAsync(byte[] inputData, string outputFileName, string password)
        {
            if (string.IsNullOrWhiteSpace(password)) throw new ArgumentNullException(nameof(password));
            var data = await DecryptString(inputData, () => password);
            File.WriteAllText(outputFileName, data);
        }

        public static async Task EncryptStringIntoFileAsync(string inputData, string outputFileName, string password)
        {
            if (string.IsNullOrWhiteSpace(password)) throw new ArgumentNullException(nameof(password));
            await EncryptStringIntoFile(inputData, outputFileName, () => password);
        }

        public static async Task EncryptStringIntoFileAsync(string inputData, string outputFileName, SecureString password)
        {
            await EncryptStringIntoFile(inputData, outputFileName, () => SecureStringToString(password));
        }

        public static async Task EncryptFileIntoNewFileAsync(string inputFileName, string outputFileName, SecureString password)
        {
            await EncryptFileIntoFile(inputFileName, outputFileName, () => SecureStringToString(password));
        }

        public static async Task EncryptFileIntoNewFileAsync(string inputFileName, string outputFileName, string password)
        {
            if (string.IsNullOrWhiteSpace(password)) throw new ArgumentNullException(nameof(password));
            await EncryptFileIntoFile(inputFileName, outputFileName, () => password);
        }

        public static async Task<byte[]> EncryptStringIntoBytesAsync(string inputData, string password)
        {
            if (string.IsNullOrWhiteSpace(password)) throw new ArgumentNullException(nameof(password));
            return await EncryptString(inputData, () => password);
        }

        public static async Task<byte[]> EncryptStringIntoBytesAsync(string inputData, SecureString password)
        {
            return await EncryptString(inputData, () => SecureStringToString(password));
        }

        public static async Task<byte[]> EncryptFileIntoBytesAsync(string inputFileName, SecureString password)
        {
            return await EncryptFileIntoBytes(inputFileName, () => SecureStringToString(password));
        }

        public static async Task<byte[]> EncryptFileIntoBytesAsync(string inputFileName, string password)
        {
            if (string.IsNullOrWhiteSpace(password)) throw new ArgumentNullException(nameof(password));
            return await EncryptFileIntoBytes(inputFileName, () => password);
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

        private static async Task EncryptFileIntoFile(string inputFileName, string outputFileName, Func<string> getPassword)
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

        private static async Task<byte[]> EncryptFileIntoBytes(string inputFileName, Func<string> getPassword)
        {
            if (inputFileName == null) throw new ArgumentNullException(nameof(inputFileName));
            using (var inputStream = File.Open(inputFileName, FileMode.Open, FileAccess.Read, FileShare.Read))
            {
                using (var outputStream = new MemoryStream())
                {
                    using (var cryptoStream = CipherStream.Create(outputStream, getPassword()))
                    {
                        await inputStream.CopyToAsync(cryptoStream);
                    }
                    return outputStream.ToArray();
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