using System;
using System.Diagnostics;
using System.IO;
using CommandLine;

namespace Confuzzle
{
    public static class Program
    {
        private static string password;

        public static void Main(string[] args)
        {
            Console.WriteLine("Confuzzle - File encryption - Rees.biz");

            var options = new Options();
            if (Parser.Default.ParseArguments(args, options) && ValidateArgs(options))
            {
                // Values are available here
                Console.WriteLine($"File Name: {options.InputFile}");
                try
                {
                    if (options.Decrypt)
                    {
                        Decrypt(options);
                    }
                    else if (options.Encrypt)
                    {
                        Encrypt(options);
                    }
                }
                catch (UserAbortException)
                {
                    Console.WriteLine();
                    Console.WriteLine("User aborted.");
                }
                catch (ArgumentException ex)
                {
                    Console.WriteLine();
                    Console.WriteLine("Encryption validation error: " + ex.Message);
                }
                catch (OverflowException)
                {
                    Console.WriteLine();
                    Console.WriteLine("File is too large to encrypt.");
                }
            }
            else
            {
                Console.WriteLine("Error - invalid arguments.");
            }

            if (!options.Silent)
            {
                Console.WriteLine("Press enter to exit");
                Console.ReadLine();
            }
        }

        private static bool SetPassword(Options options)
        {
            Console.WriteLine();
            if (options.Silent)
            {
                password = options.Password;
                return true;
            }

            Console.WriteLine("Enter password: ");
            var pass = PromptUserForPassword();
            password = pass;
            Console.WriteLine("\nConfirm password: ");
            pass = PromptUserForPassword();
            Console.WriteLine();
            if (string.Compare(password, pass, StringComparison.Ordinal) != 0)
            {
                Console.WriteLine("Passwords do not match.");
                throw new UserAbortException();
            }

            if (string.IsNullOrWhiteSpace(password))
            {
                Console.WriteLine("Invalid Password - Passwords cannot be blank");
                return false;
            }

            return true;
        }

        private static string PromptUserForPassword()
        {
            ConsoleKeyInfo key;
            var pass = string.Empty;
            do
            {
                key = Console.ReadKey(true);

                // Backspace Should Not Work
                if (key.Key != ConsoleKey.Backspace && key.Key != ConsoleKey.Enter)
                {
                    pass += key.KeyChar;
                    Console.Write("*");
                }
                else
                {
                    if (key.Key == ConsoleKey.Backspace && pass.Length > 0)
                    {
                        pass = pass.Substring(0, pass.Length - 1);
                        Console.Write("\b \b");
                    }
                }
            } while (key.Key != ConsoleKey.Enter); // Stops Receving Keys Once Enter is Pressed
            return pass;
        }

        private static void Encrypt(Options options)
        {
            Console.WriteLine("Encrypt Mode");
            if (!SetPassword(options)) return;
            InitialiseOutputFile(options);

            var stopwatch = Stopwatch.StartNew();
            using (var inputFile = File.Open(options.InputFile, FileMode.Open, FileAccess.Read, FileShare.Read))
            {
                using (var outputFile = File.Open(options.OutputFile, FileMode.Create, FileAccess.Write, FileShare.Read))
                {
                    using (var cryptoStream = CipherStream.Create(outputFile, password))
                    {
                        inputFile.CopyTo(cryptoStream);
                    }
                }
            }
            Console.WriteLine($"Encryption complete. {stopwatch.ElapsedMilliseconds:N}\b\b\bms ");

            if (File.Exists(options.OutputFile))
            {
                Console.WriteLine($"{options.OutputFile} created successfully.");
            }
        }

        private static void InitialiseOutputFile(Options options)
        {
            if (File.Exists(options.OutputFile))
            {
                Console.WriteLine($"{options.OutputFile} exists. Deleting it now.");
                if (!options.Silent)
                {
                    Console.Write("Confirm [Y/N]: ");
                    var key = Console.ReadKey();
                    Console.WriteLine();
                    if (key.Key == ConsoleKey.N) throw new UserAbortException();
                }
                File.Delete(options.OutputFile);
            }
        }

        private static void Decrypt(Options options)
        {
            Console.WriteLine("Decrypt Mode");
            if (!SetPassword(options)) return;
            InitialiseOutputFile(options);

            var stopwatch = Stopwatch.StartNew();
            using (var inputFile = File.Open(options.InputFile, FileMode.Open, FileAccess.Read, FileShare.Read))
            {
                using (var outputFile = File.Open(options.OutputFile, FileMode.Create, FileAccess.Write, FileShare.Read))
                {
                    using (var cryptoStream = CipherStream.Open(inputFile, password))
                    {
                        cryptoStream.CopyTo(outputFile);
                    }
                }
            }
            Console.WriteLine($"Decryption complete. {stopwatch.ElapsedMilliseconds:N}\b\b\bms ");

            if (File.Exists(options.OutputFile))
            {
                Console.WriteLine($"{options.OutputFile} created successfully.");
            }
        }

        private static bool ValidateArgs(Options options)
        {
            var valid = options.Decrypt ^ options.Encrypt;
            if (!valid)
            {
                Console.WriteLine(
                    "Only one of the Encrypt or Decrypt command line options can be in the same command line.");
                return false;
            }

            valid = File.Exists(options.InputFile);
            if (!valid)
            {
                Console.WriteLine("Input file does not exist.");
                return false;
            }

            if (string.IsNullOrWhiteSpace(options.OutputFile))
            {
                var extension = options.Encrypt ? ".secure" : ".txt";
                var folder = Path.GetDirectoryName(options.InputFile);
                options.OutputFile = $"{folder}\\{Path.GetFileNameWithoutExtension(options.InputFile)}{extension}";
            }

            if (options.Silent && string.IsNullOrWhiteSpace(options.Password))
            {
                Console.WriteLine(
                    "No password has been supplied and Silent mode is active. Password is required when running without user interaction.");
                return false;
            }

            return true;
        }
    }
}