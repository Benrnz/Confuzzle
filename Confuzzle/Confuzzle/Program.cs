using System;
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
            password = pass;
            Console.WriteLine();
            if (string.IsNullOrWhiteSpace(password))
            {
                Console.WriteLine("Invalid Password - Passwords cannot be blank");
                return false;
            }

            return true;
        }

        private static void Encrypt(Options options)
        {
            Console.WriteLine("Encrypt Mode");
            if (!SetPassword(options)) return;
            InitialiseOutputFile(options);
            var fileContents = File.ReadAllText(options.InputFile);
            var stopwatch = System.Diagnostics.Stopwatch.StartNew();
            var encrypted = Encryptor.SimpleEncryptWithPassword(fileContents, password);
            Console.WriteLine($"Encryption complete. {stopwatch.ElapsedMilliseconds:N}ms ");
            File.WriteAllText(options.OutputFile, encrypted);
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
            var fileContents = File.ReadAllText(options.InputFile);
            var stopwatch = System.Diagnostics.Stopwatch.StartNew();
            var decrypted = Encryptor.SimpleDecryptWithPassword(fileContents, password);
            Console.WriteLine($"Decryption complete. {stopwatch.ElapsedMilliseconds:N}ms ");
            if (decrypted == null)
            {
                Console.WriteLine("Decryption FAILED!");
                throw new UserAbortException();
            }

            InitialiseOutputFile(options);
            File.WriteAllText(options.OutputFile, decrypted);
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
                Console.WriteLine("Only one of the Encrypt or Decrypt command line options can be in the same command line.");
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
                Console.WriteLine("No password has been supplied and Silent mode is active. Password is required when running without user interaction.");
                return false;
            }

            return true;
        }
    }
}