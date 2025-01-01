// See https://aka.ms/new-console-template for more information

using CommandLine;
using ConfuzzleCommandLine;

if (args.Length == 0)
{
    args = ["--help"];
}

Console.WriteLine("Confuzzle - File encryption - Rees.biz");
Console.WriteLine("Version " + ProgramMain.GetVersion());

Parser.Default.ParseArguments<Options>(args)
    .WithParsed(options =>
    {
        if (ProgramMain.ValidateArgs(options))
        {
            // Values are available here
            Console.WriteLine($"File Name: {options.InputFile}");
            try
            {
                if (options.Decrypt)
                {
                    ProgramMain.Decrypt(options).Wait();
                }
                else if (options.Encrypt)
                {
                    ProgramMain.Encrypt(options).Wait();
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
    });

Console.WriteLine();
