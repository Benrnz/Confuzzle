// Define a class to receive parsed values

using CommandLine;
using CommandLine.Text;

public class Options
{
    [Option('i', "inputFileName", Required = true, HelpText = "Input file to be processed.")]
    public string InputFile { get; set; }

    [Option('e', "encrypt", DefaultValue = false, HelpText = "Encrypt mode - encrypts the supplied Input File.")]
    public bool Encrypt { get; set; }

    [Option('d', "decrypt", DefaultValue = false, HelpText = "Decrypt mode - decrypts the supplied Input File.")]
    public bool Decrypt { get; set; }

    [Option('o', "outputFile", HelpText = "The file to output to.")]
    public string OutputFile { get; set; }

    [Option('s', "silent", HelpText = "Silent mode. Will not prompt for password or confirmation.")]
    public bool Silent { get; set; }

    [Option('p', "password", HelpText = "The password to use.  NOT RECOMMENDED FOR INTERACTIVE MODE - USE ONLY FOR SCRIPTING. Password will be prompted from user when Silent = false.")]
    public string Password { get; set; }

    [ParserState]
    public IParserState LastParserState { get; set; }

    [HelpOption]
    public string GetUsage()
    {
        return HelpText.AutoBuild(this, current => HelpText.DefaultParsingErrorsHandler(this, current));
    }
}