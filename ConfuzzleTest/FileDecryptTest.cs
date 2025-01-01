using ConfuzzleCore;
using Xunit;

namespace ConfuzzleTest;

public class FileDecryptTest
{
    private const string Password = "Password99";

    [Fact]
    public async Task DecryptFile_ShouldReturnKnownString()
    {
        // Get the base directory of the test project
        var baseDirectory = AppDomain.CurrentDomain.BaseDirectory;

        // Construct the path to the file
        var filePath = Path.Combine(baseDirectory, "TestFile.secure");

        var result = await Confuzzle.DecryptFile(filePath)
            .WithPassword(Password)
            .IntoString();

        Assert.Equal("The quick brown fox jumped over the lazy dog.\r\n", result);
    }

    [Fact]
    public async Task DecryptFile_ShouldReturnWriteNewFile()
    {
        // Get the base directory of the test project
        var baseDirectory = AppDomain.CurrentDomain.BaseDirectory;

        // Construct the path to the file
        var filePath = Path.Combine(baseDirectory, "TestFile.secure");

        var outputFileName = Path.Combine(baseDirectory, $"TestOutputFile1-{DateTime.UtcNow:yyyyMMMdd-hhmmssfff}.txt");

        await Confuzzle.DecryptFile(filePath)
            .WithPassword(Password)
            .IntoFile(outputFileName);

        Assert.True(File.Exists(outputFileName));
    }

    [Fact]
    public async Task DecryptFile_ShouldReturnWriteNewFileAndContentsAreExpected()
    {
        // Get the base directory of the test project
        var baseDirectory = AppDomain.CurrentDomain.BaseDirectory;

        // Construct the path to the file
        var filePath = Path.Combine(baseDirectory, "TestFile.secure");

        var outputFileName = Path.Combine(baseDirectory, $"TestOutputFile2-{DateTime.UtcNow:yyyyMMMdd-hhmmssfff}.txt");

        await Confuzzle.DecryptFile(filePath)
            .WithPassword(Password)
            .IntoFile(outputFileName);

        var result = await File.ReadAllTextAsync(outputFileName);
        Assert.Equal("The quick brown fox jumped over the lazy dog.\r\n", result);
    }
}
