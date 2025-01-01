using ConfuzzleCore;

namespace ConfuzzleTest
{
    public class Examples
    {
        public async Task SampleCode()
        {
            // Encrypt a file into another file.
            await Confuzzle.EncryptFile("C:\\PathToMyFile\\Myfile.txt")
                .WithPassword("MySecretSquirrelPassword")
                .IntoFile("C:\\PathToMyFile\\Myfile.txt.secure");

            // Decrypt a file into another file.
            await Confuzzle.DecryptFile("C:\\PathToMyFile\\Myfile.txt.secure")
                .WithPassword("MySecretSquirrelPassword")
                .IntoFile("C:\\PathToMyFile\\Myfile.txt");

            // Encrypt a string.
            var bytes = await Confuzzle.EncryptString("This is the string I want to encrypt")
                .WithPassword("MySecretSquirrelPassword")
                .IntoByteArray();
            var base64 = Convert.ToBase64String(bytes);

            // Decrypt a string.
            var bytes2 = Convert.FromBase64String(base64);
            var result = await Confuzzle.DecryptBytes(bytes2)
                .WithPassword("MySecretSquirrelPassword")
                .IntoString();
        }
    }
}
