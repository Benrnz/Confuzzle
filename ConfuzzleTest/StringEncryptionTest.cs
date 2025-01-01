using ConfuzzleCore;
using Xunit;
using Xunit.Abstractions;

namespace ConfuzzleTest
{
    public class StringEncryptionTest
    {
        private readonly ITestOutputHelper output;
        private readonly string password = "MyPassword123";

        public StringEncryptionTest(ITestOutputHelper output)
        {
            this.output = output;
        }

        [Theory]
        [InlineData("The quick brown fox jumped over the lazy dog. 1234567890 -=_+ !@#$%^&*() {}|\\][ \"';: <>,./?")]
        [InlineData(" ")]
        [InlineData("")]
        public async Task DecryptString_ShouldReturnDecryptedResult_WithStringPassword(string inputData)
        {
            var encryptedResult = await Confuzzle.EncryptString(inputData)
                .WithPassword(this.password)
                .IntoByteArray();
            var decryptedResult = await Confuzzle.DecryptBytes(encryptedResult)
                .WithPassword(this.password)
                .IntoString();

            Assert.Equal(inputData, decryptedResult);
        }

        [Fact]
        public async Task DecryptString_ShouldThrow_GivenNullInputString()
        {
            await Assert.ThrowsAsync<ArgumentNullException>(() => Confuzzle.DecryptBytes(null).WithPassword(this.password).IntoString());
        }

        [Fact]
        public async Task DecryptString_ShouldThrow_GivenNullPassword()
        {
            await Assert.ThrowsAsync<ArgumentNullException>(() => Confuzzle.DecryptBytes(new byte[] { 0, 2 }).WithPassword((string)null).IntoString());
        }

        [Theory]
        [InlineData("The quick brown fox jumped over the lazy dog. 1234567890 -=_+ !@#$%^&*() {}|\\][ \"';: <>,./?")]
        [InlineData(" ")]
        [InlineData("")]
        public async Task EncryptString_ShouldReturnNonNullString_WithStringPassword(string inputData)
        {
            var encryptedResult = await Confuzzle.EncryptString(inputData)
                .WithPassword(this.password)
                .IntoByteArray();

            Assert.True(encryptedResult != null);
            Assert.True(encryptedResult.Length > 0);
        }

        [Fact]
        public async Task EncryptString_ShouldThrow_GivenNullInputString()
        {
            await Assert.ThrowsAsync<ArgumentNullException>(() => Confuzzle.EncryptString(null).WithPassword(this.password).IntoByteArray());
        }

        [Fact]
        public async Task EncryptString_ShouldThrow_GivenNullPassword()
        {
            await Assert.ThrowsAsync<ArgumentNullException>(() => Confuzzle.EncryptString("Foo").WithPassword((string)null).IntoByteArray());
        }

        [Fact]
        public async Task OutputToBase64Example()
        {
            var inputData = "The quick brown fox jumped over the lazy dog. 1234567890 -=_+ !@#$%^&*() {}|\\][ \"';: <>,./?";
            this.output.WriteLine(inputData);

            var encryptedResult = await Confuzzle.EncryptString(inputData)
                .WithPassword(this.password)
                .IntoByteArray();
            var base64 = Convert.ToBase64String(encryptedResult, Base64FormattingOptions.InsertLineBreaks);
            this.output.WriteLine($"Encryption complete: {encryptedResult.Length} bytes");
            this.output.WriteLine(base64);

            var base64ByteArray = Convert.FromBase64String(base64);
            var decryptedResult = await Confuzzle.DecryptBytes(base64ByteArray)
                .WithPassword(this.password)
                .IntoString();

            this.output.WriteLine("Decryption complete:");
            this.output.WriteLine(decryptedResult);
        }
    }
}
