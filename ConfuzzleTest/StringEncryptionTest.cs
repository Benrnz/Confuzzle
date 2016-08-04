using System;
using System.Text;
using System.Threading.Tasks;
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
            var encryptedResult = await Confuzzle.SimpleEncryptWithPasswordAsync(inputData, password);
            var decryptedResult = await Confuzzle.SimpleDecryptWithPasswordAsync(encryptedResult, password);

            Assert.Equal(inputData, decryptedResult);
        }

        [Fact]
        public async Task DecryptString_ShouldThrow_GivenNullInputString()
        {
            await Assert.ThrowsAsync<ArgumentNullException>(() => Confuzzle.SimpleDecryptWithPasswordAsync(null, password));
        }

        [Fact]
        public async Task DecryptString_ShouldThrow_GivenNullPassword()
        {
            var inputData = Encoding.UTF8.GetBytes("Foo");
            await Assert.ThrowsAsync<ArgumentNullException>(() => Confuzzle.SimpleDecryptWithPasswordAsync(inputData, (string) null));
        }

        [Theory]
        [InlineData("The quick brown fox jumped over the lazy dog. 1234567890 -=_+ !@#$%^&*() {}|\\][ \"';: <>,./?")]
        [InlineData(" ")]
        [InlineData("")]
        public async Task EncryptString_ShouldReturnNonNullString_WithStringPassword(string inputData)
        {
            var encryptedResult = await Confuzzle.SimpleEncryptWithPasswordAsync(inputData, password);

            Assert.True(encryptedResult != null);
            Assert.True(encryptedResult.Length > 0);
        }

        [Fact]
        public async Task EncryptString_ShouldThrow_GivenNullInputString()
        {
            await Assert.ThrowsAsync<ArgumentNullException>(() => Confuzzle.SimpleEncryptWithPasswordAsync(null, password));
        }

        [Fact]
        public async Task EncryptString_ShouldThrow_GivenNullPassword()
        {
            await Assert.ThrowsAsync<ArgumentNullException>(() => Confuzzle.SimpleEncryptWithPasswordAsync("Foo", (string) null));
        }

        [Fact]
        public async Task OutputToBase64Example()
        {
            var inputData = "The quick brown fox jumped over the lazy dog. 1234567890 -=_+ !@#$%^&*() {}|\\][ \"';: <>,./?";
            output.WriteLine(inputData);
            var encryptedResult = await Confuzzle.SimpleEncryptWithPasswordAsync(inputData, password);
            var base64 = Convert.ToBase64String(encryptedResult, Base64FormattingOptions.InsertLineBreaks);

            output.WriteLine(base64);

            var base64ByteArray = Convert.FromBase64String(base64);
            var decryptedResult = await Confuzzle.SimpleDecryptWithPasswordAsync(base64ByteArray, password);

            output.WriteLine(decryptedResult);
        }
    }
}