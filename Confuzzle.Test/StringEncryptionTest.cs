using System;
using System.Threading.Tasks;
using ConfuzzleCore;
using Xunit;

namespace ConfuzzleTest
{
    public class StringEncryptionTest
    {
        private string password = "MyPassword123";

        [Theory]
        [InlineData("The quick brown fox jumped over the lazy dog. 1234567890 -=_+ !@#$%^&*() {}|\\][ \"';: <>,./?")]
        [InlineData(" ")]
        [InlineData("")]
        public async Task EncryptString_ShouldReturnNonNullString_WithStringPassword(string inputData)
        {
            var encryptedResult = await Confuzzle.SimpleEncryptWithPasswordAsync(inputData, password);
            
            Assert.False(string.IsNullOrWhiteSpace(encryptedResult));
        }

        [Fact]
        public async Task EncryptString_ShouldThrow_GivenNullInputString()
        {
            await Assert.ThrowsAsync<ArgumentNullException>(() => Confuzzle.SimpleEncryptWithPasswordAsync(null, password));
        }

        [Fact]
        public async Task EncryptString_ShouldThrow_GivenNullPassword()
        {
            await Assert.ThrowsAsync<ArgumentNullException>(() => Confuzzle.SimpleEncryptWithPasswordAsync("Foo", (string)null));
        }

        [Fact]
        public async Task DecryptString_ShouldThrow_GivenNullInputString()
        {
            await Assert.ThrowsAsync<ArgumentNullException>(() => Confuzzle.SimpleDecryptWithPasswordAsync(null, password));
        }

        [Fact]
        public async Task DecryptString_ShouldThrow_GivenNullPassword()
        {
            await Assert.ThrowsAsync<ArgumentNullException>(() => Confuzzle.SimpleDecryptWithPasswordAsync("Foo", (string)null));
        }

        [Theory]
        [InlineData("The quick brown fox jumped over the lazy dog. 1234567890 -=_+ !@#$%^&*() {}|\\][ \"';: <>,./?")]
        public async Task DecryptString_ShouldReturnDecryptedResult_WithStringPassword(string inputData)
        {
            var encryptedResult = await Confuzzle.SimpleEncryptWithPasswordAsync(inputData, password);
            var decryptedResult = await Confuzzle.SimpleDecryptWithPasswordAsync(encryptedResult, password);

            Assert.Equal(inputData, decryptedResult);
        }
    }
}
