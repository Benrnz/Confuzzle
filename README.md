[![benrnz MyGet Build Status](https://www.myget.org/BuildSource/Badge/benrnz?identifier=13def666-1450-4a0c-adf6-2b3008a08094)](https://www.myget.org/)

Nuget: [Install-Package Confuzzle.Core](https://www.nuget.org/packages/Confuzzle.Core/)

Nuget: [Install-Package Confuzzle Commandline](https://www.nuget.org/packages/Confuzzle/)

# Confuzzle
Do you find encryption hard? How about doing it in a best practice fashion?  Good, so do I, that's why we've spent some time researching a best practice way of doing it, and wrapping it in an easy to use package. The idea behind Confuzzle is to provide a few really simple methods of encrypting text files and streams.
Confuzzle command line is a handy and terse utility to encrypt and decrypt text files with a simple password. The longer your password the more difficult it will be to decrypt.
Confuzzle also contains a .NET class library for use in your code. The API is intended to provide simple methods based on strings or streams.

All text is expected to be UTF-8.  I'm using this tool to encrypt JSON, XML and Text files only at this point, so anything else is untested.
Encryption is provided by standard .NET System.Security.Cryptography libraries.

## WARNING
Use at your own risk.  Data can be lost if you forget your password, or modify the encryption algorithms.

## Contributors

**@nzgeek Jamie** - Security and .NET Expert

**@benrnz Ben**   - All round great guy ;-)

Special thanks to Jamie for introducing stream based file encryption to cater for large text and binary files alike.  Also for simplifying dependencies back down to standard .NET libraries.

New contributions are welcome.

## C# Examples using Confuzzle.Core
For C# usage you will only need the Confuzzle.Core.dll.
### Encrypt a file into another file.
```
await Confuzzle.EncryptFile("C:\\PathToMyFile\\Myfile.txt")
    .WithPassword("MySecretSquirrelPassword")
    .IntoFile("C:\\PathToMyFile\\Myfile.txt.secure");
```

### Decrypt a file into another file.
```
await Confuzzle.DecryptFile("C:\\PathToMyFile\\Myfile.txt.secure")
    .WithPassword("MySecretSquirrelPassword")
    .IntoFile("C:\\PathToMyFile\\Myfile.txt");
```

### Encrypt a string.
```
byte[] bytes = await Confuzzle.EncryptString("This is the string I want to encrypt")
    .WithPassword("MySecretSquirrelPassword")
    .IntoByteArray();
var base64 = Convert.ToBase64String(bytes);
```

### Decrypt a string.
```
var bytes2 = Convert.FromBase64String(base64);
string result = await Confuzzle.DecryptBytes(bytes2)
    .WithPassword("MySecretSquirrelPassword")
    .IntoString();
```

### Synchronous Operations
Synchronous operations are not encouraged. Large files and strings will be inefficiently managed in memory if asynchronous behaviour is not used.
If you insist on accessing Confuzzle synchronously see Advanced usage below.

### Advanced Usage
The helper methods on the Confuzzle static class can be bypassed and you can access the CipherStream class directly for more advanced usage.
For example:
To encrypt a file
```
using (var inputStream = new FileStream(unencryptedInputFileName, FileMode.Open, FileAccess.Read, FileShare.Read, bufferSize: 4096, useAsync: true))
{
    using (var outputStream = new FileStream(encryptedOutputFileName, FileMode.Create, FileAccess.Write, FileShare.Read, bufferSize: 4096, useAsync: true))
    {
        using (CipherStream cryptoStream = CipherStream.Create(outputStream, password))
        {
            // Copy the contents of the input stream into the output stream (file) and in doing so encrypt it.
            await inputStream.CopyToAsync(cryptoStream);
        }
    }
}
```

To encrypt a file synchronously
```
using (var inputStream = File.Open(inputFileName, FileMode.Open, FileAccess.Read, FileShare.Read))
{
    using (var outputStream = File.Open(outputFileName, FileMode.Create, FileAccess.Write, FileShare.Read))
    {
        using (var cryptoStream = CipherStream.Create(outputStream, getPassword()))
        {
            inputStream.CopyTo(cryptoStream);
        }
    }
}

// To encrypt a string replace the inputStream with a MemoryStream containing the string.
// To encrypt into a byte array replace the outputStream with a MemoryStream and read the bytes with .ToArray().
``` 

## Command Line Examples
`Confuzzle.exe -i C:\data\MyFile.xml -e -o C:\data\MyFile.secure`

Encrypts the file MyFile.xml into a new file called MyFile.secure. The source file is left untouched. The output file will be deleted if it exists (with interactive confirmation from the user). The password will be prompted and masked.

`Confuzzle.exe -i C:\data\MyFile.secure -d -o C:\data\MyFile.xml`

Decrypts the file MyFile.secure into the file MyFile.xml.  The source file is left untouched. The output file will be deleted if it exists (with interactive confirmation from the user). The password will be prompted and masked.
 
`Confuzzle.exe -i C:\data\MyFile.secure -d -o C:\data\MyFile.xml -s -pMyUberSecretSmellyPassword`

Same as above execpt Confuzzle will run in silent mode and not prompt for any user input.  This means the output file will be overwritten if it exists without confirmation.  The password must also be passed in the command line in Silent mode.

Other Hints
* If the password is incorrect when attempting to decrypt a file, the output file, if it already exists, will not be touched.
* Although it is supported DO NOT supply your password using the command line argument unless you are scripting this tool.  Passwords are visible in plain text on the screen and the in command line history.
* Maximum file size is approximately 500Mb. 
