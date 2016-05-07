# Confuzzle
Do you find encryption hard? How about doing it in a best practice fasion?  Good, so do I, thats why we've spent some time researching a best practice way of doing it, and wrapping it in an easy to use package. The idea behind Confuzzle is to provide a few really simple methods of encrypting text files and streams.
Confuzzle command line is a handy and terse utility to encrypt and decrypt text files with a simple password. The longer your password the more difficult it will be to decrypt.
Confuzzle also contains a .NET class library for use in your code. The API is intended to provide simple methods based on strings or streams.

All text is expected to be UTF-8.  I'm using this tool to encrypt JSON, XML and Text files only at this point, so anything else is untested.
Encryption is currently provided by BouncyCastle. (http://www.bouncycastle.org/csharp/). However, I will be moving this off to only depend on standard .NET System.Cryptography libraries soon.

## WARNING
Use at your own risk.  Data can be lost if you forget your password, or modify the encryption algorithms.

## Examples
`Confuzzle.exe -iC:\data\MyFile.xml -e -oC:\data\MyFile.secure`

Encrypts the file MyFile.xml into a new file called MyFile.secure. The source file is left untouched. The output file will be deleted if it exists (with interactive confirmation from the user). The password will be prompted and masked.

`Confuzzle.exe -iC:\data\MyFile.secure -d -oC:\data\MyFile.xml`

Decrypts the file MyFile.secure into the file MyFile.xml.  The source file is left untouched. The output file will be deleted if it exists (with interactive confirmation from the user). The password will be prompted and masked.
 
`Confuzzle.exe -iC:\data\MyFile.secure -d -oC:\data\MyFile.xml -s -pMyUberSecretSmellyPassword`

Same as above execpt Confuzzle will run in silent mode and not prompt for any user input.  This means the output file will be overwritten if it exists without confirmation.  The password must also be passed in the command line in Silent mode.

Other Hints
* If the password is incorrect when attempting to decrypt a file, the output file, if it already exists, will not be touched.
* Although it is supported DO NOT supply your password using the command line argument unless you are scripting this tool.  Passwords are visible in plain text on the screen and the in command line history.
* Maximum file size is approximately 500Mb. 
