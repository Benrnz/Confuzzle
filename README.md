# Confuzzle
A handy quick and terse command line utility to encrypt and decrypt text files with a simple password.

This tool is intended only for text files at this stage.  All text is expected to be UTF-8.  I'm using this tool to encrypt JSON, XML and Text files only at this point, so anything else is untested.
Encryption is provided by BouncyCastle. (http://www.bouncycastle.org/csharp/)

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
