using System.Security;

namespace ConfuzzleCore
{
    /// <summary>
    ///     A fluent syntax class that shows the user the next required step is to specify a password.
    ///     This class contains previously captured data.
    /// </summary>
    public class PasswordRequiredDecryptExpression
    {
        internal SourceMode DecryptFrom { get; private set; }
        internal string Password { get; private set; }
        internal SecureString SecurePassword { get; private set; }

        internal byte[] SourceData { get; private set; }
        internal string SourceFile { get; private set; }

        /// <summary>
        ///     Set the password to use to decrypt the data. If the password is incorrect the output will be garbled; no exceptions
        ///     are thrown.
        ///     Prefer use of <see cref="SecureString" /> where possible.
        /// </summary>
        public CompleteDecryptExpression WithPassword(string password)
        {
            if (string.IsNullOrWhiteSpace(password))
            {
                throw new ArgumentNullException(nameof(password));
            }

            Password = password;
            return new CompleteDecryptExpression(this);
        }

        /// <summary>
        ///     Set the password to use to decrypt the data. If the password is incorrect the output will be garbled; no exceptions
        ///     are thrown.
        /// </summary>
        public CompleteDecryptExpression WithPassword(SecureString password)
        {
            SecurePassword = password ?? throw new ArgumentNullException(nameof(password));
            return new CompleteDecryptExpression(this);
        }

        internal PasswordRequiredDecryptExpression FromBytes(byte[] bytes)
        {
            DecryptFrom = SourceMode.Bytes;
            SourceData = bytes;
            return this;
        }

        internal PasswordRequiredDecryptExpression FromFile(string fileName)
        {
            DecryptFrom = SourceMode.File;
            SourceFile = fileName;
            return this;
        }
    }
}
