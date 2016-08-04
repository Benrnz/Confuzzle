using System;
using System.Security;

namespace ConfuzzleCore
{
    /// <summary>
    ///     A fluent syntax class that shows the user the next required step is to specify a password.
    ///     This class contains previously captured data.
    /// </summary>
    public class PasswordRequiredEncryptExpression
    {
        internal SourceMode EncryptFrom { get; private set; }
        internal string Password { get; private set; }
        internal SecureString SecurePassword { get; private set; }

        internal string SourceFile { get; private set; }
        internal string StringInputData { get; private set; }

        /// <summary>
        ///     Set the password to use to encrypt the data. If the password is incorrect the output will be garbled; no exceptions
        ///     are thrown.
        ///     Prefer use of <see cref="SecureString" /> where possible.
        /// </summary>
        public CompleteEncryptExpression WithPassword(string password)
        {
            if (string.IsNullOrWhiteSpace(password)) throw new ArgumentNullException(nameof(password));
            Password = password;
            return new CompleteEncryptExpression(this);
        }

        /// <summary>
        ///     Set the password to use to encrypt the data. If the password is incorrect the output will be garbled; no exceptions
        ///     are thrown.
        /// </summary>
        public CompleteEncryptExpression WithPassword(SecureString password)
        {
            if (password == null) throw new ArgumentNullException(nameof(password));
            SecurePassword = password;
            return new CompleteEncryptExpression(this);
        }

        internal PasswordRequiredEncryptExpression SetMode(string inputData, SourceMode mode)
        {
            switch (mode)
            {
                case SourceMode.String:
                    EncryptFrom = SourceMode.String;
                    StringInputData = inputData;
                    break;
                case SourceMode.File:
                    EncryptFrom = SourceMode.File;
                    SourceFile = inputData;
                    break;
                default:
                    throw new NotSupportedException();
            }

            return this;
        }
    }
}