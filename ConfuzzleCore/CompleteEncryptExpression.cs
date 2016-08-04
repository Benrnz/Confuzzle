using System;
using System.Threading.Tasks;

namespace ConfuzzleCore
{
    /// <summary>
    ///     A fluent syntax class that shows the user the next required step is to select the output destination.
    ///     This class contains previously captured data.
    /// </summary>
    public class CompleteEncryptExpression
    {
        private readonly PasswordRequiredEncryptExpression expression;

        internal CompleteEncryptExpression(PasswordRequiredEncryptExpression expression)
        {
            this.expression = expression;
        }

        /// <summary>
        ///     Writes the encrypted data into a byte array.
        /// </summary>
        /// <returns>A encrypted set of bytes.</returns>
        public async Task<byte[]> IntoByteArray()
        {
            switch (expression.EncryptFrom)
            {
                case SourceMode.String:
                    if (expression.SecurePassword != null)
                    {
                        return await ConfuzzleInternal.EncryptStringIntoBytesAsync(expression.StringInputData, expression.SecurePassword);
                    }
                    return await ConfuzzleInternal.EncryptStringIntoBytesAsync(expression.StringInputData, expression.Password);
                case SourceMode.File:
                    if (expression.SecurePassword != null)
                    {
                        return await ConfuzzleInternal.EncryptFileIntoBytesAsync(expression.SourceFile, expression.SecurePassword);
                    }
                    return await ConfuzzleInternal.EncryptFileIntoBytesAsync(expression.SourceFile, expression.Password);
                default:
                    throw new NotSupportedException();
            }
        }

        /// <summary>
        ///     Writes the encrypted data into a new file. If the file exists it is overwritten.
        /// </summary>
        /// <param name="fileName">
        ///     A full path and file name to the file you wish to write the encrypted data. If the file exists
        ///     it is overwritten.
        /// </param>
        public async Task IntoFile(string fileName)
        {
            switch (expression.EncryptFrom)
            {
                case SourceMode.String:
                    if (expression.SecurePassword != null)
                    {
                        await ConfuzzleInternal.EncryptStringIntoFileAsync(expression.StringInputData, fileName, expression.SecurePassword);
                        return;
                    }
                    await ConfuzzleInternal.EncryptStringIntoFileAsync(expression.StringInputData, fileName, expression.Password);
                    return;
                case SourceMode.File:
                    if (expression.SecurePassword != null)
                    {
                        await ConfuzzleInternal.EncryptFileIntoNewFileAsync(expression.SourceFile, fileName, expression.SecurePassword);
                        return;
                    }
                    await ConfuzzleInternal.EncryptFileIntoNewFileAsync(expression.SourceFile, fileName, expression.Password);
                    return;
                default:
                    throw new NotSupportedException();
            }
        }
    }
}