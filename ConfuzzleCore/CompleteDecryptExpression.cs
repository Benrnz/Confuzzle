using System;
using System.Threading.Tasks;

namespace ConfuzzleCore
{
    /// <summary>
    ///     A fluent syntax class that shows the user the next required step is to select the output destination.
    ///     This class contains previously captured data.
    /// </summary>
    public class CompleteDecryptExpression
    {
        private readonly PasswordRequiredDecryptExpression expression;

        internal CompleteDecryptExpression(PasswordRequiredDecryptExpression expression)
        {
            this.expression = expression;
        }

        /// <summary>
        ///     Write the decrypted data into a new file.  If the new file already exists it is overwritten.
        ///     This method is asynchronous.
        /// </summary>
        /// <param name="fileName">
        ///     A full path and file name to the file you wish to write the decrypted data. If the file exists
        ///     it is overwritten.
        /// </param>
        public async Task IntoFile(string fileName)
        {
            switch (expression.DecryptFrom)
            {
                case SourceMode.Bytes:
                    if (expression.SecurePassword != null)
                    {
                        await ConfuzzleInternal.DecryptFromBytesIntoNewFileAsync(expression.SourceData, fileName, expression.SecurePassword);
                        return;
                    }
                    await ConfuzzleInternal.DecryptFromBytesIntoNewFileAsync(expression.SourceData, fileName, expression.Password);
                    return;
                case SourceMode.File:
                    if (expression.SecurePassword != null)
                    {
                        await ConfuzzleInternal.DecryptFromFileIntoNewFileAsync(expression.SourceFile, fileName, expression.SecurePassword);
                        return;
                    }
                    await ConfuzzleInternal.DecryptFromFileIntoNewFileAsync(expression.SourceFile, fileName, expression.Password);
                    return;
                default:
                    throw new NotSupportedException();
            }
        }

        /// <summary>
        ///     Write the decrypted data contents into a string.
        ///     This method is asynchronous.
        /// </summary>
        /// <returns>A UTF8 encoded text string.</returns>
        public async Task<string> IntoString()
        {
            switch (expression.DecryptFrom)
            {
                case SourceMode.Bytes:
                    if (expression.SecurePassword != null)
                    {
                        return await ConfuzzleInternal.DecryptFromBytesIntoStringAsync(expression.SourceData, expression.SecurePassword);
                    }
                    return await ConfuzzleInternal.DecryptFromBytesIntoStringAsync(expression.SourceData, expression.Password);
                case SourceMode.File:
                    if (expression.SecurePassword != null)
                    {
                        return await ConfuzzleInternal.DecryptFileIntoStringAsync(expression.SourceFile, expression.SecurePassword);
                    }
                    return await ConfuzzleInternal.DecryptFileIntoStringAsync(expression.SourceFile, expression.Password);
                default:
                    throw new NotSupportedException();
            }
        }
    }
}