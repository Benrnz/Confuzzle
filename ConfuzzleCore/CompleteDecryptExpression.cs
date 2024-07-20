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
            switch (this.expression.DecryptFrom)
            {
                case SourceMode.Bytes:
                    if (this.expression.SecurePassword != null)
                    {
                        await ConfuzzleInternal.DecryptFromBytesIntoNewFileAsync(this.expression.SourceData, fileName, this.expression.SecurePassword);
                        return;
                    }
                    await ConfuzzleInternal.DecryptFromBytesIntoNewFileAsync(this.expression.SourceData, fileName, this.expression.Password);
                    return;
                case SourceMode.File:
                    if (this.expression.SecurePassword != null)
                    {
                        await ConfuzzleInternal.DecryptFromFileIntoNewFileAsync(this.expression.SourceFile, fileName, this.expression.SecurePassword);
                        return;
                    }
                    await ConfuzzleInternal.DecryptFromFileIntoNewFileAsync(this.expression.SourceFile, fileName, this.expression.Password);
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
            switch (this.expression.DecryptFrom)
            {
                case SourceMode.Bytes:
                    if (this.expression.SecurePassword != null)
                    {
                        return await ConfuzzleInternal.DecryptFromBytesIntoStringAsync(this.expression.SourceData, this.expression.SecurePassword);
                    }
                    return await ConfuzzleInternal.DecryptFromBytesIntoStringAsync(this.expression.SourceData, this.expression.Password);
                case SourceMode.File:
                    if (this.expression.SecurePassword != null)
                    {
                        return await ConfuzzleInternal.DecryptFileIntoStringAsync(this.expression.SourceFile, this.expression.SecurePassword);
                    }
                    return await ConfuzzleInternal.DecryptFileIntoStringAsync(this.expression.SourceFile, this.expression.Password);
                default:
                    throw new NotSupportedException();
            }
        }
    }
}