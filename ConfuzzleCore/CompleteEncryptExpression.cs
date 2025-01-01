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
            switch (this.expression.EncryptFrom)
            {
                case SourceMode.String:
                    if (this.expression.SecurePassword != null)
                    {
                        return await ConfuzzleInternal.EncryptStringIntoBytesAsync(this.expression.StringInputData, this.expression.SecurePassword);
                    }
                    return await ConfuzzleInternal.EncryptStringIntoBytesAsync(this.expression.StringInputData, this.expression.Password);
                case SourceMode.File:
                    if (this.expression.SecurePassword != null)
                    {
                        return await ConfuzzleInternal.EncryptFileIntoBytesAsync(this.expression.SourceFile, this.expression.SecurePassword);
                    }
                    return await ConfuzzleInternal.EncryptFileIntoBytesAsync(this.expression.SourceFile, this.expression.Password);
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
            switch (this.expression.EncryptFrom)
            {
                case SourceMode.String:
                    if (this.expression.SecurePassword != null)
                    {
                        await ConfuzzleInternal.EncryptStringIntoFileAsync(this.expression.StringInputData, fileName, this.expression.SecurePassword);
                        return;
                    }
                    await ConfuzzleInternal.EncryptStringIntoFileAsync(this.expression.StringInputData, fileName, this.expression.Password);
                    return;
                case SourceMode.File:
                    if (this.expression.SecurePassword != null)
                    {
                        await ConfuzzleInternal.EncryptFileIntoNewFileAsync(this.expression.SourceFile, fileName, this.expression.SecurePassword);
                        return;
                    }
                    await ConfuzzleInternal.EncryptFileIntoNewFileAsync(this.expression.SourceFile, fileName, this.expression.Password);
                    return;
                default:
                    throw new NotSupportedException();
            }
        }
    }
}
