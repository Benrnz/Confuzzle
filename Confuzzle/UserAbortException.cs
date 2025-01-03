﻿namespace ConfuzzleCommandLine
{
    [Serializable]
    internal class UserAbortException : Exception
    {
        public UserAbortException()
        {
        }

        public UserAbortException(string message) : base(message)
        {
        }

        public UserAbortException(string message, Exception innerException) : base(message, innerException)
        {
        }
    }
}
