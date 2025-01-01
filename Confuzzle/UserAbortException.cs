using System;
using System.Runtime.Serialization;

namespace ConfuzzleCommandLine
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

        protected UserAbortException(SerializationInfo info, StreamingContext context) : base(info, context)
        {
        }
    }
}
