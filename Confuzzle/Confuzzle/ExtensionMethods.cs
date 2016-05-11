using System;
using System.Collections.Generic;
using System.IO;

namespace Confuzzle
{
    internal static class ExtensionMethods
    {
        /// <summary>
        ///     Reads an unsigned short integer from the stream.
        /// </summary>
        /// <param name="stream">The stream to read from.</param>
        public static ushort ReadUShort(this Stream stream)
        {
            if (stream == null) throw new ArgumentNullException(nameof(stream));

            var valueBytes = ReadExact(stream, sizeof(ushort));
            if (BitConverter.IsLittleEndian)
                Array.Reverse(valueBytes);

            return BitConverter.ToUInt16(valueBytes, 0);
        }

        /// <summary>
        ///     Reads the specified number of bytes from a stream.
        /// </summary>
        /// <param name="stream">The stream to read from.</param>
        /// <param name="length">The number of bytes to read.</param>
        /// <returns>A byte array containing the read data.</returns>
        public static byte[] ReadExact(this Stream stream, int length)
        {
            if (stream == null) throw new ArgumentNullException(nameof(stream));

            var value = new byte[length];
            int sizeRead = stream.Read(value, 0, length);

            if (sizeRead != length)
                throw new InvalidDataException($"Unable to read {length} bytes.");

            return value;
        }

        /// <summary>
        ///     Writes an unsigned short integer to the stream.
        /// </summary>
        /// <param name="stream">The stream to write to.</param>
        /// <param name="value">The value to write.</param>
        public static void WriteUShort(this Stream stream, ushort value)
        {
            if (stream == null) throw new ArgumentNullException(nameof(stream));

            var valueBytes = BitConverter.GetBytes(value);
            if (BitConverter.IsLittleEndian)
                Array.Reverse(valueBytes);

            Write(stream, valueBytes);
        }

        /// <summary>
        ///     Writes an array of bytes to the stream.
        /// </summary>
        /// <param name="stream">The stream to write to.</param>
        /// <param name="value">The bytes to write.</param>
        public static void Write(this Stream stream, byte[] value)
        {
            if (stream == null) throw new ArgumentNullException(nameof(stream));

            if (value != null)
                stream.Write(value, 0, value.Length);
        }

        /// <summary>
        ///     Completely fills an array with a sequence of values.
        /// </summary>
        /// <typeparam name="T">The type of value in the array.</typeparam>
        /// <param name="array">The array to be filled.</param>
        /// <param name="fillValues">A sequence of values to fill the array with.</param>
        /// <remarks>
        ///     If <paramref name="fillValues"/> contains more values than the array will hold, any additional values
        ///     will be ignored.
        ///     If <paramref name="fillValues"/> contains fewer values than the array will hold, the fill values will be
        ///     repeated until the array is filled.
        /// </remarks>
        public static void Fill<T>(this T[] array, IEnumerable<T> fillValues)
        {
            if (array == null) throw new ArgumentNullException(nameof(array));
            if (fillValues == null) throw new ArgumentNullException(nameof(fillValues));

            var count = 0;
            foreach (var fillValue in fillValues)
            {
                array[count++] = fillValue;

                if (count >= array.Length)
                    return;
            }

            for (var offset = count; offset < array.Length; offset += count)
            {
                var copyCount = Math.Min(count, array.Length - offset);
                Array.Copy(array, 0, array, offset, copyCount);
            }
        }
    }
}
