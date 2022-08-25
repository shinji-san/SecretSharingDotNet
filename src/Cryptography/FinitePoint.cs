// ----------------------------------------------------------------------------
// <copyright file="FinitePoint.cs" company="Private">
// Copyright (c) 2019 All Rights Reserved
// </copyright>
// <author>Sebastian Walther</author>
// <date>04/20/2019 10:52:28 PM</date>
// ----------------------------------------------------------------------------

#region License
// ----------------------------------------------------------------------------
// Copyright 2019 Sebastian Walther
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
#endregion

namespace SecretSharingDotNet.Cryptography
{
    using Math;
    using System;
    using System.Collections.Generic;
    using System.Globalization;
    using System.Linq;
    using System.Text;

    /// <summary>
    /// Represents the support point of the polynomial
    /// </summary>
    /// <typeparam name="TNumber">Numeric data type (An integer type)</typeparam>
    public readonly struct FinitePoint<TNumber> : IEquatable<FinitePoint<TNumber>>, IComparable<FinitePoint<TNumber>>
    {
        /// <summary>
        /// Saves the X coordinate
        /// </summary>
        private readonly Calculator<TNumber> x;

        /// <summary>
        /// Saves the Y coordinate
        /// </summary>
        private readonly Calculator<TNumber> y;

        /// <summary>
        /// Initializes a new instance of the <see cref="FinitePoint{TNumber}"/> struct.
        /// </summary>
        /// <param name="x">X coordinate as known as share index</param>
        /// <param name="polynomial">Polynomial</param>
        /// <param name="prime">The prime number given by the security level.</param>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Naming", "CA1704:IdentifiersShouldBeSpelledCorrectly", MessageId = "x")]
        public FinitePoint(Calculator<TNumber> x, ICollection<Calculator<TNumber>> polynomial, Calculator<TNumber> prime)
        {
            this.x = x ?? throw new ArgumentNullException(nameof(x));
            this.y = Evaluate(polynomial ?? throw new ArgumentNullException(nameof(polynomial)), this.x, prime ?? throw new ArgumentNullException(nameof(prime)));
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="FinitePoint{TNumber}"/> struct.
        /// </summary>
        /// <param name="serialized">string representation of the <see cref="FinitePoint{TNumber}"/> struct</param>
        /// <exception cref="T:System.ArgumentNullException"><paramref name="serialized"/> is <see langword="null"/></exception>
        public FinitePoint(string serialized)
        {
            if (string.IsNullOrWhiteSpace(serialized))
            {
                throw new ArgumentNullException(nameof(serialized));
            }

            var s = serialized.Split('-');
            Type numberType = typeof(TNumber);
            this.x = Calculator.Create(ToByteArray(s[0]), numberType) as Calculator<TNumber>;
            this.y = Calculator.Create(ToByteArray(s[1]), numberType) as Calculator<TNumber>;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="FinitePoint{TNumber}"/> struct.
        /// </summary>
        /// <param name="x">X coordinate</param>
        /// <param name="y">Y coordinate</param>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Naming", "CA1704:IdentifiersShouldBeSpelledCorrectly", MessageId = "y")]
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Naming", "CA1704:IdentifiersShouldBeSpelledCorrectly", MessageId = "x")]
        public FinitePoint(Calculator<TNumber> x, Calculator<TNumber> y)
        {
            this.x = x;
            this.y = y;
        }

        /// <summary>
        /// Gets the X coordinate
        /// </summary>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Naming", "CA1704:IdentifiersShouldBeSpelledCorrectly", MessageId = "X")]
        public Calculator<TNumber> X => this.x;

        /// <summary>
        /// Gets the Y coordinate
        /// </summary>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Naming", "CA1704:IdentifiersShouldBeSpelledCorrectly", MessageId = "Y")]
        public Calculator<TNumber> Y => this.y;

        /// <summary>
        /// 
        /// </summary>
        /// <param name="left"></param>
        /// <param name="right"></param>
        /// <returns></returns>
        public static bool operator ==(FinitePoint<TNumber> left, FinitePoint<TNumber> right) => left.Equals(right);

        /// <summary>
        /// 
        /// </summary>
        /// <param name="left"></param>
        /// <param name="right"></param>
        /// <returns></returns>
        public static bool operator !=(FinitePoint<TNumber> left, FinitePoint<TNumber> right) => !left.Equals(right);

        /// <summary>
        /// 
        /// </summary>
        /// <param name="left"></param>
        /// <param name="right"></param>
        /// <returns></returns>
        public static bool operator >(FinitePoint<TNumber> left, FinitePoint<TNumber> right) => left.CompareTo(right) == 1;

        /// <summary>
        /// 
        /// </summary>
        /// <param name="left"></param>
        /// <param name="right"></param>
        /// <returns></returns>
        public static bool operator <(FinitePoint<TNumber> left, FinitePoint<TNumber> right) => left.CompareTo(right) == -1;

        /// <summary>
        /// 
        /// </summary>
        /// <param name="left"></param>
        /// <param name="right"></param>
        /// <returns></returns>
        public static bool operator >=(FinitePoint<TNumber> left, FinitePoint<TNumber> right) => left.CompareTo(right) >= 0;

        /// <summary>
        /// 
        /// </summary>
        /// <param name="left"></param>
        /// <param name="right"></param>
        /// <returns></returns>
        public static bool operator <=(FinitePoint<TNumber> left, FinitePoint<TNumber> right) => left.CompareTo(right) <= 0;

        /// <summary>
        /// 
        /// </summary>
        /// <param name="other"></param>
        /// <returns></returns>
        public int CompareTo(FinitePoint<TNumber> other)
        {
            return ((this.X.Pow(2) + this.Y.Pow(2)).Sqrt - (other.X.Pow(2) + other.Y.Pow(2)).Sqrt).Sign;
        }

        /// <summary>
        /// Determines whether this <see cref="FinitePoint{TNumber}"/> and a specified <see cref="FinitePoint{TNumber}"/> have the same value.
        /// </summary>
        /// <param name="other">The <see cref="FinitePoint{TNumber}"/> to compare to this instance.</param>
        /// <returns><see langword="true"/> if the value of the value parameter is the same as this <see cref="FinitePoint{TNumber}"/>; otherwise, <see langword="false"/>.</returns>
        public bool Equals(FinitePoint<TNumber> other)
        {
            return this.X.Equals(other.X) && this.Y.Equals(other.Y);
        }

        /// <summary>
        /// Determines whether this structure and a specified object, which must also be a <see cref="FinitePoint{TNumber}"/> object, have the same value.
        /// </summary>
        /// <param name="obj">The <see cref="FinitePoint{TNumber}"/> to compare to this instance.</param>
        /// <returns><see langword="true"/> if <paramref name="obj"/> is a <see cref="FinitePoint{TNumber}"/> and its value is the same as this instance; otherwise, <see langword="false"/>.
        /// If <paramref name="obj"/> is <see langword="null"/>, the method returns <see langword="false"/>.</returns>
        public override bool Equals(object obj)
        {
            return obj != null && this.Equals((FinitePoint<TNumber>)obj);
        }

        /// <summary>
        /// Returns the hash code for the current <see cref="FinitePoint{TNumber}"/> structure.
        /// </summary>
        /// <returns>A 32-bit signed integer hash code.</returns>
        public override int GetHashCode() => this.X.GetHashCode() ^ this.y.GetHashCode();

        /// <summary>
        /// Returns the string representation of the <see cref="FinitePoint{TNumber}"/> structure.
        /// </summary>
        /// <returns></returns>
        public override string ToString() => string.Format(CultureInfo.InvariantCulture, "{0}-{1}", ToHexString(this.x.ByteRepresentation), ToHexString(this.y.ByteRepresentation));

        /// <summary>
        /// Evaluates polynomial (coefficient tuple) at x, used to generate a shamir pool.
        /// </summary>
        /// <param name="polynomial">The polynomial</param>
        /// <param name="x">The x-coordinate</param>
        /// <param name="prime">Mersenne prime greater or equal 5</param>
        /// <returns>y-coordinate from type <see cref="Calculator{TNumber}"/></returns>
        private static Calculator<TNumber> Evaluate(IEnumerable<Calculator<TNumber>> polynomial, Calculator<TNumber> x, Calculator<TNumber> prime)
        {
            var polynomialArray = polynomial as Calculator<TNumber>[] ?? polynomial.ToArray();
            var result = Calculator<TNumber>.Zero;
            for (int index = polynomialArray.Length - 1; index >= 0; index--)
            {
                result = (result * x + polynomialArray[index]) % prime;
            }

            return result;
        }

        /// <summary>
        /// Converts a byte collection to hexadecimal string.
        /// </summary>
        /// <param name="bytes"></param>
        /// <returns>human readable / printable string</returns>
        /// <remarks>
        /// Based on discussion on <see href="https://stackoverflow.com/questions/623104/byte-to-hex-string/5919521#5919521">stackoverflow</see>
        /// </remarks>
        private static string ToHexString(IReadOnlyCollection<byte> bytes)
        {
            StringBuilder hexRepresentation = new StringBuilder(bytes.Count * 2);
            foreach (byte b in bytes)
            {
                const string hexAlphabet = "0123456789ABCDEF";
                hexRepresentation.Append(new[] { hexAlphabet[b >> 4], hexAlphabet[b & 0xF] });
            }

            return hexRepresentation.ToString();
        }

        /// <summary>
        /// Converts a hexadecimal string to a byte array.
        /// </summary>
        /// <param name="hexString">hexadecimal string</param>
        /// <returns></returns>
        private static byte[] ToByteArray(string hexString)
        {
            var bytes = new byte[hexString.Length / 2];
            var hexValues = Array.AsReadOnly(new[] {
                0x00,
                0x01,
                0x02,
                0x03,
                0x04,
                0x05,
                0x06,
                0x07,
                0x08,
                0x09,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x0A,
                0x0B,
                0x0C,
                0x0D,
                0x0E,
                0x0F
            });

            for (int x = 0, i = 0; i < hexString.Length; i += 2, x += 1)
            {
                const char zeroDigit = '0';
                bytes[x] = (byte)((hexValues[char.ToUpper(hexString[i + 0], CultureInfo.InvariantCulture) - zeroDigit] << 4) | hexValues[char.ToUpper(hexString[i + 1], CultureInfo.InvariantCulture) - zeroDigit]);
            }

            return bytes;
        }
    }
}