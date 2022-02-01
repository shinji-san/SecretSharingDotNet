// ----------------------------------------------------------------------------
// <copyright file="Secret.cs" company="Private">
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

[assembly: System.Runtime.CompilerServices.InternalsVisibleTo("SecretSharingDotNetTest, PublicKey=0024000004800000940000000602000000240000525341310004000001000100257917fef6a3508bdfc3db4dd65b0b485261c2f5bff7380b7737b0d59f741d41b6086743a7957cab387fb7da8a17491dea1239b496cef97ef61cd76bc3b5f0f983d5e693083c8a0c283bb55edd6fe389abda1565c534a3537e9e087ddef8b1525520ebd5ff6f36e74baaa97522816f3a7998bbdd9392f99c0777c421634abaaa")]
namespace SecretSharingDotNet.Cryptography
{
    using Math;
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Text;

    /// <summary>
    /// This class represents the secret including members to parse or convert it.
    /// </summary>
    /// <typeparam name="TNumber">Numeric data type (An integer data type)</typeparam>
    public class Secret<TNumber> : IEquatable<Secret<TNumber>>, IComparable<Secret<TNumber>>
    {
        /// <summary>
        /// Saves the secret
        /// </summary>
        private readonly Calculator<TNumber> secretNumber;

        /// <summary>
        /// Initializes a new instance of the <see cref="Secret{TNumber}"/> class.
        /// </summary>
        /// <param name="secretNumber">A secret integer number represented by an <see cref="Calculator{TNumber}"/> instance.</param>
        /// <exception cref="T:System.ArgumentNullException"><paramref name="secretNumber"/> is <see langword="null"/></exception>
        internal Secret(Calculator<TNumber> secretNumber)
        {
            if (secretNumber == null)
            {
                throw new ArgumentNullException(nameof(secretNumber));
            }

            if (secretNumber.Sign < 0)
            {
                throw new ArgumentException($"The secret is represented by a negative {typeof(TNumber).Name}. Please choose secret which is represented by a positive {typeof(TNumber).Name}", nameof(secretNumber));
            }

            this.secretNumber = secretNumber;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="Secret{TNumber}"/> class.
        /// </summary>
        /// <param name="encoded">Secret encoded as base-64</param>
        /// <exception cref="T:System.ArgumentNullException"><paramref name="encoded"/> is <see langword="null"/>, empty or consists exclusively of white-space characters</exception>
        public Secret(string encoded) => this.secretNumber = ParseBase64(encoded);

        /// <summary>
        /// Casts the <typeparamref name="TNumber"/> instance to an <see cref="Secret{TNumber}"/> instance
        /// </summary>
        public static implicit operator Secret<TNumber>(TNumber number) => new Secret<TNumber>(number);

        /// <summary>
        /// Casts the <see cref="Secret{TNumber}"/> instance to an <typeparamref name="TNumber"/> instance
        /// </summary>
        public static implicit operator TNumber(Secret<TNumber> secret) => secret != null && secret.secretNumber != null ? secret.secretNumber.Value : default;

        /// <summary>
        /// Casts the <see cref="Secret{TNumber}"/> instance to an <see cref="Calculator{TNumber}"/> instance
        /// </summary>
        public static implicit operator Calculator<TNumber>(Secret<TNumber> secret) => secret?.secretNumber;

        /// <summary>
        /// Casts the <see cref="Calculator{TNumber}"/> instance to an <see cref="Secret{TNumber}"/> instance
        /// </summary>
        public static implicit operator Secret<TNumber>(Calculator<TNumber> calculator) => new Secret<TNumber>(calculator);

        /// <summary>
        /// Casts the <see cref="string"/> instance to an <see cref="Secret{TNumber}"/> instance
        /// </summary>
        public static implicit operator Secret<TNumber>(string secret) => new Secret<TNumber>(Calculator.Create(Encoding.Unicode.GetBytes(secret), typeof(TNumber)) as Calculator<TNumber>);

        /// <summary>
        /// Equality operator
        /// </summary>
        /// <param name="left">The left operand</param>
        /// <param name="right">The right operand</param>
        /// <returns>Returns <see langword="true"/> if its operands are equal, otherwise <see langword="false"/>.</returns>
        public static bool operator ==(Secret<TNumber> left, Secret<TNumber> right) => left?.Equals(right) ?? right is null;

        /// <summary>
        /// Inequality operator
        /// </summary>
        /// <param name="left">The left operand</param>
        /// <param name="right">The right operand</param>
        /// <returns>Returns <see langword="true"/> if its operands are not equal, otherwise <see langword="false"/>.</returns>
        public static bool operator !=(Secret<TNumber> left, Secret<TNumber> right) => !left?.Equals(right) ?? !(right is null);

        /// <summary>
        /// Greater than operator
        /// </summary>
        /// <param name="left">The left operand</param>
        /// <param name="right">The right operand</param>
        /// <returns></returns>
        public static bool operator >(Secret<TNumber> left, Secret<TNumber> right) => !(left is null) && !(right is null) && left.CompareTo(right) == 1;

        /// <summary>
        /// Less than operator
        /// </summary>
        /// <param name="left">The left operand</param>
        /// <param name="right">The right operand</param>
        /// <returns></returns>
        public static bool operator <(Secret<TNumber> left, Secret<TNumber> right) => !(left is null) && !(right is null) && left.CompareTo(right) == -1;

        /// <summary>
        /// Greater than or equal operator
        /// </summary>
        /// <param name="left">The left operand</param>
        /// <param name="right">The right operand</param>
        /// <returns></returns>
        public static bool operator >=(Secret<TNumber> left, Secret<TNumber> right) => !(left is null) && !(right is null) && left.CompareTo(right) >= 0;

        /// <summary>
        /// Less than or equal operator
        /// </summary>
        /// <param name="left">The left operand</param>
        /// <param name="right">The right operand</param>
        /// <returns></returns>
        public static bool operator <=(Secret<TNumber> left, Secret<TNumber> right) => !(left is null) && !(right is null) && left.CompareTo(right) <= 0;

        /// <summary>
        /// Compares this instance to a specified <see cref="Secret{TNumber}"/> and returns an indication of their relative values.
        /// </summary>
        /// <param name="other">An <see cref="Secret{TNumber}"/> instance to compare with this instance.</param>
        /// <returns>A value that indicates the relative order of the <see cref="Secret{TNumber}"/> instances being compared.</returns>
        /// <exception cref="T:System.ArgumentNullException"><paramref name="other"/> is <see langword="null"/></exception>
        public int CompareTo(Secret<TNumber> other)
        {
            if (other == null)
            {
                throw new ArgumentNullException(nameof(other));
            }

            return ((this.secretNumber * this.secretNumber).Sqrt - (other.secretNumber * other.secretNumber).Sqrt).Sign;
        }

        /// <summary>
        /// Determines whether this instance and an<paramref name="other"/> specified <see cref="Secret{TNumber}"/> instance are equal.
        /// </summary>
        /// <param name="other">The <see cref="Secret{TNumber}"/> instance to compare</param>
        /// <returns><see langword="true"/> if the value of the <paramref name="other"/> parameter is the same as the value of this instance; otherwise <see langword="false"/>.
        /// If <paramref name="other"/> is <see langword="null"/>, the method returns <see langword="false"/>.</returns>
        public bool Equals(Secret<TNumber> other)
        {
            return !(other is null) && this.secretNumber.Equals(other.secretNumber);
        }

        /// <summary>
        /// Returns a value that indicates whether the current instance and a specified object have the same value.
        /// </summary>
        /// <param name="obj">The object to compare.</param>
        /// <returns><see langword="true"/> if the <paramref name="obj"/> argument is a <see cref="Secret{TNumber}"/> object,
        /// and its value is equal to the value of the current <see cref="Secret{TNumber}"/> instance; otherwise, <see langword="false"/>.</returns>
        public override bool Equals(object obj)
        {
            return obj != null && this.Equals((Secret<TNumber>)obj);
        }

        /// <summary>
        /// Returns the hash code for the current <see cref="Secret{TNumber}"/> structure.
        /// </summary>
        /// <returns>A 32-bit signed integer hash code.</returns>
        public override int GetHashCode() => this.secretNumber.GetHashCode();

        /// <summary>
        /// Converts the value of <see cref="Secret{TNumber}"/> structure to its equivalent <see cref="string"/> representation
        /// that is unicode encoded.
        /// </summary>
        /// <returns><see cref="string"/> representation of <see cref="Secret{TNumber}"/></returns>
        public override string ToString()
        {
            int padCount = this.secretNumber.ByteCount % sizeof(char);
            if (padCount == 0)
            {
                return Encoding.Unicode.GetString(this.secretNumber.ByteRepresentation.ToArray(), 0, this.secretNumber.ByteCount);
            }

            var padded = new List<byte>(this.secretNumber.ByteRepresentation);
            for (int i = 0; i < padCount; i++)
            {
                padded.Add(0x00);
            }

            return Encoding.Unicode.GetString(padded.ToArray(), 0, padded.Count);
        }

        /// <summary>
        /// Converts the value of <see cref="Secret{TNumber}"/> structure to its equivalent <see cref="string"/> representation
        /// that is encoded with base-64 digits.
        /// </summary>
        /// <returns>The <see cref="string"/> representation in base 64</returns>
        public string ToBase64()
        {
            var bytes = this.secretNumber.ByteRepresentation.ToArray();
            return Convert.ToBase64String(bytes, 0, bytes.Length);
        }

        /// <summary>
        /// Parses a base-64 encoded secret and returns an <see cref="Secret{TNumber}"/> instance.
        /// </summary>
        /// <param name="encoded">Secret encoded as base-64</param>
        /// <exception cref="ArgumentNullException"><paramref name="encoded"/> is <see langword="null"/>, empty or  consists exclusively of white-space characters</exception>
        /// <returns>An <see cref="Secret{TNumber}"/> instance.</returns>
        private static Secret<TNumber> ParseBase64(string encoded)
        {
            if (string.IsNullOrWhiteSpace(encoded))
            {
                throw new ArgumentNullException(nameof(encoded));
            }

            byte[] bytes;
            try
            {
                bytes = Convert.FromBase64String(encoded);
            }
            catch (FormatException e)
            {
                throw new ArgumentException("", nameof(encoded), e);
            }

            return Calculator.Create(bytes, typeof(TNumber)) as Calculator<TNumber>;
        }
    }
}