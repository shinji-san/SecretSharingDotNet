// ----------------------------------------------------------------------------
// <copyright file="FinitePoint`1.cs" company="Private">
// Copyright (c) 2023 All Rights Reserved
// </copyright>
// <author>Sebastian Walther</author>
// <date>05/27/2023 06:05:12 PM</date>
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

namespace SecretSharingDotNet.Cryptography;

using Math;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
#if !NET8_0_OR_GREATER
using System.Text;
#else
using System.Runtime.CompilerServices;
#endif

/// <summary>
/// Represents the support point of the polynomial
/// </summary>
/// <typeparam name="TNumber">Numeric data type (An integer type)</typeparam>
[Obsolete("Use Share<TNumber> struct instead. This struct will be marked as internal in future releases.", false)]
public readonly record struct FinitePoint<TNumber> : IComparable<FinitePoint<TNumber>>
{
    /// <summary>
    /// Initializes a new instance of the <see cref="FinitePoint{TNumber}"/> struct.
    /// </summary>
    /// <param name="x">The x-coordinate as known as share index</param>
    /// <param name="polynomial">The polynomial</param>
    /// <param name="prime">The prime number given by the security level.</param>
    /// <exception cref="ArgumentNullException">One or more of the parameters <paramref name="x"/>, <paramref name="polynomial"/> or <paramref name="prime"/> are <see langword="null"/></exception>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Naming", "CA1704:IdentifiersShouldBeSpelledCorrectly", MessageId = "x")]
    public FinitePoint(Calculator<TNumber> x, ICollection<Calculator<TNumber>> polynomial, Calculator<TNumber> prime)
    {
        this.X = x ?? throw new ArgumentNullException(nameof(x));
        this.Y = Evaluate(polynomial ?? throw new ArgumentNullException(nameof(polynomial)), this.X, prime ?? throw new ArgumentNullException(nameof(prime)));
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="FinitePoint{TNumber}"/> struct.
    /// </summary>
    /// <param name="serialized">string representation of the <see cref="FinitePoint{TNumber}"/> struct</param>
    /// <exception cref="T:System.ArgumentNullException"><paramref name="serialized"/> is <see langword="null"/></exception>
#if NET8_0_OR_GREATER
    public FinitePoint(ReadOnlySpan<char> serialized)
#else
    public FinitePoint(string serialized)
#endif
    {
#if NET8_0_OR_GREATER
        if (serialized.IsEmpty)
#else
        if (string.IsNullOrWhiteSpace(serialized))
#endif
        {
            throw new ArgumentNullException(nameof(serialized));
        }

#if NET8_0_OR_GREATER
        var xReadOnlySpan = serialized[..serialized.IndexOf(Share<TNumber>.CoordinateSeparator)];
        var yReadOnlySpan = serialized[(serialized.IndexOf(Share<TNumber>.CoordinateSeparator) + 1)..];
        var numberType = typeof(TNumber);
        this.X = Calculator.Create(ToByteArray(xReadOnlySpan), numberType) as Calculator<TNumber>;
        this.Y = Calculator.Create(ToByteArray(yReadOnlySpan), numberType) as Calculator<TNumber>;
#else
        string[] s = serialized.Split(Share<TNumber>.CoordinateSeparatorArray);
        var numberType = typeof(TNumber);
        this.X = Calculator.Create(ToByteArray(s[0]), numberType) as Calculator<TNumber>;
        this.Y = Calculator.Create(ToByteArray(s[1]), numberType) as Calculator<TNumber>;
#endif
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
        this.X = x ?? throw new ArgumentNullException(nameof(x));
        this.Y = y ?? throw new ArgumentNullException(nameof(y));
    }

    /// <summary>
    /// Deconstructs this <see cref="FinitePoint{TNumber}"/> into its components.
    /// </summary>
    /// <param name="x">The X coordinate of the <see cref="FinitePoint{TNumber}"/>.</param>
    /// <param name="y">The Y coordinate of the <see cref="FinitePoint{TNumber}"/>.</param>
    public void Deconstruct(out Calculator<TNumber> x, out Calculator<TNumber> y)
    {
        x = this.X;
        y = this.Y;
    }

    /// <summary>
    /// Gets the X coordinate
    /// </summary>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Naming", "CA1704:IdentifiersShouldBeSpelledCorrectly", MessageId = "X")]
    public Calculator<TNumber> X { get; }

    /// <summary>
    /// Gets the Y coordinate
    /// </summary>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Naming", "CA1704:IdentifiersShouldBeSpelledCorrectly", MessageId = "Y")]
    public Calculator<TNumber> Y { get; }

    /// <summary>
    /// Greater than operator
    /// </summary>
    /// <param name="left">The first operand</param>
    /// <param name="right">The second operand</param>
    /// <returns>Returns <see langword="true"/> if its first operand is greater than its second operand, otherwise <see langword="false"/>.</returns>
    public static bool operator >(FinitePoint<TNumber> left, FinitePoint<TNumber> right) => left.CompareTo(right) == 1;

    /// <summary>
    /// Less than operator
    /// </summary>
    /// <param name="left">The first operand</param>
    /// <param name="right">The second operand</param>
    /// <returns>Returns <see langword="true"/> if its first operand is less than its second operand, otherwise <see langword="false"/>.</returns>
    public static bool operator <(FinitePoint<TNumber> left, FinitePoint<TNumber> right) => left.CompareTo(right) == -1;

    /// <summary>
    /// Greater than or equal operator
    /// </summary>
    /// <param name="left">The 1st operand</param>
    /// <param name="right">The second operand</param>
    /// <returns>Returns <see langword="true"/> if its first operand is greater than or equal to its second operand, otherwise <see langword="false"/>.</returns>
    public static bool operator >=(FinitePoint<TNumber> left, FinitePoint<TNumber> right) => left.CompareTo(right) >= 0;

    /// <summary>
    /// Less than or equal operator
    /// </summary>
    /// <param name="left">The first operand</param>
    /// <param name="right">The second operand</param>
    /// <returns>Returns <see langword="true"/> if its first operand is less than or equal to its second operand, otherwise <see langword="false"/>.</returns>
    public static bool operator <=(FinitePoint<TNumber> left, FinitePoint<TNumber> right) => left.CompareTo(right) <= 0;

    /// <inheritdoc />
    public int CompareTo(FinitePoint<TNumber> other)
    {
        return ((this.X.Pow(2) + this.Y.Pow(2)).Sqrt() - (other.X.Pow(2) + other.Y.Pow(2)).Sqrt()).Sign;
    }

    /// <summary>
    /// Returns the string representation of the <see cref="FinitePoint{TNumber}"/> structure.
    /// </summary>
    /// <returns>The string representation of the <see cref="FinitePoint{TNumber}"/> structure.</returns>
    public override string ToString() => string.Format(CultureInfo.InvariantCulture, "{0}{1}{2}", ToHexString(this.X.ByteRepresentation), Share<TNumber>.CoordinateSeparator.ToString(), ToHexString(this.Y.ByteRepresentation));

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
    /// <returns>human-readable / printable string</returns>
    /// <remarks>
    /// Based on discussion on <see href="https://stackoverflow.com/questions/623104/byte-to-hex-string/5919521#5919521">stackoverflow</see>
    /// </remarks>
    [Obsolete("Will be removed in future releases.", false)]
#if NET8_0_OR_GREATER
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
    private static string ToHexString(IEnumerable<byte> bytes)
    {
#if NET8_0_OR_GREATER
        return Convert.ToHexString(bytes as byte[] ?? bytes.ToArray());
#else
        byte[] byteArray = bytes as byte[] ?? bytes.ToArray();
        var hexRepresentation = new StringBuilder(byteArray.Length * 2);
        foreach (byte b in byteArray)
        {
            const string hexAlphabet = "0123456789ABCDEF";
            hexRepresentation.Append(hexAlphabet[b >> 4]).Append(hexAlphabet[b & 0xF]);
        }

        return hexRepresentation.ToString();
#endif
    }

    /// <summary>
    /// Converts a hexadecimal string to a byte array.
    /// </summary>
    /// <param name="hexString">hexadecimal string</param>
    /// <returns>Returns a byte array</returns>
    [Obsolete("Will be removed in future releases.", false)]
#if NET8_0_OR_GREATER
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static byte[] ToByteArray(ReadOnlySpan<char> hexString) => Convert.FromHexString(hexString);
#else
    private static byte[] ToByteArray(string hexString)
        {
            byte[] bytes = new byte[hexString.Length / 2];
            var hexValues = Array.AsReadOnly([
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
            ]);

            for (int i = 0, j = 0; j < hexString.Length; j += 2, i += 1)
            {
                const char zeroDigit = '0';
                bytes[i] = (byte)(hexValues[char.ToUpper(hexString[j + 0], CultureInfo.InvariantCulture) - zeroDigit] << 4 | hexValues[char.ToUpper(hexString[j + 1], CultureInfo.InvariantCulture) - zeroDigit]);
            }

            return bytes;
        }
#endif
}