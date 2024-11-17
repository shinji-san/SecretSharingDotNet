// ----------------------------------------------------------------------------
// <copyright file="Secret`1.cs" company="Private">
// Copyright (c) 2022 All Rights Reserved
// </copyright>
// <author>Sebastian Walther</author>
// <date>09/22/2022 00:34:47 AM</date>
// ----------------------------------------------------------------------------

#region License
// ----------------------------------------------------------------------------
// Copyright 2022 Sebastian Walther
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

using Helper;
using Math;
using System;
#if NET6_0_OR_GREATER
using System.Buffers;
#endif
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

/// <summary>
/// This class represents the secret including members to parse or convert it.
/// </summary>
/// <typeparam name="TNumber">Numeric data type (An integer data type)</typeparam>
public readonly struct Secret<TNumber> : IEquatable<Secret<TNumber>>, IComparable<Secret<TNumber>>
{
    /// <summary>
    /// Maximum mark byte to terminate the secret array and to avoid negative secret values.
    /// </summary>
    /// <remarks>prime number greater than 2^13-1</remarks>
    private const byte MaxMarkByte = 0x7F;

    /// <summary>
    /// Minimum mark byte to terminate the secret array and to avoid negative secret values.
    /// </summary>
    /// <remarks>prime number equal to 2^13-1</remarks>
    private const byte MinMarkByte = 0x1F;

    /// <summary>
    /// The maximum mark byte count.
    /// </summary>
    private const int MarkByteCount = 1;

    /// <summary>
    ///  Represents an empty secret.
    /// </summary>
    private static readonly Secret<TNumber> EmptySecret = new Secret<TNumber>([0x00]) ;

    /// <summary>
    /// Saves the secret
    /// </summary>
    private readonly byte[] secretNumber;

    /// <summary>
    /// Initializes a new instance of the <see cref="Secret{TNumber}"/> class.
    /// </summary>
    /// <param name="secretSource">A secret as array of type <see cref="byte"/></param>
    /// <exception cref="T:System.ArgumentNullException"><paramref name="secretSource"/> is <see langword="null"/></exception>
#if NET6_0_OR_GREATER
    public Secret(ReadOnlySpan<byte> secretSource)
#else
    public Secret(byte[] secretSource)
#endif
    {
        if (secretSource == null)
        {
            throw new ArgumentNullException(nameof(secretSource));
        }

        if (secretSource.Length == 0)
        {
            throw new ArgumentException(ErrorMessages.EmptyCollection, nameof(secretSource));
        }

        byte[] buffer = new byte[1];
        using (var rng = RandomNumberGenerator.Create())
        {
            rng.GetNonZeroBytes(buffer);
        }

        byte[] bytes = new byte[secretSource.Length + 1];
        byte maxMarkByte = secretSource.Length == 1 ? MinMarkByte : MaxMarkByte;
        bytes[secretSource.Length] = (byte)((buffer[0] % maxMarkByte) + 1);
#if NET6_0_OR_GREATER
        secretSource.CopyTo(bytes);
#else
        secretSource.CopyTo(bytes, 0);
#endif
        this.secretNumber = bytes;
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="Secret{TNumber}"/> class.
    /// </summary>
    /// <param name="secretSource">Secret as <see cref="Calculator"/> or <see cref="Calculator{TNumber}"/> value.</param>
    public Secret(Calculator secretSource) : this(secretSource.ByteRepresentation.ToArray()) { }

    /// <summary>
    /// Initializes a new instance of the <see cref="Secret{TNumber}"/> class. Use this ctor to deserialize a base64 string to
    /// a <see cref="Secret{TNumber}"/> instance.
    /// </summary>
    /// <param name="encoded">Secret encoded as base-64</param>
    /// <remarks>For normal text use the implicit cast from <see cref="string"/> to <see cref="Secret{TNumber}"/></remarks>
    /// <exception cref="T:System.ArgumentNullException"><paramref name="encoded"/> is <see langword="null"/>, empty or consists exclusively of white-space characters</exception>
#if NET6_0_OR_GREATER
    public Secret(ReadOnlySpan<char> encoded) : this(FromBase64CharSpan(encoded)){ }
#else
    public Secret(string encoded) : this(Convert.FromBase64String(encoded)) { }
#endif

    /// <summary>
    /// Gets the <see cref="Secret{TNumber}"/> byte size.
    /// </summary>
    internal int SecretByteSize => this.secretNumber.Length;

    /// <summary>
    /// Gets this <see cref="Secret{TNumber}"/> as an a0 coefficient.
    /// </summary>
    internal Calculator<TNumber> ToCoefficient => Calculator.Create(this.secretNumber, typeof(TNumber)) as Calculator<TNumber>;

    /// <summary>
    /// Casts the <typeparamref name="TNumber"/> instance to an <see cref="Secret{TNumber}"/> instance
    /// </summary>
    public static implicit operator Secret<TNumber>(TNumber number) => ((Calculator<TNumber>)number).ByteRepresentation.ToArray();

    /// <summary>
    /// Casts the <see cref="Secret{TNumber}"/> instance to an <typeparamref name="TNumber"/> instance
    /// </summary>
    public static implicit operator TNumber(Secret<TNumber> secret)
    {
        if (secret.secretNumber == null || secret.secretNumber.Length == 0)
        {
            return default;
        }

        return ((Calculator<TNumber>)secret).Value;
    }

    /// <summary>
    /// Casts the <see cref="Secret{TNumber}"/> instance to an <see cref="Calculator{TNumber}"/> instance
    /// </summary>
    public static implicit operator Calculator<TNumber>(Secret<TNumber> secret)
    {
        byte[] bytes = secret.secretNumber.Subset(0, secret.secretNumber.Length - MarkByteCount);
        return Calculator.Create(bytes, typeof(TNumber)) as Calculator<TNumber>;
    }

    /// <summary>
    /// Casts the <see cref="Calculator{TNumber}"/> instance to an <see cref="Secret{TNumber}"/> instance.
    /// </summary>
    public static implicit operator Secret<TNumber>(Calculator<TNumber> calculator) => calculator.ByteRepresentation.ToArray();

    /// <summary>
    /// Casts the <see cref="byte"/> array instance to an <see cref="Secret{TNumber}"/> instance.
    /// </summary>
    public static implicit operator Secret<TNumber>(byte[] array) => new Secret<TNumber>(array);

#if NET6_0_OR_GREATER
    /// <summary>
    /// Casts the <see cref="ReadOnlySpan{Byte}"/> to an <see cref="Secret{TNumber}"/> instance.
    /// </summary>
    public static implicit operator Secret<TNumber>(ReadOnlySpan<byte> buffer) => new Secret<TNumber>(buffer);
#endif

    /// <summary>
    /// Casts the <see cref="Secret{TNumber}"/> instance to an <see cref="byte"/> array instance.
    /// </summary>
    public static implicit operator byte[](Secret<TNumber> secret) => secret.ToByteArray();

#if NET6_0_OR_GREATER
    /// <summary>
    /// Casts the <see cref="Secret{TNumber}"/> instance to a <see cref="ReadOnlySpan{Byte}"/>.
    /// </summary>
    public static implicit operator ReadOnlySpan<byte>(Secret<TNumber> secret) => secret.AsReadOnlySpan();
#endif

#if NET6_0_OR_GREATER
    /// <summary>
    /// Casts the <see cref="String"/> instance to an <see cref="Secret{TNumber}"/> instance
    /// </summary>
    public static implicit operator Secret<TNumber>(string secretText) => secretText.AsSpan();
        
    /// <summary>
    /// Casts the <see cref="ReadOnlySpan{Char}"/> instance to an <see cref="Secret{TNumber}"/> instance
    /// </summary>
    public static implicit operator Secret<TNumber>(ReadOnlySpan<char> secretText)
    {
        ArrayBufferWriter<byte> arrayBufferWriter = new();
        Encoding.Unicode.GetBytes(secretText, arrayBufferWriter);
        Secret<TNumber> secret = new(arrayBufferWriter.WrittenSpan);
        arrayBufferWriter.Clear();
        return secret;
    }
#else
    /// <summary>
    /// Casts the <see cref="string"/> instance to an <see cref="Secret{TNumber}"/> instance
    /// </summary>
    public static implicit operator Secret<TNumber>(string secretText) => new Secret<TNumber>(Encoding.Unicode.GetBytes(secretText));
#endif

    /// <summary>
    /// Equality operator
    /// </summary>
    /// <param name="left">The left operand</param>
    /// <param name="right">The right operand</param>
    /// <returns>Returns <see langword="true"/> if its operands are equal, otherwise <see langword="false"/>.</returns>
    public static bool operator ==(Secret<TNumber> left, Secret<TNumber> right) => left.Equals(right);

    /// <summary>
    /// Inequality operator
    /// </summary>
    /// <param name="left">The left operand</param>
    /// <param name="right">The right operand</param>
    /// <returns>Returns <see langword="true"/> if its operands aren't equal, otherwise <see langword="false"/>.</returns>
    public static bool operator !=(Secret<TNumber> left, Secret<TNumber> right) => !left.Equals(right);

    /// <summary>
    /// Greater than operator
    /// </summary>
    /// <param name="left">The left operand</param>
    /// <param name="right">The right operand</param>
    /// <returns></returns>
    public static bool operator >(Secret<TNumber> left, Secret<TNumber> right) => left.CompareTo(right) > 0;

    /// <summary>
    /// Less than operator
    /// </summary>
    /// <param name="left">The left operand</param>
    /// <param name="right">The right operand</param>
    /// <returns></returns>
    public static bool operator <(Secret<TNumber> left, Secret<TNumber> right) => left.CompareTo(right) < 0;

    /// <summary>
    /// Greater than or equal operator
    /// </summary>
    /// <param name="left">The left operand</param>
    /// <param name="right">The right operand</param>
    /// <returns></returns>
    public static bool operator >=(Secret<TNumber> left, Secret<TNumber> right) => left.CompareTo(right) >= 0;

    /// <summary>
    /// Less than or equal operator
    /// </summary>
    /// <param name="left">The left operand</param>
    /// <param name="right">The right operand</param>
    /// <returns></returns>
    public static bool operator <=(Secret<TNumber> left, Secret<TNumber> right) => left.CompareTo(right) <= 0;

    /// <summary>
    /// Compares this instance to a specified <see cref="Secret{TNumber}"/> and returns an indication of their relative values.
    /// </summary>
    /// <param name="other">An <see cref="Secret{TNumber}"/> instance to compare with this instance.</param>
    /// <returns>A value that indicates the relative order of the <see cref="Secret{TNumber}"/> instances being compared.</returns>
    public int CompareTo(Secret<TNumber> other) => this.secretNumber
        .Subset(0, this.SecretByteSize - MarkByteCount)
        .CompareTo(other.secretNumber.Subset(0, other.SecretByteSize - MarkByteCount));

    /// <summary>
    /// Determines whether this instance and an<paramref name="other"/> specified <see cref="Secret{TNumber}"/> instance are equal.
    /// </summary>
    /// <param name="other">The <see cref="Secret{TNumber}"/> instance to compare</param>
    /// <returns><see langword="true"/> if the value of the <paramref name="other"/> parameter is the same as the value of this instance; otherwise <see langword="false"/>.
    /// If <paramref name="other"/> is <see langword="null"/>, the method returns <see langword="false"/>.</returns>
    public bool Equals(Secret<TNumber> other)
    {
        return this.secretNumber.Subset(0, this.SecretByteSize - MarkByteCount)
            .SequenceEqual(other.secretNumber.Subset(0, other.SecretByteSize - MarkByteCount));
    }

    /// <summary>
    /// Returns a value that indicates whether the current instance and a specified object have the same value.
    /// </summary>
    /// <param name="obj">The object to compare.</param>
    /// <returns><see langword="true"/> if the <paramref name="obj"/> argument is a <see cref="Secret{TNumber}"/> object,
    /// and its value is equal to the value of the current <see cref="Secret{TNumber}"/> instance; otherwise, <see langword="false"/>.</returns>
    public override bool Equals(object obj) => obj != null && this.Equals((Secret<TNumber>)obj);

    /// <summary>
    /// Returns the hash code for the current <see cref="Secret{TNumber}"/> structure.
    /// </summary>
    /// <returns>A 32-bit signed integer hash code.</returns>
    public override int GetHashCode() => this.secretNumber.GetHashCode();

    /// <summary>
    /// Converts the value of <see cref="Secret{TNumber}"/> structure to its equivalent <see cref="string"/> representation
    /// that is Unicode encoded.
    /// </summary>
    /// <returns><see cref="string"/> representation of <see cref="Secret{TNumber}"/></returns>
    public override string ToString()
    {
        int padCount = (this.secretNumber.Length - MarkByteCount) % sizeof(char);
        if (padCount == 0)
        {
            return Encoding.Unicode.GetString(this.secretNumber, 0, this.secretNumber.Length - MarkByteCount);
        }

        var padded = new List<byte>(this.secretNumber.Subset(0, this.secretNumber.Length - MarkByteCount));
        for (int i = 0; i < padCount; i++)
        {
            padded.Add(0x00);
        }

        return Encoding.Unicode.GetString(padded.ToArray(), 0, padded.Count);
    }

    /// <summary>
    /// Converts the secret to a byte array.
    /// </summary>
    /// <returns>Array of type <see cref="byte"/></returns>
    public byte[] ToByteArray()
    {
        return this.secretNumber.Subset(0, this.secretNumber.Length - MarkByteCount);
    }

#if NET6_0_OR_GREATER
    /// <summary>
    /// Converts the secret to a <see cref="ReadOnlySpan{Byte}"/>.
    /// </summary>
    /// <returns></returns>
    public ReadOnlySpan<byte> AsReadOnlySpan()
    {
        return this.secretNumber.AsSpan(0, this.secretNumber.Length - MarkByteCount);
    }
#endif

    /// <summary>
    /// Converts the value of <see cref="Secret{TNumber}"/> structure to its equivalent <see cref="string"/> representation
    /// that is encoded with base-64 digits.
    /// </summary>
    /// <returns>The <see cref="string"/> representation in base 64</returns>
    public string ToBase64()
    {
        return Convert.ToBase64String(this.secretNumber, 0, this.secretNumber.Length - MarkByteCount);
    }

#if NET6_0_OR_GREATER
    private static ReadOnlySpan<byte> FromBase64CharSpan(ReadOnlySpan<char> encoded)
    {
        if (encoded.IsEmpty || encoded.IsWhiteSpace())
        {
            throw new ArgumentException(ErrorMessages.EmptyCollection, nameof(encoded));
        }

        var bytes = new Span<byte>(new byte[(encoded.Length * 3 + 3) / 4]);
        return Convert.TryFromBase64Chars(encoded, bytes, out int bytesWritten) ? bytes[..bytesWritten] : Span<byte>.Empty;
    }
#endif

    /// <summary>
    /// Create <see cref="Secret{TNumber}"/> from a0 coefficient
    /// </summary>
    /// <typeparam name="TNumberStatic"></typeparam>
    /// <param name="coefficient">a0 coefficient</param>
    /// <returns>A <see cref="Secret{TNumber}"/></returns>
    internal static Secret<TNumberStatic> FromCoefficient<TNumberStatic>(Calculator<TNumberStatic> coefficient) =>
        new Secret<TNumberStatic>(coefficient.ByteRepresentation.Take(coefficient.ByteCount - MarkByteCount).ToArray());

    /// <summary>
    /// Creates a random secret
    /// </summary>
    /// <param name="prime">mersenne prime number</param>
    /// <remarks>Use this ctor to create a random secret</remarks>
    internal static Secret<TNumberStatic> CreateRandom<TNumberStatic>(Calculator<TNumberStatic> prime)
    {
        byte[] randomSecretBytes = new byte[prime.ByteCount];
        using (var rng = RandomNumberGenerator.Create())
        {
            rng.GetBytes(randomSecretBytes);
        }

        int i = randomSecretBytes.Length - 1;
        while (i > 0)
        {
            randomSecretBytes[i] = i == 1 ? MinMarkByte : MaxMarkByte;
            var randomSecretNumber = Calculator.Create(randomSecretBytes, typeof(TNumberStatic)) as Calculator<TNumberStatic>;
            var a0 = randomSecretNumber?.Abs() % prime;
            if (a0 == randomSecretNumber)
            {
                break;
            }

            if (a0.IsZero)
            {
                return Secret<TNumberStatic>.EmptySecret;
            }

            randomSecretBytes[i--] = 0x00;
        }

        return new Secret<TNumberStatic>(randomSecretBytes.Subset(0, randomSecretBytes.Length - (randomSecretBytes.Length - i)));
    }
}
