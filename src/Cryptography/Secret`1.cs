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

using Extension;
using Math;
using SecureArray;
using System;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;

/// <summary>
/// This class represents the secret including members to parse or convert it.
/// </summary>
/// <typeparam name="TNumber">Numeric data type (An integer data type)</typeparam>
/// <remarks>
/// <para>
/// <b>Ownership and copy semantics — single-owner discipline required.</b>
/// <see cref="Secret{TNumber}"/> is a <c>readonly struct</c> that wraps a single
/// shared <see cref="PinnedPoolArray{T}"/>. Struct assignment copies the wrapper
/// by value, but the underlying pinned buffer is a reference type — so every
/// "copy" of a <see cref="Secret{TNumber}"/> aliases the <em>same</em> backing
/// store. Calling <see cref="Dispose"/> on any copy wipes the buffer, and every
/// other copy then observes a disposed state on its next operation:
/// </para>
/// <code>
/// Secret&lt;T&gt; kept = MakeSecret();
/// {
///     using var copy = kept;       // struct-copy aliases the same PinnedPoolArray
///     /* … */
/// }                                 // copy.Dispose wipes the shared buffer
/// kept.ToByteArray();               // throws ObjectDisposedException
/// </code>
/// <para>
/// Recommended discipline: <em>do not pass <see cref="Secret{TNumber}"/> by value
/// across dispose boundaries</em>. Treat each constructed instance as a
/// single-owner resource — the same convention as for any
/// <see cref="IDisposable"/>. The <c>readonly struct</c> shape is preserved for
/// compatibility but the type behaves semantically like a class-backed handle.
/// </para>
/// <para>
/// A planned future-work item is to migrate the type to a sealed reference class
/// so the language enforces this discipline directly. The migration is gated on
/// the next breaking-change release cycle.
/// </para>
/// </remarks>
#if DEBUG
[DebuggerDisplay("{ToString()}")]
#else
[DebuggerDisplay("*** Secured Value ***")]
#endif
public readonly struct Secret<TNumber> : IEquatable<Secret<TNumber>>, IComparable<Secret<TNumber>>, IDisposable
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
    /// Saves the secret
    /// </summary>
    private readonly PinnedPoolArray<byte> secretNumber;

    /// <summary>
    /// Initializes a new instance of the <see cref="Secret{TNumber}"/> class.
    /// </summary>
    /// <param name="secretSource">A secret as array of type <see cref="byte"/></param>
    /// <exception cref="T:System.ArgumentNullException"><paramref name="secretSource"/> is <see langword="null"/></exception>
#if NET8_0_OR_GREATER
    public Secret(ReadOnlySpan<byte> secretSource) : this(secretSource, secretSource.Length)
    {
    }
#else
    public Secret(byte[] secretSource) : this(secretSource, secretSource.Length)
    {
    }
#endif

    /// <summary>
    /// Initializes a new instance of the <see cref="Secret{TNumber}"/> class.
    /// </summary>
    /// <param name="secretSource">A secret as array of type <see cref="byte"/></param>
    /// <param name="length">Length of the secret</param>
    /// <exception cref="T:System.ArgumentNullException"><paramref name="secretSource"/> is <see langword="null"/></exception>
#if NET8_0_OR_GREATER
    public Secret(ReadOnlySpan<byte> secretSource, int length)
    {
        if (secretSource.IsEmpty)
        {
#else
    public Secret(byte[] secretSource, int length)
    {
        if (secretSource == null)
        {
#endif
            throw new ArgumentNullException(nameof(secretSource));
        }

        if (length == 0)
        {
            throw new ArgumentException(ErrorMessages.EmptyCollection, nameof(secretSource));
        }

        this.secretNumber = new PinnedPoolArray<byte>(length + 1);
        byte maxMarkByte = length == 1 ? MinMarkByte : MaxMarkByte;
        // Termination byte uniformly distributed over [1, maxMarkByte]. SecureRandom.NextInt32
        // performs rejection sampling internally — no `% maxMarkByte` modulo bias.
        this.secretNumber.PoolArray[length] = (byte)SecureRandom.NextInt32(1, maxMarkByte + 1);
#if NET8_0_OR_GREATER
        secretSource[..length].CopyTo(this.secretNumber.PoolArray);
#else
        Array.Copy(secretSource, 0, this.secretNumber.PoolArray, 0, length);
#endif
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="Secret{TNumber}"/> class.
    /// </summary>
    /// <param name="secretSource">Secret as <see cref="Calculator"/> or <see cref="Calculator{TNumber}"/> value.</param>
    public Secret(Calculator secretSource)
    {
        using var bytes = secretSource.ByteRepresentation;
        this = new Secret<TNumber>(bytes.PoolArray, bytes.Length);
    }

    /// <summary>
    /// Creates a new <see cref="Secret{TNumber}"/> by encoding the characters of a pinned
    /// character buffer to UTF-8.
    /// </summary>
    /// <param name="text">
    /// A <see cref="PinnedPoolArray{T}"/> of <see cref="char"/> containing the secret text.
    /// The caller retains ownership and is responsible for disposing <paramref name="text"/>.
    /// </param>
    /// <returns>A new <see cref="Secret{TNumber}"/> whose byte content is the UTF-8 encoding of <paramref name="text"/>.</returns>
    /// <remarks>
    /// The character data is encoded directly into a pinned byte buffer; no intermediate
    /// unpinned heap allocation (such as a <see cref="string"/>, <see cref="System.Text.StringBuilder"/>,
    /// or <c>System.Buffers.ArrayBufferWriter&lt;T&gt;</c>) is created.
    /// </remarks>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="text"/> is <see langword="null"/>.
    /// </exception>
    /// <exception cref="ArgumentException">
    /// Thrown when <paramref name="text"/> has length zero.
    /// </exception>
    /// <exception cref="ObjectDisposedException">
    /// Thrown when <paramref name="text"/> has already been disposed.
    /// </exception>
    public static Secret<TNumber> FromText(PinnedPoolArray<char> text) => FromText(text, Encoding.UTF8);

    /// <summary>
    /// Creates a new <see cref="Secret{TNumber}"/> by encoding the characters of a pinned
    /// character buffer using the specified <see cref="Encoding"/>.
    /// </summary>
    /// <param name="text">
    /// A <see cref="PinnedPoolArray{T}"/> of <see cref="char"/> containing the secret text.
    /// The caller retains ownership and is responsible for disposing <paramref name="text"/>.
    /// </param>
    /// <param name="encoding">The <see cref="Encoding"/> used to convert characters to bytes.</param>
    /// <returns>A new <see cref="Secret{TNumber}"/> whose byte content is the encoding of <paramref name="text"/>.</returns>
    /// <remarks>
    /// The character data is encoded directly into a pinned byte buffer; no intermediate
    /// unpinned heap allocation is created. The intermediate pinned byte buffer is securely
    /// cleared on dispose before this method returns.
    /// </remarks>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="text"/> or <paramref name="encoding"/> is <see langword="null"/>.
    /// </exception>
    /// <exception cref="ArgumentException">
    /// Thrown when <paramref name="text"/> has length zero.
    /// </exception>
    /// <exception cref="ObjectDisposedException">
    /// Thrown when <paramref name="text"/> has already been disposed.
    /// </exception>
    public static Secret<TNumber> FromText(PinnedPoolArray<char> text, Encoding encoding)
    {
        if (text is null)
        {
            throw new ArgumentNullException(nameof(text));
        }

        if (encoding is null)
        {
            throw new ArgumentNullException(nameof(encoding));
        }

        if (text.Length == 0)
        {
            throw new ArgumentException(ErrorMessages.EmptyCollection, nameof(text));
        }

        int byteCount = encoding.GetByteCount(text.PoolArray, 0, text.Length);
        using var bytes = new PinnedPoolArray<byte>(byteCount);
        encoding.GetBytes(text.PoolArray, 0, text.Length, bytes.PoolArray, 0);
        return new Secret<TNumber>(bytes.PoolArray, byteCount);
    }

    /// <summary>
    /// Creates a new <see cref="Secret{TNumber}"/> by decoding standard Base64
    /// (RFC&#160;4648 §4: alphabet <c>A–Z a–z 0–9 + /</c>, <c>=</c> padding) from a pinned
    /// character buffer.
    /// </summary>
    /// <param name="base64">
    /// A <see cref="PinnedPoolArray{T}"/> of <see cref="char"/> containing standard
    /// Base64-encoded data. Whitespace characters (space, tab, CR, LF, FF, VT) are ignored,
    /// matching the behaviour of <see cref="Convert.FromBase64String(string)"/>. The caller
    /// retains ownership and is responsible for disposing the buffer.
    /// </param>
    /// <returns>A new <see cref="Secret{TNumber}"/> whose byte content is the decoded payload.</returns>
    /// <remarks>
    /// Decoding goes directly from the input <see cref="PinnedPoolArray{T}"/> of
    /// <see cref="char"/> into a pinned, securely cleared <see cref="PinnedPoolArray{T}"/>
    /// of <see cref="byte"/> — no intermediate <see cref="string"/>, <see cref="byte"/>
    /// array, or other unpinned managed-heap copy is allocated. The intermediate pinned
    /// byte buffer is securely cleared on dispose before this method returns. URL-safe
    /// Base64 (alphabet <c>- _</c>) is not accepted; encode with the standard alphabet
    /// to interoperate.
    /// </remarks>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="base64"/> is <see langword="null"/>.
    /// </exception>
    /// <exception cref="ArgumentException">
    /// Thrown when <paramref name="base64"/> contains no non-whitespace characters.
    /// </exception>
    /// <exception cref="ObjectDisposedException">
    /// Thrown when <paramref name="base64"/> has already been disposed.
    /// </exception>
    /// <exception cref="FormatException">
    /// Thrown when <paramref name="base64"/> contains an invalid character (with the
    /// position of the offending character in the message), is not padded to a multiple
    /// of four non-whitespace characters, or contains malformed <c>'='</c> padding.
    /// </exception>
    public static Secret<TNumber> FromBase64(PinnedPoolArray<char> base64)
    {
        using var decoded = DecodeBase64(base64);
        return new Secret<TNumber>(decoded.PoolArray, decoded.Length);
    }

    /// <summary>
    /// Decodes a pinned Base64 character buffer into a pinned byte buffer in two passes:
    /// pass 1 validates the input and computes the output size; pass 2 performs the
    /// actual decoding. No intermediate unpinned heap allocation is created.
    /// </summary>
    private static PinnedPoolArray<byte> DecodeBase64(PinnedPoolArray<char> base64)
    {
        if (base64 is null)
        {
            throw new ArgumentNullException(nameof(base64));
        }

        var src = base64.PoolArray;
        int srcLen = base64.Length;

        // Pass 1: validate and count.
        int numNonWs = 0;
        int paddingCount = 0;
        bool seenPadding = false;
        for (int i = 0; i < srcLen; i++)
        {
            char c = src[i];
            int sextet = DecodeBase64Char(c);
            if (sextet == WhitespaceSextet)
            {
                continue;
            }

            if (sextet == InvalidSextet)
            {
                throw new FormatException(string.Format(ErrorMessages.InvalidBase64CharAtPosition, c, i));
            }

            if (sextet == PaddingSextet)
            {
                seenPadding = true;
                paddingCount++;
                numNonWs++;
                continue;
            }

            if (seenPadding)
            {
                throw new FormatException(ErrorMessages.InvalidBase64Padding);
            }

            numNonWs++;
        }

        if (numNonWs == 0)
        {
            throw new ArgumentException(ErrorMessages.EmptyCollection, nameof(base64));
        }

        if (numNonWs % 4 != 0)
        {
            throw new FormatException(ErrorMessages.InvalidBase64Length);
        }

        if (paddingCount > 2)
        {
            throw new FormatException(ErrorMessages.InvalidBase64Padding);
        }

        int totalQuads = numNonWs / 4;
        int byteCount = totalQuads * 3 - paddingCount;
        var result = new PinnedPoolArray<byte>(byteCount);

        // Pass 2: decode.
        int srcPos = 0;
        int dstPos = 0;
        for (int q = 0; q < totalQuads; q++)
        {
            int s0 = NextNonWsSextet(src, srcLen, ref srcPos);
            int s1 = NextNonWsSextet(src, srcLen, ref srcPos);
            int s2 = NextNonWsSextet(src, srcLen, ref srcPos);
            int s3 = NextNonWsSextet(src, srcLen, ref srcPos);
            int v2 = s2 == PaddingSextet ? 0 : s2;
            int v3 = s3 == PaddingSextet ? 0 : s3;

            result.PoolArray[dstPos++] = (byte)((s0 << 2) | (s1 >> 4));

            bool isLastQuad = q == totalQuads - 1;
            if (!isLastQuad || paddingCount < 2)
            {
                result.PoolArray[dstPos++] = (byte)(((s1 & 0xF) << 4) | (v2 >> 2));
            }

            if (!isLastQuad || paddingCount < 1)
            {
                result.PoolArray[dstPos++] = (byte)(((v2 & 0x3) << 6) | v3);
            }
        }

        return result;
    }

    /// <summary>
    /// Advances <paramref name="pos"/> through <paramref name="src"/> until a non-whitespace
    /// character is reached and returns its decoded sextet (0–63), <see cref="PaddingSextet"/>
    /// for <c>'='</c>, or throws on out-of-range. Whitespace alone is skipped silently;
    /// invalid characters are pre-rejected by pass 1 and therefore never seen here.
    /// </summary>
    private static int NextNonWsSextet(char[] src, int srcLen, ref int pos)
    {
        while (pos < srcLen)
        {
            int sextet = DecodeBase64Char(src[pos++]);
            if (sextet != WhitespaceSextet)
            {
                return sextet;
            }
        }

        throw new FormatException(ErrorMessages.InvalidBase64Length);
    }

    /// <summary>
    /// Maps a single Base64 character to its sextet value (0–63), or to one of the
    /// negative sentinel values <see cref="PaddingSextet"/>, <see cref="WhitespaceSextet"/>,
    /// or <see cref="InvalidSextet"/>.
    /// </summary>
    private static int DecodeBase64Char(char c)
    {
        if (c >= 'A' && c <= 'Z')
        {
            return c - 'A';
        }

        if (c >= 'a' && c <= 'z')
        {
            return c - 'a' + 26;
        }

        if (c >= '0' && c <= '9')
        {
            return c - '0' + 52;
        }

        switch (c)
        {
            case '+':
                return 62;
            case '/':
                return 63;
            case '=':
                return PaddingSextet;
            case ' ':
            case '\t':
            case '\r':
            case '\n':
            case '\f':
            case '\v':
                return WhitespaceSextet;
            default:
                return InvalidSextet;
        }
    }

    private const int InvalidSextet = -1;
    private const int PaddingSextet = -2;
    private const int WhitespaceSextet = -3;

    /// <summary>
    /// Gets the <see cref="Secret{TNumber}"/> byte size.
    /// </summary>
    internal int SecretByteSize => this.secretNumber.Length;

    /// <summary>
    /// Gets this <see cref="Secret{TNumber}"/> as an a0 coefficient.
    /// </summary>
    internal Calculator<TNumber> ToCoefficient => Calculator.Create<TNumber>(this.secretNumber.PoolArray, this.secretNumber.Length);

    /// <summary>
    /// Casts the <typeparamref name="TNumber"/> instance to an <see cref="Secret{TNumber}"/> instance
    /// </summary>
    public static implicit operator Secret<TNumber>(TNumber number)
    {
        using var secretCalculator = (Calculator<TNumber>)number;
        using var secretBytes = secretCalculator.ByteRepresentation;
        return new Secret<TNumber>(secretBytes.PoolArray, secretCalculator.ByteCount);
    }

    /// <summary>
    /// Casts the <see cref="Secret{TNumber}"/> instance to an <typeparamref name="TNumber"/> instance
    /// </summary>
    public static implicit operator TNumber(Secret<TNumber> secret)
    {
        if (secret.secretNumber == null || secret.secretNumber.Length == 0)
        {
            return default;
        }

        using var calc = (Calculator<TNumber>)secret;
        return calc.ExtractValue();
    }

    /// <summary>
    /// Casts the <see cref="Secret{TNumber}"/> instance to an <see cref="Calculator{TNumber}"/> instance
    /// </summary>
    public static implicit operator Calculator<TNumber>(Secret<TNumber> secret)
    {
        secret.ThrowIfDisposed();
        using var secretBytes = secret.secretNumber.Subset(0, secret.secretNumber.Length - MarkByteCount);
        return Calculator.Create<TNumber>(secretBytes.PoolArray, secretBytes.Length);
    }

    /// <summary>
    /// Casts the <see cref="Calculator{TNumber}"/> instance to an <see cref="Secret{TNumber}"/> instance.
    /// </summary>
    public static implicit operator Secret<TNumber>(Calculator<TNumber> calculator)
    {
        using var calculatorByteRepresentation = calculator.ByteRepresentation;
        return new Secret<TNumber>(calculatorByteRepresentation.PoolArray, calculatorByteRepresentation.Length);
    }

    /// <summary>
    /// Casts the <see cref="byte"/> array instance to an <see cref="Secret{TNumber}"/> instance.
    /// </summary>
    public static implicit operator Secret<TNumber>(byte[] array)
    {
        return new Secret<TNumber>(array, array.Length);
    }

    /// <summary>
    /// Casts the <see cref="PinnedPoolArray{Byte}"/> instance to an <see cref="Secret{TNumber}"/> instance.
    /// </summary>
    public static implicit operator Secret<TNumber>(PinnedPoolArray<byte> array)
    {
        return new Secret<TNumber>(array.PoolArray, array.Length);
    }

#if NET8_0_OR_GREATER
    /// <summary>
    /// Casts the <see cref="ReadOnlySpan{Byte}"/> to an <see cref="Secret{TNumber}"/> instance.
    /// </summary>
    public static implicit operator Secret<TNumber>(ReadOnlySpan<byte> buffer) => new Secret<TNumber>(buffer, buffer.Length);
#endif

    /// <summary>
    /// Casts the <see cref="Secret{TNumber}"/> instance to an <see cref="PinnedPoolArray{Byte}"/> instance.
    /// </summary>
    public static implicit operator PinnedPoolArray<byte>(Secret<TNumber> secret) => secret.ToByteArray();

#if NET8_0_OR_GREATER
    /// <summary>
    /// Casts the <see cref="Secret{TNumber}"/> instance to a <see cref="ReadOnlySpan{Byte}"/>.
    /// </summary>
    public static implicit operator ReadOnlySpan<byte>(Secret<TNumber> secret) => secret.AsReadOnlySpan();
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
    public int CompareTo(Secret<TNumber> other)
    {
        this.ThrowIfDisposed();
        other.ThrowIfDisposed();
        using var pinnedPoolArrayLeft = this.secretNumber.Subset(0, this.SecretByteSize - MarkByteCount);
        using var pinnedPoolArrayRight = other.secretNumber.Subset(0, other.SecretByteSize - MarkByteCount);
        return pinnedPoolArrayLeft.CompareTo(pinnedPoolArrayRight);
    }

    /// <summary>
    /// Determines whether this instance and an<paramref name="other"/> specified <see cref="Secret{TNumber}"/> instance are equal.
    /// </summary>
    /// <param name="other">The <see cref="Secret{TNumber}"/> instance to compare</param>
    /// <returns><see langword="true"/> if the value of the <paramref name="other"/> parameter is the same as the value of this instance; otherwise <see langword="false"/>.
    /// If <paramref name="other"/> is <see langword="null"/>, the method returns <see langword="false"/>.</returns>
    public bool Equals(Secret<TNumber> other)
    {
        this.ThrowIfDisposed();
        other.ThrowIfDisposed();
        if (this.SecretByteSize < MarkByteCount && other.SecretByteSize < MarkByteCount)
        {
#if (NET8_0_OR_GREATER || NETSTANDARD2_1_OR_GREATER)
            var secretSpan = this.secretNumber.PoolArray.AsSpan(0, this.secretNumber.Length);
            var otherSecretSpan = other.secretNumber.PoolArray.AsSpan(0, other.secretNumber.Length);
            return CryptographicOperations.FixedTimeEquals(secretSpan, otherSecretSpan);
#else
            return this.secretNumber.FixedTimeEquals(other.secretNumber);
#endif
        }

        if (this.SecretByteSize < MarkByteCount || other.SecretByteSize < MarkByteCount)
        {
            return false;
        }

#if (NET8_0_OR_GREATER || NETSTANDARD2_1_OR_GREATER)
        return CryptographicOperations.FixedTimeEquals(
            this.secretNumber.PoolArray.AsSpan(0, this.SecretByteSize - MarkByteCount),
            other.secretNumber.PoolArray.AsSpan(0, other.SecretByteSize - MarkByteCount));
#else
        using var valueLeft = this.secretNumber.Subset(0, this.SecretByteSize - MarkByteCount);
        using var valueRight = other.secretNumber.Subset(0, other.SecretByteSize - MarkByteCount);
        return valueLeft.FixedTimeEquals(valueRight);
#endif
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
    /// <exception cref="ObjectDisposedException">
    /// The underlying buffer has already been disposed.
    /// </exception>
    public override int GetHashCode()
    {
        this.ThrowIfDisposed();
        return this.secretNumber.GetHashCode();
    }

    /// <summary>
    /// Converts the value of <see cref="Secret{TNumber}"/> structure to its equivalent <see cref="string"/> representation
    /// that is Unicode encoded.
    /// </summary>
    /// <returns>
    /// In Debug builds: the UTF-8 decoded <see cref="string"/> representation of the secret.
    /// In Release builds: always returns <c>"*** Secured Value ***"</c> to prevent accidental exposure
    /// in logs, exception messages or other output.
    /// </returns>
    public override string ToString()
    {
#if DEBUG
        this.ThrowIfDisposed();
        if (this.secretNumber is not { Length: > MarkByteCount })
        {
            return string.Empty;
        }

        return Encoding.UTF8.GetString(this.secretNumber.PoolArray, 0, this.secretNumber.Length - MarkByteCount);
#else
        return "*** Secured Value ***";
#endif
    }

    /// <summary>
    /// Releases all resources used by the current instance of the <see cref="Secret{TNumber}"/> struct.
    /// </summary>
    public void Dispose()
    {
        this.secretNumber?.Dispose();
    }

    /// <summary>
    /// Throws <see cref="ObjectDisposedException"/> with the
    /// <see cref="Secret{TNumber}"/> type name if the underlying pinned buffer
    /// has been disposed. The default-value struct (where
    /// <see cref="secretNumber"/> is <see langword="null"/>) is treated as the
    /// uninitialized state and flows through — methods that special-case
    /// "empty / uninitialized" handle it separately. Reads
    /// <see cref="PinnedPoolArray{T}.IsDisposed"/>, which is a non-throwing,
    /// thread-safe accessor.
    /// </summary>
    /// <exception cref="ObjectDisposedException">
    /// The underlying buffer has already been disposed.
    /// </exception>
    private void ThrowIfDisposed()
    {
        if (this.secretNumber is not null && this.secretNumber.IsDisposed)
        {
            throw new ObjectDisposedException(nameof(Secret<TNumber>));
        }
    }

    /// <summary>
    /// Converts the secret to a byte array.
    /// </summary>
    /// <returns>Array of type <see cref="byte"/></returns>
    /// <exception cref="ObjectDisposedException">
    /// Thrown when the underlying buffer has been disposed.
    /// </exception>
    public PinnedPoolArray<byte> ToByteArray()
    {
        this.ThrowIfDisposed();
        return this.secretNumber.Subset(0, this.secretNumber.Length - MarkByteCount);
    }

    /// <summary>
    /// Converts the secret bytes to a <see cref="PinnedPoolArray{Char}"/> containing the
    /// UTF-8-decoded characters of the secret, excluding the termination byte.
    /// </summary>
    /// <returns>
    /// A <see cref="PinnedPoolArray{Char}"/> with the decoded characters. The caller is responsible
    /// for disposing the returned instance. Returns a buffer of length zero if the secret is empty
    /// or uninitialized.
    /// </returns>
    /// <remarks>
    /// This overload is the inverse of <see cref="FromText(PinnedPoolArray{char})"/> and uses the
    /// same UTF-8 default. For any other encoding use the
    /// <see cref="ToCharArray(Encoding)"/> overload.
    /// </remarks>
    /// <exception cref="System.Text.DecoderFallbackException">
    /// Thrown when the secret bytes are not a valid UTF-8 sequence.
    /// </exception>
    /// <exception cref="ObjectDisposedException">
    /// Thrown when the underlying buffer has been disposed.
    /// </exception>
    public PinnedPoolArray<char> ToCharArray() => this.ToCharArray(Encoding.UTF8);

    /// <summary>
    /// Converts the secret bytes to a <see cref="PinnedPoolArray{Char}"/> containing the
    /// characters decoded with the specified <paramref name="encoding"/>, excluding the
    /// termination byte.
    /// </summary>
    /// <param name="encoding">The <see cref="Encoding"/> used to decode the secret bytes.</param>
    /// <returns>
    /// A <see cref="PinnedPoolArray{Char}"/> with the decoded characters. The caller is responsible
    /// for disposing the returned instance. Returns a buffer of length zero if the secret is empty
    /// or uninitialized.
    /// </returns>
    /// <remarks>
    /// Inverse of <see cref="FromText(PinnedPoolArray{char}, Encoding)"/>. The decoded characters
    /// are written directly into a pinned buffer; no intermediate <see cref="string"/> or other
    /// unpinned heap allocation is created.
    /// </remarks>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="encoding"/> is <see langword="null"/>.
    /// </exception>
    /// <exception cref="System.Text.DecoderFallbackException">
    /// Thrown when the secret bytes are not a valid sequence in <paramref name="encoding"/>.
    /// </exception>
    /// <exception cref="ObjectDisposedException">
    /// Thrown when the underlying buffer has been disposed.
    /// </exception>
    public PinnedPoolArray<char> ToCharArray(Encoding encoding)
    {
        this.ThrowIfDisposed();
        if (encoding is null)
        {
            throw new ArgumentNullException(nameof(encoding));
        }

        if (this.secretNumber is not { Length: > MarkByteCount })
        {
            return new PinnedPoolArray<char>(0);
        }

        int byteCount = this.secretNumber.Length - MarkByteCount;
#if (NET8_0_OR_GREATER || NETSTANDARD2_1_OR_GREATER)
        ReadOnlySpan<byte> sourceSpan = this.secretNumber.PoolArray.AsSpan(0, byteCount);
        int charCount = encoding.GetCharCount(sourceSpan);
        var result = new PinnedPoolArray<char>(charCount);
        encoding.GetChars(sourceSpan, result.PoolArray.AsSpan(0, charCount));
        return result;
#else
        int charCount = encoding.GetCharCount(this.secretNumber.PoolArray, 0, byteCount);
        var result = new PinnedPoolArray<char>(charCount);
        encoding.GetChars(this.secretNumber.PoolArray, 0, byteCount, result.PoolArray, 0);
        return result;
#endif
    }

#if NET8_0_OR_GREATER
    /// <summary>
    /// Converts the secret to a <see cref="ReadOnlySpan{Byte}"/>.
    /// </summary>
    /// <returns></returns>
    public ReadOnlySpan<byte> AsReadOnlySpan()
    {
        this.ThrowIfDisposed();
        return this.secretNumber.PoolArray.AsSpan(0, this.secretNumber.Length - MarkByteCount);
    }
#endif

    /// <summary>
    /// Converts the value of <see cref="Secret{TNumber}"/> structure to its equivalent <see cref="string"/> representation
    /// that is encoded with base-64 digits.
    /// </summary>
    /// <returns>
    /// In Debug builds: the base-64 encoded <see cref="string"/> representation of the secret.
    /// In Release builds: always returns <c>"*** Secured Value ***"</c> to prevent accidental exposure
    /// in logs, exception messages or other output.
    /// </returns>
    /// <exception cref="ObjectDisposedException">
    /// Thrown in Debug builds when the underlying buffer has been disposed.
    /// </exception>
    public string ToBase64String()
    {
#if DEBUG
        this.ThrowIfDisposed();
        if (this.secretNumber is not { Length: > MarkByteCount })
        {
            return string.Empty;
        }

        return Convert.ToBase64String(this.secretNumber.PoolArray, 0, this.secretNumber.Length - MarkByteCount);
#else
        return "*** Secured Value ***";
#endif
    }

    /// <summary>
    /// Converts the secret bytes to a <see cref="PinnedPoolArray{Char}"/> containing the base-64 encoded characters.
    /// </summary>
    /// <returns>
    /// A <see cref="PinnedPoolArray{Char}"/> with the base-64 encoded characters of the secret,
    /// excluding the termination byte. The caller is responsible for disposing the returned instance.
    /// Returns a <see cref="PinnedPoolArray{Char}"/> with length zero if the secret is empty or uninitialized.
    /// </returns>
    /// <exception cref="ObjectDisposedException">
    /// Thrown when the underlying buffer has been disposed.
    /// </exception>
    public PinnedPoolArray<char> ToBase64CharArray()
    {
        this.ThrowIfDisposed();
        if (this.secretNumber is not { Length: > MarkByteCount })
        {
            return new PinnedPoolArray<char>(0);
        }

        int byteCount = this.secretNumber.Length - MarkByteCount;
        int charCount = ((byteCount + 2) / 3) * 4;
#if (NET8_0_OR_GREATER || NETSTANDARD2_1_OR_GREATER)
        ReadOnlySpan<byte> sourceSpan = this.secretNumber.PoolArray.AsSpan(0, byteCount);
        var result = new PinnedPoolArray<char>(charCount);
        Convert.TryToBase64Chars(sourceSpan, result.PoolArray.AsSpan(0, charCount), out int charsWritten);
        result.Length = charsWritten;
        return result;
#else
        string base64 = Convert.ToBase64String(this.secretNumber.PoolArray, 0, byteCount);
        var result = new PinnedPoolArray<char>(base64.Length);
        base64.CopyTo(0, result.PoolArray, 0, base64.Length);
        return result;
#endif
    }

    /// <summary>
    /// Create <see cref="Secret{TNumber}"/> from a0 coefficient
    /// </summary>
    /// <typeparam name="TNumberStatic"></typeparam>
    /// <param name="coefficient">a0 coefficient</param>
    /// <returns>A <see cref="Secret{TNumber}"/></returns>
    internal static Secret<TNumberStatic> FromCoefficient<TNumberStatic>(Calculator<TNumberStatic> coefficient)
    {
        using var coefficientByteRepresentation = coefficient.ByteRepresentation;
        return new Secret<TNumberStatic>(coefficientByteRepresentation.PoolArray, coefficient.ByteCount - MarkByteCount);
    }

    /// <summary>
    /// Creates a random secret
    /// </summary>
    /// <param name="prime">mersenne prime number</param>
    /// <remarks>Use this ctor to create a random secret</remarks>
    internal static Secret<TNumberStatic> CreateRandom<TNumberStatic>(Calculator<TNumberStatic> prime)
    {
        using var randomSecretBytes = new PinnedPoolArray<byte>(prime.ByteCount);
        SecureRandom.Fill(randomSecretBytes.PoolArray, 0, randomSecretBytes.Length);

        int i = randomSecretBytes.Length - 1;
        while (i > 0)
        {
            randomSecretBytes.PoolArray[i] = i == 1 ? MinMarkByte : MaxMarkByte;
            using var randomSecretNumber =
                Calculator.Create<TNumberStatic>(randomSecretBytes.PoolArray, randomSecretBytes.Length);
            using var absValue = randomSecretNumber.Abs();
            using var a0 = absValue % prime;
            if (a0 == randomSecretNumber)
            {
                break;
            }

            if (a0.IsZero)
            {
                // Fresh instance per call — must not alias a static singleton, because
                // the caller's `using` would dispose the shared backing buffer and break
                // every subsequent zero-draw return.
                return new Secret<TNumberStatic>(new byte[] { 0x00 }, 1);
            }

            randomSecretBytes.PoolArray[i--] = 0x00;
        }

        using var secretBytes = randomSecretBytes.Subset(0, randomSecretBytes.Length - (randomSecretBytes.Length - i));
        return new Secret<TNumberStatic>(secretBytes.PoolArray, secretBytes.Length);
    }
}
