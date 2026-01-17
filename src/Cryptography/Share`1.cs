// ----------------------------------------------------------------------------
// <copyright file="Share`1.cs" company="Private">
// Copyright (c) 2025 All Rights Reserved
// </copyright>
// <author>Sebastian Walther</author>
// <date>12/24/2025 08:50:07 PM</date>
// ----------------------------------------------------------------------------

#region License
// ----------------------------------------------------------------------------
// Copyright 2025 Sebastian Walther
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
#if NET8_0_OR_GREATER
using System.Buffers;
#endif
using System.Collections.Generic;
#if NET8_0_OR_GREATER
using System.Diagnostics.CodeAnalysis;
#endif
using System.Linq;
using System.Runtime.CompilerServices;

/// <summary>
/// Represents an immutable share in a secret sharing scheme.
/// A share consists of an index (X coordinate) and a value (Y coordinate).
/// </summary>
/// <remarks>
/// This type provides a simplified, type-safe wrapper for secret sharing operations.
/// It supports parsing from and formatting to the standard share format "X-Y" where
/// X is the hexadecimal index and Y is the hexadecimal share value.
/// </remarks>
public readonly record struct Share<TNumber> : IComparable<Share<TNumber>>, IFormattable
#if NET8_0_OR_GREATER
    , ISpanParsable<Share<TNumber>>
#endif
{
#if NET8_0_OR_GREATER
    private static readonly SearchValues<char> HexChars =
        SearchValues.Create("0123456789ABCDEFabcdef" + CoordinateSeparator);
#endif

    /// <summary>
    /// The separator between the X and Y coordinate
    /// </summary>
    /// <remarks>Todo: Make private and configure via options in future versions.</remarks>
    private const char CoordinateSeparator = '-';

    /// <summary>
    /// Separator array for <see cref="string.Split(char[])"/> method usage to avoid allocation of a new array.
    /// </summary>
    /// <remarks>Todo: Make private in future versions.</remarks>
    internal static readonly char[] CoordinateSeparatorArray = [CoordinateSeparator];

    /// <summary>
    /// The index (X coordinate) of this share.
    /// </summary>
    /// <remarks>
    /// In Shamir's Secret Sharing, each share is a point on a polynomial.
    /// The index represents the X coordinate of this point.
    /// </remarks>
    public Calculator<TNumber> Index { get; }

    /// <summary>
    /// The value (Y coordinate) of this share.
    /// </summary>
    /// <remarks>
    /// In Shamir's Secret Sharing, this represents the Y coordinate of the point
    /// on the polynomial at the given index.
    /// </remarks>
    public Calculator<TNumber> Value { get; }

    /// <summary>
    /// Gets a value indicating whether the share index is even.
    /// </summary>
    public bool IsIndexEven => this.Index.IsEven;

    /// <summary>
    /// Gets a value indicating whether the share index is odd.
    /// </summary>
    public bool IsIndexOdd => !this.Index.IsEven;

    /// <summary>
    /// Gets a value indicating whether this share is empty (default/uninitialized).
    /// </summary>
    public bool IsEmpty => (this.Index is null || this.Index.IsZero) && (this.Value is null || this.Value.IsZero);

    /// <summary>
    /// Initializes a new instance of the <see cref="Share{TNumber}"/> struct with the specified index and value.
    /// </summary>
    /// <param name="index">The index (X coordinate) of the share. Must be positive.</param>
    /// <param name="value">The value (Y coordinate) of the share.</param>
    /// <exception cref="ArgumentOutOfRangeException">
    /// Thrown when <paramref name="index"/> is less than or equal to one.
    /// </exception>
    public Share(Calculator<TNumber> index, Calculator<TNumber> value)
    {
        if (index < Calculator<TNumber>.One)
        {
            throw new ArgumentOutOfRangeException(
                nameof(index),
                index,
                ErrorMessages.ShareIndexMustBePositive);
        }

        this.Index = index;
        this.Value = value;
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="Share{TNumber}"/> struct by parsing a character span.
    /// </summary>
    /// <param name="shareString">A character span in the format "X-Y" where X and Y are hexadecimal values.</param>
    /// <exception cref="FormatException">
    /// Thrown when <paramref name="shareString"/> is not in the expected format.
    /// </exception>
#if NET8_0_OR_GREATER
    public Share(ReadOnlySpan<char> shareString)
#else
    public Share(string shareString)
#endif
    {
        var (index, value) = ParseCore(shareString);
        this.Index = index;
        this.Value = value;
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="Share{TNumber}"/> struct from raw byte arrays.
    /// </summary>
    /// <param name="indexBytes">The byte array representing the index (X coordinate).</param>
    /// <param name="valueBytes">The byte array representing the value (Y coordinate).</param>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="indexBytes"/> or <paramref name="valueBytes"/> is null.
    /// </exception>
    public Share(byte[] indexBytes, byte[] valueBytes)
    {
        this.Index = Calculator.Create(indexBytes, indexBytes.Length, typeof(TNumber)) as Calculator<TNumber>;
        if (this.Index < Calculator<TNumber>.One)
        {
            throw new ArgumentOutOfRangeException(nameof(indexBytes), ErrorMessages.ShareIndexMustBePositive);
        }

        this.Value = Calculator.Create(valueBytes, valueBytes.Length, typeof(TNumber)) as Calculator<TNumber>;
    }

    /// <summary>
    /// Parses a string into a <see cref="Share{TNumber}"/>.
    /// </summary>
    /// <param name="s">The string to parse.</param>
    /// <returns>A new <see cref="Share{TNumber}"/> instance.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="s"/> is null.</exception>
    /// <exception cref="FormatException">Thrown when <paramref name="s"/> is not in the expected format.</exception>
    public static Share<TNumber> Parse(string s)
    {
        return string.IsNullOrWhiteSpace(s) ? throw new ArgumentNullException(nameof(s)) : new Share<TNumber>(s);
    }

#if NET8_0_OR_GREATER
    /// <summary>
    /// Parses a character span into a <see cref="Share{TNumber}"/>.
    /// </summary>
    /// <param name="s">The character span to parse.</param>
    /// <returns>A new <see cref="Share{TNumber}"/> instance.</returns>
    /// <exception cref="FormatException">Thrown when <paramref name="s"/> is not in the expected format.</exception>
    public static Share<TNumber> Parse(ReadOnlySpan<char> s) => new Share<TNumber>(s);

    /// <inheritdoc/>
    public static Share<TNumber> Parse(ReadOnlySpan<char> s, IFormatProvider provider) => Parse(s);
#endif
    
    /// <inheritdoc/>
    public static Share<TNumber> Parse(string s, IFormatProvider provider) => Parse(s);

    /// <summary>
    /// Tries to parse a string into a <see cref="Share{TNumber}"/>.
    /// </summary>
    /// <param name="s">The string to parse.</param>
    /// <param name="result">
    /// When this method returns, <paramref name="result"/> contains the parsed <see cref="Share{TNumber}"/> if parsing
    /// succeeded, or the default value if parsing failed.
    /// </param>
    /// <returns><see langword="true"/> if parsing succeeded; otherwise, <see langword="false"/>.</returns>
#if NET8_0_OR_GREATER
    public static bool TryParse([NotNullWhen(true)] string s, out Share<TNumber> result)
#else
    public static bool TryParse(string s, out Share<TNumber> result)
#endif
    {
        if (string.IsNullOrWhiteSpace(s))
        {
            result = default;
            return false;
        }

        try
        {
            result = new Share<TNumber>(s);
            return true;
        }
        catch
        {
            result = default;
            return false;
        }
    }

#if NET8_0_OR_GREATER
    /// <summary>
    /// Tries to parse a character span into a <see cref="Share{TNumber}"/>.
    /// </summary>
    /// <param name="s">The character span to parse.</param>
    /// <param name="result">
    /// When this method returns, <paramref name="result"/> contains the parsed <see cref="Share{TNumber}"/> if parsing
    /// succeeded, or the default value if parsing failed.
    /// </param>
    /// <returns><see langword="true"/> if parsing succeeded; otherwise, <see langword="false"/>.</returns>
    public static bool TryParse(ReadOnlySpan<char> s, out Share<TNumber> result)
    {
        try
        {
            result = new Share<TNumber>(s);
            return true;
        }
        catch
        {
            result = default;
            return false;
        }
    }

    /// <inheritdoc/>
    public static bool TryParse(ReadOnlySpan<char> s, IFormatProvider provider, out Share<TNumber> result)
        => TryParse(s, out result);

    /// <inheritdoc/>
    public static bool TryParse([NotNullWhen(true)] string s, IFormatProvider provider, out Share<TNumber> result)
#else
    /// <summary>
    /// Attempts to parse the specified string representation of a share into a <see cref="Share{TNumber}"/> instance.
    /// </summary>
    /// <param name="s">The string representation of the share to parse.</param>
    /// <param name="provider">An object that provides culture-specific formatting information.</param>
    /// <param name="result">
    /// When this method returns, contains the parsed <see cref="Share{TNumber}"/> value if the parse was successful;
    /// otherwise, it is set to the default value of <see cref="Share{TNumber}"/>. This parameter is passed uninitialized.
    /// </param>
    /// <returns><see langword="true"/> if parsing succeeded; otherwise, <see langword="false"/>.</returns>
    public static bool TryParse(string s, IFormatProvider provider, out Share<TNumber> result)
#endif
        => TryParse(s, out result);

    /// <summary>
    /// Compares this share to another share by their indices.
    /// </summary>
    /// <param name="other">The other share to compare to.</param>
    /// <returns>
    /// A negative value if this share's index is less than the other's,
    /// zero if they are equal, or a positive value if this share's index is greater.
    /// </returns>
    public int CompareTo(Share<TNumber> other) => this.Index.CompareTo(other.Index);

    /// <summary>
    /// Returns a string representation of the current <see cref="Share{TNumber}"/> instance.
    /// </summary>
    /// <returns>A string that represents the current share, including its index and value.</returns>
    public override string ToString() => this.ToString(format: null, formatProvider: null);

    /// <summary>
    /// Returns the string representation of this share in the format "X-Y".
    /// </summary>
    /// <returns>A string representation of this share.</returns>
    public string ToString(string format) => this.ToString(format, formatProvider: null);

    /// <summary>
    /// Returns the string representation of this share using the specified format.
    /// </summary>
    /// <param name="format">
    /// The format string. Use "X" (default) or "x" for hexadecimal.
    /// </param>
    /// <param name="formatProvider">The format provider (currently unused).</param>
    /// <returns>A string representation of this share.</returns>
    public string ToString(string format, IFormatProvider formatProvider)
    {
        if (string.IsNullOrEmpty(format))
        {
            format = "X";
        }

        return format switch
        {
            "X" => this.FormatHex(uppercase: true),
            "x" => this.FormatHex(uppercase: false),
            _ => throw new FormatException($"Unknown format string: {format}")
        };
    }

    /// <summary>
    /// Implicitly converts a string to a <see cref="Share{TNumber}"/>.
    /// </summary>
    /// <param name="shareString">The string representation of the share.</param>
    public static implicit operator Share<TNumber>(string shareString) => Parse(shareString);

    /// <summary>
    /// Determines whether one share is less than another based on their indices.
    /// </summary>
    public static bool operator <(Share<TNumber> left, Share<TNumber> right) => left.CompareTo(right) < 0;

    /// <summary>
    /// Determines whether one share is greater than another based on their indices.
    /// </summary>
    public static bool operator >(Share<TNumber> left, Share<TNumber> right) => left.CompareTo(right) > 0;

    /// <summary>
    /// Determines whether one share is less than or equal to another based on their indices.
    /// </summary>
    public static bool operator <=(Share<TNumber> left, Share<TNumber> right) => left.CompareTo(right) <= 0;

    /// <summary>
    /// Determines whether one share is greater than or equal to another based on their indices.
    /// </summary>
    public static bool operator >=(Share<TNumber> left, Share<TNumber> right) => left.CompareTo(right) >= 0;

    /// <summary>
    /// Deconstructs this share into its index and value components.
    /// </summary>
    /// <param name="index">The index (X coordinate) of the share.</param>
    /// <param name="value">The value (Y coordinate) of the share.</param>
    public void Deconstruct(out Calculator<TNumber> index, out Calculator<TNumber> value)
    {
        index = this.Index;
        value = this.Value;
    }

    /// <summary>
    /// Determines whether the provided string consists only of hexadecimal characters and the coordinate separator.
    /// </summary>
    /// <param name="s">The string to check for hexadecimal characters and the coordinate separator.</param>
    /// <returns>
    /// <see langword="true"/> if the string only contains characters representing hexadecimal
    /// digits ('0'-'9', 'A'-'F', 'a'-'f', '-') and the coordinate separator; otherwise, <see langword="false"/>.
    /// </returns>
#if NET8_0_OR_GREATER
    private static bool IsHexWithCoordinateSeparatorOnly(ReadOnlySpan<char> s)
    {
        return s.IndexOfAnyExcept(HexChars) < 0;
    }
#else
    private static bool IsHexWithCoordinateSeparatorOnly(string s)
    {
        return s.Select(c => c is >= '0' and <= '9' or >= 'A' and <= 'F' or >= 'a' and <= 'f' or CoordinateSeparator)
            .All(isHex => isHex);
    }
#endif

#if NET8_0_OR_GREATER
    private static (Calculator<TNumber> Index, Calculator<TNumber> Value) ParseCore(ReadOnlySpan<char> serialized)
#else
    private static (Calculator<TNumber> Index, Calculator<TNumber> Value) ParseCore(string serialized)
#endif
    {
        serialized = serialized.Trim();
        var separatorIndex = serialized.IndexOf(CoordinateSeparator);
        if (separatorIndex < 0 || !IsHexWithCoordinateSeparatorOnly(serialized))
        {
            throw new ArgumentException(string.Format(ErrorMessages.InvalidShareFormat, CoordinateSeparator));
        }

#if NET8_0_OR_GREATER
        if (serialized.IsEmpty)
#else
        if (string.IsNullOrWhiteSpace(serialized))
#endif
        {
            throw new ArgumentNullException(nameof(serialized), ErrorMessages.ShareStringCannotBeEmpty);
        }

#if NET8_0_OR_GREATER
        var indexReadOnlySpan = serialized[..serialized.IndexOf(CoordinateSeparator)];
        var valueReadOnlySpan = serialized[(serialized.IndexOf(CoordinateSeparator) + 1)..];
        if (indexReadOnlySpan.IsEmpty || valueReadOnlySpan.IsEmpty)
        {
            throw new FormatException(ErrorMessages.ShareIndexAndValueMustBeNonEmpty);
        }

        var numberType = typeof(TNumber);
        var indexByteArray = ToByteArray(FormatHexWithLeadingZero(indexReadOnlySpan));
        var index = Calculator.Create(indexByteArray, indexByteArray.Length, numberType) as Calculator<TNumber>;
        var valueByteArray = ToByteArray(FormatHexWithLeadingZero(valueReadOnlySpan));
        var value = Calculator.Create(valueByteArray, valueByteArray.Length, numberType) as Calculator<TNumber>;
#else
        var shareCoordinates = serialized.Split(CoordinateSeparatorArray);
        var numberType = typeof(TNumber);
        var indexByteArray = ToByteArray(FormatHexWithLeadingZero(shareCoordinates[0]));
        var index = Calculator.Create(indexByteArray, indexByteArray.Length, numberType) as Calculator<TNumber>;
        var valueByteArray = ToByteArray(FormatHexWithLeadingZero(shareCoordinates[1]));
        var value = Calculator.Create(valueByteArray, valueByteArray.Length, numberType) as Calculator<TNumber>;
#endif
        if (index < Calculator<TNumber>.One)
        {
            throw new FormatException(ErrorMessages.ShareIndexMustBePositive);
        }

        return (index, value);
    }

    private string FormatHex(bool uppercase)
    {
        using var indexByteRepresentation = this.Index.ByteRepresentation;
        using var valueByteRepresentation = this.Value.ByteRepresentation;
        var indexHex = ToHexString(indexByteRepresentation, uppercase);
        var valueHex = ToHexString(valueByteRepresentation, uppercase);
        indexHex = FormatHexWithLeadingZero(indexHex);
        valueHex = FormatHexWithLeadingZero(valueHex);

        return $"{indexHex}{CoordinateSeparator}{valueHex}";
    }

#if NET8_0_OR_GREATER
    private static ReadOnlySpan<char> FormatHexWithLeadingZero(ReadOnlySpan<char> valueHex)
    {
        if (valueHex.Length % 2 == 0)
        {
            return valueHex;
        }

        var paddedHex = new Span<char>(new char[valueHex.Length + 1]);
        valueHex.CopyTo(paddedHex[1..]);
        paddedHex[0] = '0';
        return paddedHex;
    }
#else
    private static string FormatHexWithLeadingZero(string valueHex)
        {
            if (valueHex.Length % 2 == 0)
            {
                return valueHex;
            }

            return "0" + valueHex;
    }
#endif

#if NET8_0_OR_GREATER
    private static ReadOnlySpan<char> ToHexString(PinnedPoolArray<byte> pinnedArray, bool uppercase)
#else
    private static string ToHexString(PinnedPoolArray<byte> pinnedArray, bool uppercase)
#endif
    {
#if NET8_0_OR_GREATER
        var byteArray = pinnedArray.PoolArray[..pinnedArray.Length];
        var hexString = Convert.ToHexString(byteArray);

        if (uppercase)
        {
            return hexString;
        }

        var chars = hexString.Length <= 512 ? stackalloc char[hexString.Length] : new char[hexString.Length];
        hexString.AsSpan().ToLowerInvariant(chars);
        return new string(chars);
#else
        var hexAlphabet = uppercase ? "0123456789ABCDEF" : "0123456789abcdef";

        var result = new char[pinnedArray.Length * 2];
        var pos = 0;
        for (int index = 0; index < pinnedArray.Length; index++)
        {
            var b = pinnedArray.PoolArray[index];
            result[pos++] = hexAlphabet[b >> 4];
            result[pos++] = hexAlphabet[b & 0xF];
        }

        return new string(result);
#endif
    }

    /// <summary>
    /// Converts a hexadecimal string to a byte array.
    /// </summary>
    /// <param name="hexString">hexadecimal string</param>
    /// <returns>Returns a byte array</returns>
#if NET8_0_OR_GREATER
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static byte[] ToByteArray(ReadOnlySpan<char> hexString) => Convert.FromHexString(hexString);
#else
    private static byte[] ToByteArray(string hexString)
    {
        if (string.IsNullOrEmpty(hexString))
        {
            return [];
        }

        if ((hexString.Length & 1) != 0)
        {
            throw new ArgumentException(ErrorMessages.HexStringMustBeEven, nameof(hexString));
        }

        var bytes = new byte[hexString.Length >> 1];

        for (int i = 0, j = 0; j < hexString.Length; j += 2, i++)
        {
            var high = GetHexValue(hexString[j]);
            var low = GetHexValue(hexString[j + 1]);

            if (high < 0 || low < 0)
            {
                throw new FormatException(string.Format(ErrorMessages.InvalidHexCharacter, high < 0 ? j : j + 1));
            }

            bytes[i] = (byte)(high << 4 | low);
        }

        return bytes;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static int GetHexValue(char c)
    {
        return c switch
        {
            >= '0' and <= '9' => c - '0',
            >= 'A' and <= 'F' => c - 'A' + 10,
            >= 'a' and <= 'f' => c - 'a' + 10,
            _ => -1
        };
    }
#endif
}
