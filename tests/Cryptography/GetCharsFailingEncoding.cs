// ----------------------------------------------------------------------------
// <copyright file="GetCharsFailingEncoding.cs" company="Private">
// Copyright (c) 2026 All Rights Reserved
// </copyright>
// <author>Sebastian Walther</author>
// <date>11/19/2026 00:00:00 AM</date>
// ----------------------------------------------------------------------------

#region License

// ----------------------------------------------------------------------------
// Copyright 2026 Sebastian Walther
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

namespace SecretSharingDotNetTest.Cryptography;

using System;
using System.Text;

/// <summary>
/// <see cref="Encoding"/> test double whose <see cref="GetCharCount(byte[], int, int)"/> succeeds
/// and whose <see cref="GetChars(byte[], int, int, char[], int)"/> fills its destination with
/// plaintext stand-ins and then throws.
/// </summary>
/// <remarks>
/// It models an encoding that fails only on the second pass over the bytes. A strict built-in
/// decoder never does that: it already fails in <c>GetCharCount</c>. Only the array-based members
/// are overridden; on .NET 8 and later the span-based members of the base class reach them through
/// temporary arrays, so <see cref="Destination"/> is the caller's buffer only on .NET Framework.
/// </remarks>
internal sealed class GetCharsFailingEncoding : Encoding
{
    /// <summary>
    /// The character that <see cref="GetChars(byte[], int, int, char[], int)"/> writes into its
    /// destination before it throws.
    /// </summary>
    public const char PlaintextStandIn = 'X';

    /// <summary>
    /// Gets a value indicating whether <see cref="GetChars(byte[], int, int, char[], int)"/> was called.
    /// </summary>
    public bool GetCharsCalled { get; private set; }

    /// <summary>
    /// Gets the destination array of the last <see cref="GetChars(byte[], int, int, char[], int)"/>
    /// call, or <see langword="null"/> before the first call.
    /// </summary>
    public char[] Destination { get; private set; }

    /// <summary>
    /// Gets the exception that the last <see cref="GetChars(byte[], int, int, char[], int)"/> call
    /// threw, or <see langword="null"/> before the first call.
    /// </summary>
    public DecoderFallbackException ThrownException { get; private set; }

    /// <summary>
    /// Not supported; the double only decodes.
    /// </summary>
    /// <param name="chars">Ignored.</param>
    /// <param name="index">Ignored.</param>
    /// <param name="count">Ignored.</param>
    /// <returns>Never returns.</returns>
    /// <exception cref="NotSupportedException">Always.</exception>
    public override int GetByteCount(char[] chars, int index, int count)
    {
        throw new NotSupportedException();
    }

    /// <summary>
    /// Not supported; the double only decodes.
    /// </summary>
    /// <param name="chars">Ignored.</param>
    /// <param name="charIndex">Ignored.</param>
    /// <param name="charCount">Ignored.</param>
    /// <param name="bytes">Ignored.</param>
    /// <param name="byteIndex">Ignored.</param>
    /// <returns>Never returns.</returns>
    /// <exception cref="NotSupportedException">Always.</exception>
    public override int GetBytes(char[] chars, int charIndex, int charCount, byte[] bytes, int byteIndex)
    {
        throw new NotSupportedException();
    }

    /// <summary>
    /// Returns one character per byte, so the count always succeeds.
    /// </summary>
    /// <param name="bytes">The bytes to count.</param>
    /// <param name="index">The index of the first byte to count.</param>
    /// <param name="count">The number of bytes to count.</param>
    /// <returns><paramref name="count"/>.</returns>
    public override int GetCharCount(byte[] bytes, int index, int count)
    {
        return count;
    }

    /// <summary>
    /// Records the call, writes <see cref="PlaintextStandIn"/> from <paramref name="charIndex"/> to the
    /// end of <paramref name="chars"/>, and throws.
    /// </summary>
    /// <param name="bytes">Ignored.</param>
    /// <param name="byteIndex">Ignored.</param>
    /// <param name="byteCount">Ignored.</param>
    /// <param name="chars">The destination; recorded in <see cref="Destination"/>.</param>
    /// <param name="charIndex">The index of the first destination character to write.</param>
    /// <returns>Never returns.</returns>
    /// <exception cref="DecoderFallbackException">Always; recorded in <see cref="ThrownException"/>.</exception>
    public override int GetChars(byte[] bytes, int byteIndex, int byteCount, char[] chars, int charIndex)
    {
        this.GetCharsCalled = true;
        this.Destination = chars;
        for (int i = charIndex; i < chars.Length; i++)
        {
            chars[i] = PlaintextStandIn;
        }

        this.ThrownException = new DecoderFallbackException("GetChars fails after GetCharCount succeeded.");
        throw this.ThrownException;
    }

    /// <summary>
    /// Returns one byte per character.
    /// </summary>
    /// <param name="charCount">The number of characters.</param>
    /// <returns><paramref name="charCount"/>.</returns>
    public override int GetMaxByteCount(int charCount)
    {
        return charCount;
    }

    /// <summary>
    /// Returns one character per byte.
    /// </summary>
    /// <param name="byteCount">The number of bytes.</param>
    /// <returns><paramref name="byteCount"/>.</returns>
    public override int GetMaxCharCount(int byteCount)
    {
        return byteCount;
    }
}
