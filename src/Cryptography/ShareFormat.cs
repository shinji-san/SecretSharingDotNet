// ----------------------------------------------------------------------------
// <copyright file="ShareFormat.cs" company="Private">
// Copyright (c) 2026 All Rights Reserved
// </copyright>
// <author>Sebastian Walther</author>
// <date>09/16/2026 09:00:00 AM</date>
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

namespace SecretSharingDotNet.Cryptography;

/// <summary>
/// Selects which serialized form a <see cref="Share{TNumber}"/> is written in.
/// </summary>
/// <remarks>
/// <para>
/// Reading needs no selector: the parser accepts either form and takes the security level from a
/// third segment when one is present. Only writing has to choose, because a share that records a
/// level can be written either way.
/// </para>
/// <para>
/// <see cref="Legacy"/> stays the default for every existing signature, so this addition changes
/// no output. <see cref="Extended"/> is opt-in.
/// </para>
/// </remarks>
public enum ShareFormat
{
    /// <summary>
    /// <c>INDEX-VALUE</c> — the form every released version writes and reads. A recorded security
    /// level is dropped, which is exactly the loss that makes a persisted share unreconstructable
    /// without being told its field.
    /// </summary>
    Legacy = 0,

    /// <summary>
    /// <c>INDEX-VALUE-LEVEL</c>, the level as a hexadecimal Mersenne exponent in the third segment.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The level goes last so the leading bytes stay byte-for-byte what they were, and an older
    /// library reading this form fails loudly rather than misreading it: its parser takes the first
    /// separator and treats the remainder as the value, where the second separator is not a hex
    /// digit and the decode is refused.
    /// </para>
    /// <para>
    /// Requires the share to record a level. Asking for this form from a share that does not is an
    /// <see cref="System.InvalidOperationException"/> — a valid request the object's state cannot
    /// serve. Emitting a zero, silently falling back to two segments or guessing would each hand
    /// back a share claiming something it does not know.
    /// </para>
    /// <para>
    /// When <c>withPrefix</c> is requested, the level segment carries the <c>0x</c> prefix like the
    /// coordinates do. One rule for every segment; the parser strips a prefix from each
    /// independently, so either choice would parse, and treating one segment differently would
    /// only be a detail to remember.
    /// </para>
    /// </remarks>
    Extended = 1,
}

/// <summary>
/// Guards the one rule about which <see cref="ShareFormat"/> values exist.
/// </summary>
/// <remarks>
/// A single place on purpose. Every entry point that takes a format has to reject an undefined
/// one, and restating the comparison at each of them is the shape that lets one entry point drift
/// — which is exactly how an empty collection came to accept a cast integer while a populated one
/// refused it.
/// </remarks>
internal static class ShareFormatValidation
{
    /// <summary>
    /// Throws when <paramref name="format"/> is not a defined <see cref="ShareFormat"/> value.
    /// </summary>
    /// <param name="format">The value to check.</param>
    /// <param name="paramName">The parameter name to report.</param>
    /// <exception cref="System.ArgumentOutOfRangeException"><paramref name="format"/> is undefined.</exception>
    internal static void EnsureDefined(ShareFormat format, string paramName)
    {
        if (format != ShareFormat.Legacy && format != ShareFormat.Extended)
        {
            throw new System.ArgumentOutOfRangeException(paramName, format, null);
        }
    }
}
