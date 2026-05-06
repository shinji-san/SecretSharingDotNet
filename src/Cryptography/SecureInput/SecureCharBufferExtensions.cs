// ----------------------------------------------------------------------------
// <copyright file="SecureCharBufferExtensions.cs" company="Private">
// Copyright (c) 2026 All Rights Reserved
// </copyright>
// <author>Sebastian Walther</author>
// <date>05/02/2026</date>
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

namespace SecretSharingDotNet.Cryptography.SecureInput;

using Extension;
using System;
using SecureArray;

/// <summary>
/// Provides extension methods that copy character data into pinned, securely cleared
/// <see cref="PinnedPoolArray{T}"/> buffers. Intended as the entry point for callers that
/// already hold secret characters in less-controlled containers (a <see cref="string"/>,
/// a managed <see cref="char"/> array, or a span backed by either) and want to migrate
/// the material into pinned memory before handing it to the rest of the library.
/// </summary>
public static class SecureCharBufferExtensions
{
    /// <summary>
    /// Copies the characters of the specified <paramref name="source"/> string into a new
    /// pinned <see cref="PinnedPoolArray{T}"/>.
    /// </summary>
    /// <param name="source">The source <see cref="string"/> to copy from.</param>
    /// <returns>
    /// A new <see cref="PinnedPoolArray{T}"/> of <see cref="char"/> containing a copy of
    /// <paramref name="source"/>. The caller is responsible for disposing the returned instance.
    /// </returns>
    /// <remarks>
    /// <b>Security warning:</b> The source <see cref="string"/> remains in unpinned, immutable
    /// managed memory. It cannot be securely cleared, the GC may relocate it (leaving residue),
    /// and the runtime may have interned it. After this method returns, the secret characters
    /// are still recoverable from the original <see cref="string"/> instance until the
    /// containing process exits.
    /// <para>
    /// This helper exists only to bridge code that has <i>already</i> received a
    /// <see cref="string"/> from a less-controlled source. New code should obtain the secret
    /// characters into a pinned buffer from the start — for example via
    /// <see cref="ConsolePasswordReader.ReadPassword(int, char?)"/>.
    /// </para>
    /// </remarks>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="source"/> is <see langword="null"/>.
    /// </exception>
    public static PinnedPoolArray<char> ToPinnedSecure(this string source)
    {
        if (source is null)
        {
            throw new ArgumentNullException(nameof(source));
        }

        var pinned = new PinnedPoolArray<char>(source.Length);
        if (source.Length > 0)
        {
            source.CopyTo(0, pinned.PoolArray, 0, source.Length);
        }

        return pinned;
    }

#if NET8_0_OR_GREATER || NETSTANDARD2_1_OR_GREATER
    /// <summary>
    /// Copies the characters of the specified <paramref name="source"/> span into a new
    /// pinned <see cref="PinnedPoolArray{T}"/>.
    /// </summary>
    /// <param name="source">The source span to copy from.</param>
    /// <returns>
    /// A new <see cref="PinnedPoolArray{T}"/> of <see cref="char"/> containing a copy of
    /// <paramref name="source"/>. The caller is responsible for disposing the returned instance.
    /// </returns>
    /// <remarks>
    /// The pinning guarantee covers only the destination buffer. If <paramref name="source"/>
    /// is backed by an unpinned managed array or a <see cref="string"/>, the original
    /// characters remain recoverable from that backing store after this method returns.
    /// </remarks>
    public static PinnedPoolArray<char> ToPinnedSecure(this ReadOnlySpan<char> source)
    {
        var pinned = new PinnedPoolArray<char>(source.Length);
        if (source.Length > 0)
        {
            source.CopyTo(pinned.PoolArray.AsSpan(0, source.Length));
        }

        return pinned;
    }
#endif

    /// <summary>
    /// Copies the characters of the specified mutable <paramref name="source"/> array into a
    /// new pinned <see cref="PinnedPoolArray{T}"/>, then securely clears <paramref name="source"/>.
    /// </summary>
    /// <param name="source">
    /// The source array to copy from. On return, every element is set to <c>'\0'</c>.
    /// </param>
    /// <returns>
    /// A new <see cref="PinnedPoolArray{T}"/> of <see cref="char"/> containing a copy of
    /// <paramref name="source"/>. The caller is responsible for disposing the returned instance.
    /// </returns>
    /// <remarks>
    /// The source array reference itself remains valid; only its contents are wiped.
    /// The pinning guarantee covers only the destination buffer — the GC may have relocated
    /// <paramref name="source"/> at any point in its lifetime, so prior unpinned residue may
    /// still exist elsewhere in process memory.
    /// </remarks>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="source"/> is <see langword="null"/>.
    /// </exception>
    public static PinnedPoolArray<char> ToPinnedSecureClearing(this char[] source)
    {
        if (source is null)
        {
            throw new ArgumentNullException(nameof(source));
        }

        var pinned = new PinnedPoolArray<char>(source.Length);
        if (source.Length > 0)
        {
            Array.Copy(source, 0, pinned.PoolArray, 0, source.Length);
            Array.Clear(source, 0, source.Length);
        }

        return pinned;
    }

    /// <summary>
    /// Copies each share-line <see cref="string"/> in <paramref name="lines"/> into its own
    /// pinned <see cref="PinnedPoolArray{T}"/> and returns them as a single owned
    /// <see cref="PinnedPoolArrayList{T}"/>. A single <c>using</c> over the returned list
    /// disposes every line buffer at once.
    /// </summary>
    /// <param name="lines">
    /// The share-line strings (typically from a UI form or import file). <see langword="null"/>
    /// or empty entries are pinned as zero-length buffers — the caller is responsible for
    /// upstream validation if blank lines are not desirable.
    /// </param>
    /// <returns>
    /// A <see cref="PinnedPoolArrayList{T}"/> of <see cref="char"/> with one entry per source line.
    /// </returns>
    /// <remarks>
    /// Same string-residue caveats as <see cref="ToPinnedSecure(string)"/> — the source strings
    /// remain in unpinned, immutable managed memory and cannot be securely cleared.
    /// </remarks>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="lines"/> is <see langword="null"/>.
    /// </exception>
    public static PinnedPoolArrayList<char> ToPinnedSecureShareLines(this string[] lines)
    {
        if (lines is null)
        {
            throw new ArgumentNullException(nameof(lines));
        }

        var entries = new PinnedPoolArray<char>[lines.Length];
        try
        {
            for (int i = 0; i < lines.Length; i++)
            {
                entries[i] = lines[i] is null
                    ? new PinnedPoolArray<char>(0)
                    : lines[i].ToPinnedSecure();
            }
        }
        catch
        {
            entries.DisposeAll();
            throw;
        }

        return new PinnedPoolArrayList<char>(entries);
    }
}