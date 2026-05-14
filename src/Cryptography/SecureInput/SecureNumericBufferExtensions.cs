// ----------------------------------------------------------------------------
// <copyright file="SecureNumericBufferExtensions.cs" company="Private">
// Copyright (c) 2026 All Rights Reserved
// </copyright>
// <author>Sebastian Walther</author>
// <date>05/14/2026</date>
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

using System;
using System.Buffers.Binary;
using System.Numerics;
using SecureArray;

/// <summary>
/// Provides extension methods that copy integer data into pinned, securely cleared
/// <see cref="PinnedPoolArray{T}"/> buffers. Intended as the entry point for callers that
/// already hold a secret numeric value in less-controlled containers (a stack-allocated
/// <see cref="int"/>, a <see cref="BigInteger"/>, or a managed <see cref="byte"/> array)
/// and want to migrate the material into pinned memory before handing it to the rest of
/// the library.
/// </summary>
public static class SecureNumericBufferExtensions
{
    /// <summary>
    /// Encodes <paramref name="source"/> as a fixed 4-byte little-endian sequence in a new
    /// pinned <see cref="PinnedPoolArray{T}"/>.
    /// </summary>
    /// <param name="source">The source <see cref="int"/> to encode.</param>
    /// <returns>
    /// A new <see cref="PinnedPoolArray{T}"/> of <see cref="byte"/> with exactly four
    /// little-endian bytes. The caller is responsible for disposing the returned instance.
    /// </returns>
    /// <remarks>
    /// <b>Security warning:</b> A 32-bit secret has at most 2^32 possible values; many
    /// realistic use cases (e.g. a 4–6 digit PIN) carry far less entropy. Pinning the bytes
    /// does not change that — an attacker who can mount an offline dictionary attack against
    /// the resulting share material can still enumerate the secret space cheaply. Treat this
    /// helper as protection against passive memory disclosure of the encoded buffer, not as
    /// a defence against brute-force.
    /// <para>
    /// The encoding is fixed at little-endian to match the byte ordering the rest of the
    /// library uses on the wire (<see cref="BinaryPrimitives.WriteInt32LittleEndian"/> rather
    /// than the platform-endian <see cref="BitConverter.GetBytes(int)"/>), so callers on
    /// big-endian hosts do not silently produce shares with reversed coordinates.
    /// </para>
    /// </remarks>
    public static PinnedPoolArray<byte> ToPinnedSecureBytes(this int source)
    {
        var pinned = new PinnedPoolArray<byte>(sizeof(int));
        BinaryPrimitives.WriteInt32LittleEndian(pinned.PoolArray.AsSpan(0, sizeof(int)), source);
        return pinned;
    }

    /// <summary>
    /// Copies the two's-complement little-endian byte representation of
    /// <paramref name="source"/> into a new pinned <see cref="PinnedPoolArray{T}"/>.
    /// </summary>
    /// <param name="source">The source <see cref="BigInteger"/> to encode.</param>
    /// <returns>
    /// A new <see cref="PinnedPoolArray{T}"/> of <see cref="byte"/> containing the
    /// minimal little-endian two's-complement representation of <paramref name="source"/>.
    /// The caller is responsible for disposing the returned instance.
    /// </returns>
    /// <remarks>
    /// <b>Security warning — magnitude leak:</b> The length of the returned buffer reflects
    /// the magnitude of <paramref name="source"/> (e.g. <c>42</c> encodes to a single byte,
    /// <c>1234567</c> to three). Callers that want to mask the magnitude must pre-pad to a
    /// fixed width before invoking this method (or wrap it themselves) — this overload
    /// intentionally does not, so the contract matches <see cref="BigInteger.ToByteArray()"/>
    /// exactly.
    /// <para>
    /// <b>Security warning — intermediate copy:</b> <see cref="BigInteger.ToByteArray()"/>
    /// allocates an unpinned managed array; the GC may have relocated it before this method
    /// gets a chance to wipe it. The wipe step inside this method is best-effort — heap
    /// snapshots taken before the wipe (or of relocation residue) can still expose the
    /// secret. Prefer callers that hold the value in pinned memory from the start.
    /// </para>
    /// </remarks>
    public static PinnedPoolArray<byte> ToPinnedSecureBytes(this BigInteger source)
    {
        byte[] bytes = source.ToByteArray();
        try
        {
            var pinned = new PinnedPoolArray<byte>(bytes.Length);
            if (bytes.Length > 0)
            {
                Array.Copy(bytes, 0, pinned.PoolArray, 0, bytes.Length);
            }

            return pinned;
        }
        finally
        {
            Array.Clear(bytes, 0, bytes.Length);
        }
    }

    /// <summary>
    /// Copies the bytes of the specified mutable <paramref name="source"/> array into a
    /// new pinned <see cref="PinnedPoolArray{T}"/>, then securely clears <paramref name="source"/>.
    /// </summary>
    /// <param name="source">
    /// The source array to copy from. On return, every element is set to <c>0x00</c>.
    /// </param>
    /// <returns>
    /// A new <see cref="PinnedPoolArray{T}"/> of <see cref="byte"/> containing a copy of
    /// <paramref name="source"/>. The caller is responsible for disposing the returned instance.
    /// </returns>
    /// <remarks>
    /// The source array reference itself remains valid; only its contents are wiped. The
    /// pinning guarantee covers only the destination buffer — the GC may have relocated
    /// <paramref name="source"/> at any point in its lifetime, so prior unpinned residue may
    /// still exist elsewhere in process memory.
    /// </remarks>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="source"/> is <see langword="null"/>.
    /// </exception>
    public static PinnedPoolArray<byte> ToPinnedSecureBytesClearing(this byte[] source)
    {
        if (source is null)
        {
            throw new ArgumentNullException(nameof(source));
        }

        var pinned = new PinnedPoolArray<byte>(source.Length);
        if (source.Length > 0)
        {
            Array.Copy(source, 0, pinned.PoolArray, 0, source.Length);
            Array.Clear(source, 0, source.Length);
        }

        return pinned;
    }
}