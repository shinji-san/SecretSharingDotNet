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
    /// <para>
    /// If the post-allocation write throws, the pinned buffer is disposed before the
    /// exception is rethrown — no reference to a partially-filled buffer escapes.
    /// </para>
    /// </remarks>
    public static PinnedPoolArray<byte> ToPinnedSecureBytes(this int source)
    {
        var pinned = new PinnedPoolArray<byte>(sizeof(int));
        try
        {
            BinaryPrimitives.WriteInt32LittleEndian(pinned.PoolArray.AsSpan(0, sizeof(int)), source);
        }
        catch
        {
            pinned.Dispose();
            throw;
        }

        return pinned;
    }

    /// <summary>
    /// Encodes <paramref name="source"/> as a fixed 8-byte little-endian sequence in a new
    /// pinned <see cref="PinnedPoolArray{T}"/>.
    /// </summary>
    /// <param name="source">The source <see cref="long"/> to encode.</param>
    /// <returns>
    /// A new <see cref="PinnedPoolArray{T}"/> of <see cref="byte"/> with exactly eight
    /// little-endian bytes. The caller is responsible for disposing the returned instance.
    /// </returns>
    /// <remarks>
    /// <b>Security warning:</b> the 64-bit space is large enough that the brute-force
    /// concern raised for <see cref="ToPinnedSecureBytes(int)"/> does not generally apply,
    /// but entropy is a property of the source — pinning the byte representation does not
    /// lift a low-entropy <c>long</c> (a monotonic timestamp, a sequence number, a small
    /// counter) into a hard-to-guess secret. Treat this helper as protection against
    /// passive memory disclosure of the encoded buffer, not as a defence against an
    /// attacker who can guess the source distribution.
    /// <para>
    /// The encoding is fixed at little-endian to match the byte ordering the rest of the
    /// library uses on the wire (<see cref="BinaryPrimitives.WriteInt64LittleEndian"/> rather
    /// than the platform-endian <see cref="BitConverter.GetBytes(long)"/>), so callers on
    /// big-endian hosts do not silently produce shares with reversed coordinates.
    /// </para>
    /// <para>
    /// If the post-allocation write throws, the pinned buffer is disposed before the
    /// exception is rethrown — no reference to a partially-filled buffer escapes.
    /// </para>
    /// </remarks>
    public static PinnedPoolArray<byte> ToPinnedSecureBytes(this long source)
    {
        var pinned = new PinnedPoolArray<byte>(sizeof(long));
        try
        {
            BinaryPrimitives.WriteInt64LittleEndian(pinned.PoolArray.AsSpan(0, sizeof(long)), source);
        }
        catch
        {
            pinned.Dispose();
            throw;
        }

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
    /// <para>
    /// If the post-allocation write throws, the pinned buffer is disposed before the
    /// exception is rethrown — no reference to a partially-filled buffer escapes. The
    /// intermediate unpinned byte array is wiped on both the success and failure path.
    /// </para>
    /// </remarks>
    public static PinnedPoolArray<byte> ToPinnedSecureBytes(this BigInteger source)
    {
        byte[] bytes = source.ToByteArray();
        try
        {
            var pinned = new PinnedPoolArray<byte>(bytes.Length);
            try
            {
                if (bytes.Length > 0)
                {
                    Array.Copy(bytes, 0, pinned.PoolArray, 0, bytes.Length);
                }
            }
            catch
            {
                pinned.Dispose();
                throw;
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
    /// <para>
    /// If the post-allocation write throws, the pinned buffer is disposed before the
    /// exception is rethrown — no reference to a partially-filled buffer escapes.
    /// </para>
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
        try
        {
            if (source.Length > 0)
            {
                Array.Copy(source, 0, pinned.PoolArray, 0, source.Length);
                Array.Clear(source, 0, source.Length);
            }
        }
        catch
        {
            pinned.Dispose();
            throw;
        }

        return pinned;
    }

    /// <summary>
    /// Decodes <paramref name="source"/> as a fixed 4-byte little-endian <see cref="int"/>.
    /// </summary>
    /// <param name="source">The source pinned buffer. Must have <c>Length == 4</c>.</param>
    /// <returns>The decoded <see cref="int"/> value.</returns>
    /// <remarks>
    /// <b>Security warning — leaks pinned secret into unpinned memory.</b> The returned
    /// <see cref="int"/> lives on the caller's stack (or as a managed field), neither of
    /// which is pinned. Register spilling, stack unwinding, and GC relocation of any
    /// containing reference type can leave residue elsewhere in process memory. This
    /// method undoes the protection that <see cref="ToPinnedSecureBytes(int)"/> set up.
    /// <para>
    /// <b>Safer alternatives:</b>
    /// <list type="bullet">
    ///   <item><description>Keep the value as a pinned buffer and pass <paramref name="source"/>
    ///   directly to the rest of the library — every consumer that accepts a
    ///   <c>PinnedPoolArray&lt;byte&gt;</c> or wraps it in <see cref="Secret{TNumber}"/> reads
    ///   pinned memory end to end.</description></item>
    ///   <item><description>For equality checks against a known reference value, encode the
    ///   reference via <see cref="ToPinnedSecureBytes(int)"/> and compare byte buffers in
    ///   constant time instead of decoding.</description></item>
    /// </list>
    /// </para>
    /// Only call this method at trust boundaries where the value must surface as a primitive
    /// (e.g. a verification API that explicitly contracts to disclose the integer).
    /// </remarks>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="source"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">Thrown if <paramref name="source"/> length is not exactly 4.</exception>
    public static int ToInt32Unprotected(this PinnedPoolArray<byte> source)
    {
        if (source is null)
        {
            throw new ArgumentNullException(nameof(source));
        }

        if (source.Length != sizeof(int))
        {
            throw new ArgumentException(
                string.Format(ErrorMessages.PinnedBufferLengthMismatch, sizeof(int), source.Length),
                nameof(source));
        }

        return BinaryPrimitives.ReadInt32LittleEndian(source.PoolArray.AsSpan(0, sizeof(int)));
    }

    /// <summary>
    /// Decodes <paramref name="source"/> as a fixed 8-byte little-endian <see cref="long"/>.
    /// </summary>
    /// <param name="source">The source pinned buffer. Must have <c>Length == 8</c>.</param>
    /// <returns>The decoded <see cref="long"/> value.</returns>
    /// <remarks>
    /// <b>Security warning — leaks pinned secret into unpinned memory.</b> The returned
    /// <see cref="long"/> lives on the caller's stack (or as a managed field), neither of
    /// which is pinned. Register spilling, stack unwinding, and GC relocation of any
    /// containing reference type can leave residue elsewhere in process memory. This
    /// method undoes the protection that <see cref="ToPinnedSecureBytes(long)"/> set up.
    /// <para>
    /// <b>Safer alternatives:</b>
    /// <list type="bullet">
    ///   <item><description>Keep the value as a pinned buffer and pass <paramref name="source"/>
    ///   directly to the rest of the library — every consumer that accepts a
    ///   <c>PinnedPoolArray&lt;byte&gt;</c> or wraps it in <see cref="Secret{TNumber}"/> reads
    ///   pinned memory end to end.</description></item>
    ///   <item><description>For equality checks against a known reference value, encode the
    ///   reference via <see cref="ToPinnedSecureBytes(long)"/> and compare byte buffers in
    ///   constant time instead of decoding.</description></item>
    /// </list>
    /// </para>
    /// Only call this method at trust boundaries where the value must surface as a primitive
    /// (e.g. a verification API that explicitly contracts to disclose the integer).
    /// </remarks>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="source"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">Thrown if <paramref name="source"/> length is not exactly 8.</exception>
    public static long ToInt64Unprotected(this PinnedPoolArray<byte> source)
    {
        if (source is null)
        {
            throw new ArgumentNullException(nameof(source));
        }

        if (source.Length != sizeof(long))
        {
            throw new ArgumentException(
                string.Format(ErrorMessages.PinnedBufferLengthMismatch, sizeof(long), source.Length),
                nameof(source));
        }

        return BinaryPrimitives.ReadInt64LittleEndian(source.PoolArray.AsSpan(0, sizeof(long)));
    }

    /// <summary>
    /// Decodes <paramref name="source"/> as a little-endian two's-complement
    /// <see cref="BigInteger"/>. Mirrors the byte contract of
    /// <see cref="ToPinnedSecureBytes(BigInteger)"/>.
    /// </summary>
    /// <param name="source">The source pinned buffer holding LE two's-complement bytes.</param>
    /// <returns>The decoded <see cref="BigInteger"/>. Returns <see cref="BigInteger.Zero"/>
    /// when <paramref name="source"/> is empty.</returns>
    /// <remarks>
    /// <b>Security warning — leaks pinned secret into unpinned heap memory.</b> The returned
    /// <see cref="BigInteger"/> is a value type, but its internal <c>uint[]</c> magnitude
    /// storage is allocated on the GC heap, unpinned. The runtime may have relocated it
    /// during marshalling, and there is no <see cref="IDisposable.Dispose"/> path that can
    /// wipe it. The intermediate <see cref="byte"/> array this method allocates is wiped
    /// best-effort before return, but the <see cref="BigInteger"/>'s own internal storage
    /// stays.
    /// <para>
    /// <b>Safer alternative:</b> route the bytes through
    /// <see cref="SecretSharingDotNet.Math.Numerics.SecureBigInteger(byte[], int)"/> instead.
    /// <c>SecureBigInteger</c> consumes the exact same LE two's-complement contract, stores
    /// its limbs in pinned <c>PinnedPoolArray&lt;ulong&gt;</c>, and wipes them on dispose —
    /// no unpinned residue. Only call <c>ToBigIntegerUnprotected</c> when interop with the
    /// BCL <see cref="BigInteger"/> type is unavoidable (e.g. comparing against a reference
    /// computation in a test, or crossing a public API that contracts in
    /// <see cref="BigInteger"/>).
    /// </para>
    /// </remarks>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="source"/> is <see langword="null"/>.</exception>
    public static BigInteger ToBigIntegerUnprotected(this PinnedPoolArray<byte> source)
    {
        if (source is null)
        {
            throw new ArgumentNullException(nameof(source));
        }

        if (source.Length == 0)
        {
            return BigInteger.Zero;
        }

        byte[] managed = new byte[source.Length];
        try
        {
            Array.Copy(source.PoolArray, 0, managed, 0, source.Length);
            return new BigInteger(managed);
        }
        finally
        {
            Array.Clear(managed, 0, managed.Length);
        }
    }
}