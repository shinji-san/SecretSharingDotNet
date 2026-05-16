// ----------------------------------------------------------------------------
// <copyright file="SecureRandom.cs" company="Private">
// Copyright (c) 2026 All Rights Reserved
// </copyright>
// <author>Sebastian Walther</author>
// <date>05/03/2026 00:00:00 AM</date>
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

using System;
using System.Security.Cryptography;

/// <summary>
/// Cryptographically secure random helpers built on top of
/// <see cref="RandomNumberGenerator"/>. Centralises the per-TFM call shape
/// (static helpers on netstandard2.1+ / net8+, instance + dispose on legacy)
/// and offers a bias-free uniform-int draw for small ranges.
/// </summary>
internal static class SecureRandom
{
    /// <summary>
    /// Maximum value of <c>toExclusive - fromInclusive</c> that
    /// <see cref="NextInt32"/>'s legacy fallback can serve. The fallback rejection-samples
    /// over a single random byte, so any range above this would be unrepresentable.
    /// Modern targets use <see cref="RandomNumberGenerator"/>'s
    /// <c>GetInt32(int, int)</c> static helper and have no such restriction.
    /// </summary>
    private const int LegacyFallbackMaxRange = 256;

    /// <summary>
    /// Fills <paramref name="count"/> bytes of <paramref name="buffer"/> starting at
    /// <paramref name="offset"/> with cryptographically secure random data.
    /// </summary>
    /// <param name="buffer">The destination buffer.</param>
    /// <param name="offset">The offset into <paramref name="buffer"/> at which to start writing.</param>
    /// <param name="count">The number of bytes to write.</param>
    /// <exception cref="ArgumentNullException"><paramref name="buffer"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentOutOfRangeException">
    /// <paramref name="offset"/> or <paramref name="count"/> is negative, or the requested range
    /// would extend past the end of <paramref name="buffer"/>.
    /// </exception>
    public static void Fill(byte[] buffer, int offset, int count)
    {
        if (buffer is null)
        {
            throw new ArgumentNullException(nameof(buffer));
        }

        if (offset < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(offset));
        }

        if (count < 0 || offset + count > buffer.Length)
        {
            throw new ArgumentOutOfRangeException(nameof(count));
        }

#if NET8_0_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        RandomNumberGenerator.Fill(buffer.AsSpan(offset, count));
#else
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(buffer, offset, count);
#endif
    }

    /// <summary>
    /// Returns a cryptographically secure uniform random integer in
    /// <c>[<paramref name="fromInclusive"/>, <paramref name="toExclusive"/>)</c>.
    /// </summary>
    /// <param name="fromInclusive">Inclusive lower bound of the result.</param>
    /// <param name="toExclusive">Exclusive upper bound of the result. Must be greater than <paramref name="fromInclusive"/>.</param>
    /// <returns>A uniformly distributed integer in the requested range.</returns>
    /// <exception cref="ArgumentOutOfRangeException">
    /// <paramref name="toExclusive"/> is not greater than <paramref name="fromInclusive"/>; or, on
    /// legacy targets, the range exceeds the legacy fallback's supported maximum.
    /// </exception>
    /// <remarks>
    /// On netstandard2.1+ / net8+ this is a thin wrapper around
    /// <see cref="RandomNumberGenerator"/>'s <c>GetInt32(int, int)</c> static helper.
    /// On legacy targets a single random
    /// byte is rejection-sampled into the desired range; this fallback is sufficient for every
    /// in-tree caller (termination-byte ranges of [1, 32) and [1, 128)).
    /// </remarks>
    public static int NextInt32(int fromInclusive, int toExclusive)
    {
        if (toExclusive <= fromInclusive)
        {
            throw new ArgumentOutOfRangeException(nameof(toExclusive));
        }

#if NET8_0_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        return RandomNumberGenerator.GetInt32(fromInclusive, toExclusive);
#else
        int range = toExclusive - fromInclusive;
        if (range > LegacyFallbackMaxRange)
        {
            throw new ArgumentOutOfRangeException(
                nameof(toExclusive),
                ErrorMessages.RandomRangeExceedsMaximum);
        }

        // Largest multiple of `range` ≤ LegacyFallbackMaxRange. Drawing in [0, rangeBound)
        // and reducing mod `range` yields a uniform sample; drawing in
        // [rangeBound, LegacyFallbackMaxRange) is rejected.
        int rangeBound = (LegacyFallbackMaxRange / range) * range;
        using var rng = RandomNumberGenerator.Create();
        var oneByte = new byte[1];
        while (true)
        {
            rng.GetBytes(oneByte);
            int draw = oneByte[0];
            if (draw < rangeBound)
            {
                return fromInclusive + (draw % range);
            }
        }
#endif
    }
}