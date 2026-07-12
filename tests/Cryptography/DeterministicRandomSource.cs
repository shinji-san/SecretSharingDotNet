// ----------------------------------------------------------------------------
// <copyright file="DeterministicRandomSource.cs" company="Private">
// Copyright (c) 2026 All Rights Reserved
// </copyright>
// <author>Sebastian Walther</author>
// <date>07/10/2026 00:00:00 AM</date>
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

using SecretSharingDotNet.Cryptography;
using System;

/// <summary>
/// Deterministic <see cref="IRandomSource"/> test double backed by a seeded
/// <see cref="Random"/>. Given the same seed it reproduces the same byte and integer stream,
/// which makes the split output (random secret + polynomial coefficients) reproducible in tests.
/// </summary>
/// <remarks>
/// This double is <b>not</b> cryptographically secure and <b>not</b> thread-safe — it exists
/// solely to exercise the <see cref="IRandomSource"/> seam under the single-threaded test harness.
/// Its argument guards mirror <see cref="SecureRandom"/> so it is a faithful stand-in.
/// </remarks>
internal sealed class DeterministicRandomSource : IRandomSource
{
    /// <summary>
    /// The seeded pseudo-random generator producing the deterministic stream.
    /// </summary>
    private readonly Random random;

    /// <summary>
    /// Initializes a new instance of the <see cref="DeterministicRandomSource"/> class.
    /// </summary>
    /// <param name="seed">Seed for the underlying <see cref="Random"/>; equal seeds yield equal streams.</param>
    public DeterministicRandomSource(int seed)
    {
        this.random = new Random(seed);
    }

    /// <inheritdoc/>
    public void Fill(byte[] buffer, int offset, int count)
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

        for (int i = 0; i < count; i++)
        {
            buffer[offset + i] = (byte)this.random.Next(0, 256);
        }
    }

    /// <inheritdoc/>
    public int NextInt32(int fromInclusive, int toExclusive)
    {
        if (toExclusive <= fromInclusive)
        {
            throw new ArgumentOutOfRangeException(nameof(toExclusive));
        }

        return this.random.Next(fromInclusive, toExclusive);
    }
}
