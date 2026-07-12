// ----------------------------------------------------------------------------
// <copyright file="CryptoRandomSourceTest.cs" company="Private">
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
#if NET8_0_OR_GREATER
using System.Threading.Tasks;
#endif
using Xunit;

/// <summary>
/// Tests for <see cref="CryptoRandomSource"/> — the default <see cref="IRandomSource"/>
/// implementation forwarding to <see cref="SecureRandom"/>. Verifies the shared instance and
/// that the two forwarded operations honour the <see cref="IRandomSource"/> contract.
/// </summary>
public class CryptoRandomSourceTest
{
    /// <summary>
    /// Tests that the shared <see cref="CryptoRandomSource.Instance"/> is available (used as the
    /// default random source throughout the library).
    /// </summary>
    [Fact]
    public void Instance_IsNotNull()
    {
        // Act & Assert
        Assert.NotNull(CryptoRandomSource.Instance);
    }

    /// <summary>
    /// Tests that <see cref="CryptoRandomSource.Fill"/> forwards the argument contract of
    /// <see cref="SecureRandom.Fill"/> — a <see langword="null"/> buffer is rejected with
    /// <see cref="ArgumentNullException"/>.
    /// </summary>
    [Fact]
    public void Fill_NullBuffer_ThrowsArgumentNullException()
    {
        // Act & Assert
        var ex = Assert.Throws<ArgumentNullException>(() => CryptoRandomSource.Instance.Fill(null!, 0, 0));
        Assert.Equal("buffer", ex.ParamName);
    }

    /// <summary>
    /// Tests that <see cref="CryptoRandomSource.Fill"/> writes only within the requested
    /// <c>[offset, offset + count)</c> window and leaves the surrounding bytes untouched.
    /// </summary>
    [Fact]
    public void Fill_WritesOnlyWithinRequestedRange()
    {
        // Arrange — sentinel-filled buffer; fill only the middle 8 bytes.
        var buffer = new byte[16];
        for (int i = 0; i < buffer.Length; i++)
        {
            buffer[i] = 0xAA;
        }

        // Act
        CryptoRandomSource.Instance.Fill(buffer, 4, 8);

        // Assert — bytes outside [4, 12) are still the sentinel.
        for (int i = 0; i < 4; i++)
        {
            Assert.Equal((byte)0xAA, buffer[i]);
        }

        for (int i = 12; i < buffer.Length; i++)
        {
            Assert.Equal((byte)0xAA, buffer[i]);
        }
    }

    /// <summary>
    /// Tests that <see cref="CryptoRandomSource.NextInt32"/> returns values within the
    /// half-open range <c>[fromInclusive, toExclusive)</c> across many draws.
    /// </summary>
    [Fact]
    public void NextInt32_StaysWithinRequestedRange()
    {
        // Act & Assert — 1000 draws must all land in [1, 128).
        for (int i = 0; i < 1000; i++)
        {
            int value = CryptoRandomSource.Instance.NextInt32(1, 128);
            Assert.InRange(value, 1, 127);
        }
    }

#if NET8_0_OR_GREATER
    /// <summary>
    /// Concurrency stress test: many threads drawing from the shared
    /// <see cref="CryptoRandomSource.Instance"/> in parallel must all receive valid, in-range output
    /// without corruption or exceptions. Validates the documented thread-safety of the stateless
    /// singleton (it forwards to the thread-safe <see cref="SecureRandom"/>). Opt-in via the
    /// <c>Category=Stress</c> trait.
    /// </summary>
    [Fact]
    [Trait(StressTraits.CategoryKey, StressTraits.CategoryValue)]
    public void Instance_ConcurrentDraws_StayWithinRangeWithoutError()
    {
        // Arrange
        const int degreeOfParallelism = 16;
        const int drawsPerWorker = 250;

        // Act & Assert
        Parallel.For(0, degreeOfParallelism, _ =>
        {
            var buffer = new byte[32];
            for (int i = 0; i < drawsPerWorker; i++)
            {
                int value = CryptoRandomSource.Instance.NextInt32(1, 128);
                Assert.InRange(value, 1, 127);

                CryptoRandomSource.Instance.Fill(buffer, 0, buffer.Length);
            }
        });
    }
#endif
}
