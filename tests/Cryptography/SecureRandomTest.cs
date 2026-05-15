// ----------------------------------------------------------------------------
// <copyright file="SecureRandomTest.cs" company="Private">
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


namespace SecretSharingDotNetTest.Cryptography;

using SecretSharingDotNet.Cryptography;
using System;
using System.Linq;
using Xunit;

/// <summary>
/// Tests for <see cref="SecureRandom"/> — the project's internal wrapper around
/// <see cref="System.Security.Cryptography.RandomNumberGenerator"/>, used wherever the
/// library needs cryptographically strong random material (share-index polynomials,
/// termination bytes, etc.).
/// </summary>
public class SecureRandomTest
{
    /// <summary>
    /// Tests that <see cref="SecureRandom.Fill"/> rejects a <see langword="null"/> buffer
    /// with <see cref="ArgumentNullException"/> before attempting any fill.
    /// </summary>
    [Fact]
    public void Fill_NullBuffer_ThrowsArgumentNullException()
    {
        // Act & Assert
        var ex = Assert.Throws<ArgumentNullException>(() => SecureRandom.Fill(null!, 0, 0));
        Assert.Equal("buffer", ex.ParamName);
    }

    /// <summary>
    /// Tests that <see cref="SecureRandom.Fill"/> rejects a negative offset with
    /// <see cref="ArgumentOutOfRangeException"/>.
    /// </summary>
    [Fact]
    public void Fill_NegativeOffset_ThrowsArgumentOutOfRangeException()
    {
        // Arrange
        var buffer = new byte[8];

        // Act & Assert
        var ex = Assert.Throws<ArgumentOutOfRangeException>(() => SecureRandom.Fill(buffer, -1, 0));
        Assert.Equal("offset", ex.ParamName);
    }

    /// <summary>
    /// Tests that <see cref="SecureRandom.Fill"/> rejects an <c>(offset, count)</c> pair
    /// whose range extends beyond the end of the buffer with
    /// <see cref="ArgumentOutOfRangeException"/> rather than overwriting OOB memory.
    /// </summary>
    [Fact]
    public void Fill_RangePastEndOfBuffer_ThrowsArgumentOutOfRangeException()
    {
        // Arrange
        var buffer = new byte[8];

        // Act & Assert
        var ex = Assert.Throws<ArgumentOutOfRangeException>(() => SecureRandom.Fill(buffer, 4, 5));
        Assert.Equal("count", ex.ParamName);
    }

    /// <summary>
    /// Tests that <see cref="SecureRandom.Fill"/> writes only inside the requested
    /// <c>(offset, count)</c> window — bytes outside that window remain at their
    /// pre-call sentinel value.
    /// </summary>
    [Fact]
    public void Fill_WritesOnlyTheRequestedRange()
    {
        // Arrange — sentinel-fill the surrounding bytes so we can verify Fill leaves them alone.
        var buffer = Enumerable.Repeat((byte)0xCD, 16).ToArray();

        // Act
        SecureRandom.Fill(buffer, 4, 8);

        // Assert — bytes outside [4, 12) untouched.
        Assert.Equal(Enumerable.Repeat((byte)0xCD, 4), buffer.Take(4));
        Assert.Equal(Enumerable.Repeat((byte)0xCD, 4), buffer.Skip(12));
    }

    /// <summary>
    /// Tests that <see cref="SecureRandom.NextInt32"/> rejects an inverted range
    /// (<c>fromInclusive &gt; toExclusive</c>) with <see cref="ArgumentOutOfRangeException"/>.
    /// </summary>
    [Fact]
    public void NextInt32_BoundsInverted_ThrowsArgumentOutOfRangeException()
    {
        // Act & Assert
        var ex = Assert.Throws<ArgumentOutOfRangeException>(() => SecureRandom.NextInt32(10, 5));
        Assert.Equal("toExclusive", ex.ParamName);
    }

    /// <summary>
    /// Tests that <see cref="SecureRandom.NextInt32"/> rejects an empty range
    /// (<c>fromInclusive == toExclusive</c>) with <see cref="ArgumentOutOfRangeException"/>
    /// — the half-open contract excludes the upper bound, so an equal-bounds call has
    /// no valid result.
    /// </summary>
    [Fact]
    public void NextInt32_BoundsEqual_ThrowsArgumentOutOfRangeException()
    {
        // Act & Assert
        var ex = Assert.Throws<ArgumentOutOfRangeException>(() => SecureRandom.NextInt32(7, 7));
        Assert.Equal("toExclusive", ex.ParamName);
    }

    /// <summary>
    /// Tests that <see cref="SecureRandom.NextInt32"/> stays within the requested half-open
    /// range across 1024 sampled draws on the small-mark-byte termination range <c>[1, 32)</c>.
    /// </summary>
    [Fact]
    public void NextInt32_StaysWithinRange_TerminationByteSmall()
    {
        // Act & Assert — [1, 32) is the small-mark-byte termination range. Sample many draws
        // and confirm every result lies in the requested range.
        Assert.All(Enumerable.Range(0, 1024), _ => Assert.InRange(SecureRandom.NextInt32(1, 32), 1, 31));
    }

    /// <summary>
    /// Tests that <see cref="SecureRandom.NextInt32"/> stays within the requested half-open
    /// range across 1024 sampled draws on the large-mark-byte termination range
    /// <c>[1, 128)</c>.
    /// </summary>
    [Fact]
    public void NextInt32_StaysWithinRange_TerminationByteLarge()
    {
        // Act & Assert — [1, 128) is the large-mark-byte termination range.
        Assert.All(Enumerable.Range(0, 1024), _ => Assert.InRange(SecureRandom.NextInt32(1, 128), 1, 127));
    }

    /// <summary>
    /// Tests that <see cref="SecureRandom.NextInt32"/> always returns the lower bound when
    /// the half-open range <c>[lo, lo+1)</c> contains exactly one valid value.
    /// </summary>
    [Fact]
    public void NextInt32_SingletonRange_AlwaysReturnsLowerBound()
    {
        // Act & Assert — [42, 43) has exactly one valid result.
        Assert.All(Enumerable.Range(0, 16), _ => Assert.Equal(42, SecureRandom.NextInt32(42, 43)));
    }
}