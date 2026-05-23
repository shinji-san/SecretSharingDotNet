// ----------------------------------------------------------------------------
// <copyright file="SecureBigIntegerLimbsTest.cs" company="Private">
// Copyright (c) 2026 All Rights Reserved
// </copyright>
// <author>Sebastian Walther</author>
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

namespace SecretSharingDotNetTest.Math.Numerics;

using System;
using SecretSharingDotNet.Cryptography.SecureArray;
using SecretSharingDotNet.Math.Numerics;
using Xunit;

/// <summary>
/// Drift tests for the D2 ulong-limb interop on <see cref="SecureBigInteger"/>.
/// Verifies that <c>ToLimbs()</c> and the <c>(limbs, limbCount, isNegative)</c>
/// constructor round-trip values without loss, that <c>LimbCount</c> reports
/// correct sizes, and that the constructor validates its inputs.
/// </summary>
/// <remarks>
/// These tests guard the byte ↔ ulong representation mapping that subsequent
/// CT-op phases (D3–D9) build on. A regression here silently breaks every
/// constant-time operation that reads or writes via <c>ToLimbs</c>.
/// </remarks>
public sealed class SecureBigIntegerLimbsTest
{
    /// <summary>
    /// Tests that <see cref="SecureBigInteger.ToLimbs"/> followed by the
    /// <c>(limbs, limbCount, isNegative)</c> constructor reproduces the original value
    /// across positive/negative/zero/boundary samples spanning the <see cref="long"/> range.
    /// </summary>
    /// <param name="value">The seed <see cref="long"/> value for the round-trip.</param>
    [Theory]
    [InlineData(0L)]
    [InlineData(1L)]
    [InlineData(7L)]
    [InlineData(255L)]
    [InlineData(256L)]
    [InlineData(65535L)]
    [InlineData(65536L)]
    [InlineData(int.MaxValue)]
    [InlineData(int.MinValue)]
    [InlineData(long.MaxValue)]
    [InlineData(long.MinValue)]
    [InlineData(-1L)]
    [InlineData(-7L)]
    [InlineData(-256L)]
    public void ToLimbs_FromLimbs_RoundTripPreservesValue(long value)
    {
        // Arrange
        using var original = new SecureBigInteger(value);
        bool isNegative = value < 0;

        // Act
        using var limbs = original.ToLimbs();
        using var roundtripped = new SecureBigInteger(limbs, original.LimbCount, isNegative);

        // Assert
        Assert.Equal(original, roundtripped);
    }

    /// <summary>
    /// Tests that <see cref="SecureBigInteger.LimbCount"/> reports a single limb for the
    /// zero value (canonical zero is one zero-limb, not an empty buffer).
    /// </summary>
    [Fact]
    public void LimbCount_OfZero_IsOne()
    {
        // Arrange
        using var zero = new SecureBigInteger(0);

        // Act
        int limbCount = zero.LimbCount;

        // Assert
        Assert.Equal(1, limbCount);
    }

    /// <summary>
    /// Tests that <see cref="SecureBigInteger.LimbCount"/> reports a single limb for a
    /// value (<c>0xFF</c>) that fits inside one byte — far below the 64-bit limb boundary.
    /// </summary>
    [Fact]
    public void LimbCount_OfSingleByteValue_IsOne()
    {
        // Arrange
        using var small = new SecureBigInteger(0xFF);

        // Act
        int limbCount = small.LimbCount;

        // Assert
        Assert.Equal(1, limbCount);
    }

    /// <summary>
    /// Tests that <see cref="SecureBigInteger.LimbCount"/> reports a single limb for
    /// <see cref="long.MaxValue"/> — the largest value that still fits inside one 64-bit limb.
    /// </summary>
    [Fact]
    public void LimbCount_OfLongMaxValue_IsOne()
    {
        // Arrange
        using var v = new SecureBigInteger(long.MaxValue);

        // Act
        int limbCount = v.LimbCount;

        // Assert
        Assert.Equal(1, limbCount);
    }

    /// <summary>
    /// Tests that <see cref="SecureBigInteger.LimbCount"/> jumps to two for the smallest
    /// value that exceeds a single 64-bit limb (<c>2^64</c>) — boundary crossing into the
    /// multi-limb representation.
    /// </summary>
    [Fact]
    public void LimbCount_OfNineByteMagnitude_IsTwo()
    {
        // Arrange — smallest magnitude that crosses into a second limb (2^64).
        var bytes = new byte[9];
        bytes[8] = 0x01;
        using var v = new SecureBigInteger(bytes, isNegative: false);

        // Act
        int limbCount = v.LimbCount;

        // Assert
        Assert.Equal(2, limbCount);
    }

    /// <summary>
    /// Tests that <see cref="SecureBigInteger.ToLimbs"/> places the full <see cref="ulong"/>
    /// value in <c>limbs[0]</c> when the value fits in one limb — covers byte/word/qword
    /// boundary values up to <see cref="ulong.MaxValue"/>.
    /// </summary>
    /// <param name="value">The <see cref="ulong"/> seed value.</param>
    [Theory]
    [InlineData(7UL)]
    [InlineData(0xDEADBEEFUL)]
    [InlineData(0x123456789ABCDEF0UL)]
    [InlineData(ulong.MaxValue)]
    public void ToLimbs_OfUlongValue_LowLimbMatchesValue(ulong value)
    {
        // Arrange
        using var num = new SecureBigInteger(value);

        // Act
        using var limbs = num.ToLimbs();

        // Assert
        Assert.True(limbs.Length >= 1);
        Assert.Equal(value, limbs[0]);
    }

    /// <summary>
    /// Tests the exact boundary <c>2^64</c>: <see cref="SecureBigInteger.ToLimbs"/> must
    /// emit <c>limbs[0] = 0</c> and <c>limbs[1] = 1</c>, confirming the carry into the
    /// upper limb.
    /// </summary>
    [Fact]
    public void ToLimbs_OfTwoToThe64_PlacesHighBitInSecondLimb()
    {
        // Arrange — 2^64 exactly straddles the limb boundary.
        var bytes = new byte[9];
        bytes[8] = 0x01;
        using var v = new SecureBigInteger(bytes, isNegative: false);

        // Act
        using var limbs = v.ToLimbs();

        // Assert
        Assert.Equal(2, limbs.Length);
        Assert.Equal(0UL, limbs[0]);
        Assert.Equal(1UL, limbs[1]);
    }

    /// <summary>
    /// Tests that the <c>(limbs, limbCount, isNegative)</c> constructor rejects a
    /// <see langword="null"/> <c>limbs</c> argument with <see cref="ArgumentNullException"/>.
    /// </summary>
    [Fact]
    public void FromLimbs_NullLimbs_ThrowsArgumentNullException()
    {
        // Arrange — none.

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() =>
        {
            using var _ = new SecureBigInteger(limbs: null!, limbCount: 1, isNegative: false);
        });
    }

    /// <summary>
    /// Tests that the <c>(limbs, limbCount, isNegative)</c> constructor rejects a
    /// <c>limbCount</c> of zero (or negative) with <see cref="ArgumentOutOfRangeException"/> —
    /// canonical zero is represented as one zero-limb, never as zero limbs.
    /// </summary>
    [Fact]
    public void FromLimbs_LimbCountBelowOne_ThrowsArgumentOutOfRangeException()
    {
        // Arrange
        using var limbs = new PinnedPoolArray<ulong>(2);

        // Act & Assert
        Assert.Throws<ArgumentOutOfRangeException>(() =>
        {
            using var _ = new SecureBigInteger(limbs, limbCount: 0, isNegative: false);
        });
    }

    /// <summary>
    /// Tests that the <c>(limbs, limbCount, isNegative)</c> constructor rejects a
    /// <c>limbCount</c> greater than the buffer's length with
    /// <see cref="ArgumentOutOfRangeException"/>.
    /// </summary>
    [Fact]
    public void FromLimbs_LimbCountExceedsLength_ThrowsArgumentOutOfRangeException()
    {
        // Arrange
        using var limbs = new PinnedPoolArray<ulong>(2);

        // Act & Assert
        Assert.Throws<ArgumentOutOfRangeException>(() =>
        {
            using var _ = new SecureBigInteger(limbs, limbCount: 3, isNegative: false);
        });
    }

    /// <summary>
    /// Tests that the <c>(limbs, limbCount, isNegative)</c> constructor canonicalises an
    /// all-zero magnitude tagged as <c>isNegative: true</c> to positive zero (i.e.
    /// <see cref="SecureBigInteger.Sign"/> == 0). Matches the byte-array ctors' zero-clamping.
    /// </summary>
    [Fact]
    public void FromLimbs_AllZeroMagnitudeWithNegativeFlag_NormalisesToZero()
    {
        // Arrange — defensive: zero magnitude tagged as negative must
        // canonicalise to (positive) zero, matching the byte-array ctors that
        // call IsZeroInternal() to clear the negative flag for all-zero data.
        using var limbs = new PinnedPoolArray<ulong>(1);
        limbs[0] = 0UL;
        using var zero = new SecureBigInteger(0);

        // Act
        using var v = new SecureBigInteger(limbs, limbCount: 1, isNegative: true);

        // Assert
        Assert.Equal(0, v.Sign);
        Assert.Equal(zero, v);
    }
}