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