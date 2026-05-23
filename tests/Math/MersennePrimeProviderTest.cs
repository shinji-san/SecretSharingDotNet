// ----------------------------------------------------------------------------
// <copyright file="MersennePrimeProviderTest.cs" company="Private">
// Copyright (c) 2019 All Rights Reserved
// </copyright>
// <author>Sebastian Walther</author>
// <date>10/03/2025 02:48:34 PM</date>
// ----------------------------------------------------------------------------

#region License
// ----------------------------------------------------------------------------
// Copyright 2025 Sebastian Walther
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

namespace SecretSharingDotNetTest.Math;

using SecretSharingDotNet.Math;
using System;
using Xunit;

/// <summary>
/// Tests for <see cref="MersennePrimeProvider"/> — the singleton that exposes the
/// 41 known Mersenne-prime exponents (13–43112609) used to pick the prime
/// field for Shamir's scheme.
/// </summary>
public class MersennePrimeProviderTest
{
    /// <summary>
    /// Tests that <see cref="MersennePrimeProvider.Instance"/> is not <see langword="null"/>.
    /// </summary>
    [Fact]
    public void SingletonInstance_Should_NotBeNull()
    {
        // Act & Assert
        Assert.NotNull(MersennePrimeProvider.Instance);
    }
    
    /// <summary>
    /// Tests that repeated reads of <see cref="MersennePrimeProvider.Instance"/> return the
    /// same singleton reference (proper singleton contract).
    /// </summary>
    [Fact]
    public void SingletonInstance_MultipleGet_Should_ReturnSameInstance()
    {
        // Arrange & Act
        var instance1 = MersennePrimeProvider.Instance;
        var instance2 = MersennePrimeProvider.Instance;

        // Assert
        Assert.NotNull(instance1);
        Assert.NotNull(instance2);
        Assert.Same(instance1, instance2);
    }

    /// <summary>
    /// Tests that <see cref="MersennePrimeProvider.IsValidMersennePrimeExponent"/> accepts
    /// known Mersenne exponents (13, 31, 42643801) and rejects non-Mersenne values (14)
    /// or negatives.
    /// </summary>
    /// <param name="exponent">The exponent to test.</param>
    /// <param name="expected">Whether the exponent is a known Mersenne exponent.</param>
    [Theory]
    [InlineData(13, true)]
    [InlineData(31, true)]
    [InlineData(42643801, true)]
    [InlineData(14, false)]
    [InlineData(-10, false)]
    public void IsValidMersennePrimeExponent_Should_ReturnCorrectValues(int exponent, bool expected)
    {
        // Arrange & Act
        var result = MersennePrimeProvider.Instance.IsValidMersennePrimeExponent(exponent);

        // Assert
        Assert.Equal(expected, result);
    }

    /// <summary>
    /// Tests that <see cref="MersennePrimeProvider.MinMersennePrimeExponent"/> returns the
    /// smallest known Mersenne exponent (13 → <c>M13 = 8191</c>).
    /// </summary>
    [Fact]
    public void MinMersennePrimeExponent_Should_ReturnSmallestExponent()
    {
        // Act & Assert
        Assert.Equal(13, MersennePrimeProvider.Instance.MinMersennePrimeExponent);
    }

    /// <summary>
    /// Tests that <see cref="MersennePrimeProvider.MaxMersennePrimeExponent"/> returns the
    /// largest tabulated Mersenne exponent (43,112,609).
    /// </summary>
    [Fact]
    public void MaxMersennePrimeExponent_Should_ReturnLargestExponent()
    {
        // Act & Assert
        Assert.Equal(43112609, MersennePrimeProvider.Instance.MaxMersennePrimeExponent);
    }

    /// <summary>
    /// Tests that <see cref="MersennePrimeProvider.GetNextMersennePrimeExponent"/> rounds the
    /// requested minimum up to the next tabulated Mersenne exponent (with exact-match
    /// returning the value itself).
    /// </summary>
    /// <param name="minValue">The minimum exponent the caller needs to clear.</param>
    /// <param name="expected">The smallest tabulated Mersenne exponent <c>≥ minValue</c>.</param>
    [Theory]
    [InlineData(100, 107)]
    [InlineData(13, 13)] // Exact match
    [InlineData(43000000, 43112609)]
    public void GetNextMersennePrimeExponent_Should_ReturnCorrectNextValue(int minValue, int expected)
    {
        // Arrange & Act
        var result = MersennePrimeProvider.Instance.GetNextMersennePrimeExponent(minValue);

        // Assert
        Assert.Equal(expected, result);
    }

    /// <summary>
    /// Tests that <see cref="MersennePrimeProvider.GetNextMersennePrimeExponent"/> throws
    /// <see cref="ArgumentOutOfRangeException"/> when the requested minimum exceeds the
    /// largest tabulated exponent.
    /// </summary>
    [Fact]
    public void GetNextMersennePrimeExponent_Should_ThrowException_WhenOutOfRange()
    {
        // Act & Assert
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            MersennePrimeProvider.Instance.GetNextMersennePrimeExponent(50000000));
    }

    /// <summary>
    /// Tests that <see cref="MersennePrimeProvider.GetIndexOfMersennePrimeExponent"/> maps
    /// a Mersenne exponent to its zero-based position in the table, or <c>-1</c> if the
    /// exponent is not a known Mersenne exponent.
    /// </summary>
    /// <param name="mersenneExponent">The exponent to look up.</param>
    /// <param name="expected">The expected table index (or <c>-1</c> for not-found).</param>
    [Theory]
    [InlineData(13, 0)]
    [InlineData(31, 3)]
    [InlineData(43112609, 42)]
    [InlineData(14, -1)] // Not found
    public void GetIndexOfMersennePrimeExponent_Should_ReturnCorrectIndex(int mersenneExponent, int expected)
    {
        // Arrange & Act
        var result = MersennePrimeProvider.Instance.GetIndexOfMersennePrimeExponent(mersenneExponent);

        // Assert
        Assert.Equal(expected, result);
    }

    /// <summary>
    /// Tests that <see cref="MersennePrimeProvider.GetMersennePrimeExponentByIndex"/> maps
    /// a zero-based table index to the matching Mersenne exponent.
    /// </summary>
    /// <param name="index">The zero-based index into the exponent table.</param>
    /// <param name="expected">The Mersenne exponent at that index.</param>
    [Theory]
    [InlineData(0, 13)]
    [InlineData(3, 31)]
    [InlineData(41, 42643801)]
    public void GetMersennePrimeExponentByIndex_Should_ReturnCorrectExponent(int index, int expected)
    {
        // Arrange & Act
        var result = MersennePrimeProvider.Instance.GetMersennePrimeExponentByIndex(index);

        // Assert
        Assert.Equal(expected, result);
    }

    /// <summary>
    /// Tests that <see cref="MersennePrimeProvider.GetMersennePrimeExponentByIndex"/> throws
    /// <see cref="IndexOutOfRangeException"/> when the requested index is outside the
    /// 0..40 range of the tabulated exponents.
    /// </summary>
    [Fact]
    public void GetMersennePrimeExponentByIndex_Should_ThrowException_WhenOutOfRange()
    {
        // Act & Assert
        Assert.Throws<IndexOutOfRangeException>(() =>
            MersennePrimeProvider.Instance.GetMersennePrimeExponentByIndex(50));
    }
}