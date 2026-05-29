// ----------------------------------------------------------------------------
// <copyright file="BigIntCalculatorTest.cs" company="Private">
// Copyright (c) 2025 All Rights Reserved
// </copyright>
// <author>Sebastian Walther</author>
// <date>11/16/2025 03:20:28 AM</date>
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

namespace SecretSharingDotNetTest.Math.Numerics;

using System;
using System.Linq;
using System.Numerics;
using SecretSharingDotNet;
using SecretSharingDotNet.Math;
using SecretSharingDotNet.Math.Numerics;
using Xunit;

/// <summary>
/// Tests for <see cref="BigIntCalculator"/> — the BCL-<see cref="BigInteger"/>-backed
/// <see cref="Calculator{TNumber}"/> implementation. Covers construction, arithmetic,
/// comparison, increment/decrement, and the byte-representation surface.
/// </summary>
public class BigIntCalculatorTest
{
    /// <summary>
    /// Tests that <see cref="BigIntCalculator(BigInteger)"/> stores the supplied value in
    /// <see cref="Calculator{TNumber}.Value"/>.
    /// </summary>
    [Fact]
    public void Constructor_WithBigInteger_ShouldInitializeValue()
    {
        // Arrange
        BigInteger value = 12345;

        // Act
        using Calculator<BigInteger> calculator = new BigIntCalculator(value);

        // Assert
        Assert.Equal(value, calculator.Value);
    }

    /// <summary>
    /// Lifetime-probe for <see cref="Calculator{BigInteger}.One"/> — mirrors the
    /// <see cref="Numerics.SecureBigInteger"/>-backend probe. If the getter's internal
    /// <c>using var zero = Zero;</c> erroneously took ownership of the returned instance,
    /// accessing <see cref="Calculator{TNumber}.Value"/> on the caller side would throw
    /// <see cref="ObjectDisposedException"/>. <see cref="BigInteger"/> is a value type with
    /// no observable post-dispose state, so the only check available here is reaching the
    /// <see cref="BigInteger.One"/> equality assertion without an in-flight throw.
    /// </summary>
    [Fact]
    public void Calculator_One_ReturnedInstanceIsLiveAfterInternalTemporaryDisposal()
    {
        // Arrange & Act
        using var one = Calculator<BigInteger>.One;

        // Assert
        Assert.Equal(BigInteger.One, one.Value);
    }

    /// <summary>
    /// Lifetime-probe for <see cref="Calculator{BigInteger}.Two"/> — mirrors the
    /// <see cref="Numerics.SecureBigInteger"/>-backend probe. The getter chains through
    /// <see cref="Calculator{BigInteger}.One"/>, which itself disposes a transient
    /// <see cref="Calculator{BigInteger}.Zero"/>. As above, the lifetime check on this
    /// value-type backend reduces to "value access reaches the assertion without throwing".
    /// </summary>
    [Fact]
    public void Calculator_Two_ReturnedInstanceIsLiveAfterInternalTemporaryDisposal()
    {
        // Arrange & Act
        using var two = Calculator<BigInteger>.Two;

        // Assert
        Assert.Equal(new BigInteger(2), two.Value);
    }

    /// <summary>
    /// Tests that the <c>(byte[], int)</c> constructor decodes a little-endian
    /// two's-complement byte array into the matching <see cref="BigInteger"/> value.
    /// </summary>
    [Fact]
    public void Constructor_WithByteArray_ShouldInitializeValue()
    {
        // Arrange
        byte[] data = [1, 2, 3, 4, 0, 0, 0, 0];

        // Act
        using Calculator<BigInteger> calculator = new BigIntCalculator(data, data.Length);

        // Assert
        Assert.Equal(new BigInteger(data), calculator.Value);
    }

    /// <summary>
    /// Tests that <see cref="BigIntCalculator.Equals(Calculator{BigInteger})"/> returns
    /// <see langword="true"/> for two calculators wrapping equal <see cref="BigInteger"/> values.
    /// </summary>
    [Fact]
    public void Equals_ShouldReturnTrue_ForEqualValues()
    {
        // Arrange
        using Calculator<BigInteger> calculator1 = new BigIntCalculator(new BigInteger(12345));
        using Calculator<BigInteger> calculator2 = new BigIntCalculator(new BigInteger(12345));

        // Act & Assert
        Assert.True(calculator1.Equals(calculator2));
    }

    /// <summary>
    /// Tests that <see cref="BigIntCalculator.Equals(Calculator{BigInteger})"/> returns
    /// <see langword="false"/> for two calculators wrapping different
    /// <see cref="BigInteger"/> values.
    /// </summary>
    [Fact]
    public void Equals_ShouldReturnFalse_ForDifferentValues()
    {
        // Arrange
        using Calculator<BigInteger> calculator1 = new BigIntCalculator(new BigInteger(12345));
        using Calculator<BigInteger> calculator2 = new BigIntCalculator(new BigInteger(67890));

        // Act & Assert
        Assert.False(calculator1.Equals(calculator2));
    }

    /// <summary>
    /// Tests the <c>&gt;</c> operator on <see cref="Calculator{BigInteger}"/> — the
    /// inherited overload returns the expected boolean against rhs values both below
    /// and above the lhs.
    /// </summary>
    [Fact]
    public void GreaterThan_ShouldReturnCorrectResult()
    {
        // Arrange
        using Calculator<BigInteger> calculator = new BigIntCalculator(new BigInteger(10));
        using Calculator<BigInteger> rhs5 = new BigIntCalculator(new BigInteger(5));
        using Calculator<BigInteger> rhs15 = new BigIntCalculator(new BigInteger(15));

        // Act & Assert
        Assert.True(calculator > rhs5);
        Assert.False(calculator > rhs15);
    }

    /// <summary>
    /// Tests the <c>&lt;</c> operator on <see cref="Calculator{BigInteger}"/> against rhs
    /// values both above and below the lhs.
    /// </summary>
    [Fact]
    public void LowerThan_ShouldReturnCorrectResult()
    {
        // Arrange
        using Calculator<BigInteger> calculator = new BigIntCalculator(new BigInteger(10));
        using Calculator<BigInteger> rhs5 = new BigIntCalculator(new BigInteger(5));
        using Calculator<BigInteger> rhs15 = new BigIntCalculator(new BigInteger(15));

        // Act & Assert
        Assert.True(calculator < rhs15);
        Assert.False(calculator < rhs5);
    }

    /// <summary>
    /// Tests the <c>&gt;=</c> operator on <see cref="Calculator{BigInteger}"/> across the
    /// equal, strictly-greater, and strictly-lower comparison cases.
    /// </summary>
    [Fact]
    public void EqualOrGreaterThan_ShouldReturnCorrectResult()
    {
        // Arrange
        using Calculator<BigInteger> calculator = new BigIntCalculator(new BigInteger(10));
        using Calculator<BigInteger> rhs5 = new BigIntCalculator(new BigInteger(5));
        using Calculator<BigInteger> rhs10 = new BigIntCalculator(new BigInteger(10));
        using Calculator<BigInteger> rhs11 = new BigIntCalculator(new BigInteger(11));

        // Act & Assert
        Assert.True(calculator >= rhs10);
        Assert.True(calculator >= rhs5);
        Assert.False(calculator >= rhs11);
    }

    /// <summary>
    /// Tests the <c>&lt;=</c> operator on <see cref="Calculator{BigInteger}"/> across the
    /// equal, strictly-lower, and strictly-greater comparison cases.
    /// </summary>
    [Fact]
    public void EqualOrLowerThan_ShouldReturnCorrectResult()
    {
        // Arrange
        using Calculator<BigInteger> calculator = new BigIntCalculator(new BigInteger(10));
        using Calculator<BigInteger> rhs5 = new BigIntCalculator(new BigInteger(5));
        using Calculator<BigInteger> rhs10 = new BigIntCalculator(new BigInteger(10));
        using Calculator<BigInteger> rhs11 = new BigIntCalculator(new BigInteger(11));

        // Act & Assert
        Assert.True(calculator <= rhs10);
        Assert.True(calculator <= rhs11);
        Assert.False(calculator <= rhs5);
    }

    /// <summary>
    /// Tests <see cref="BigIntCalculator.CompareTo(Calculator{BigInteger})"/>: returns
    /// <c>-1</c>, <c>0</c>, or <c>+1</c> depending on whether the lhs is less than,
    /// equal to, or greater than the rhs.
    /// </summary>
    [Fact]
    public void CompareTo_ShouldReturnCorrectComparison()
    {
        // Arrange
        using var calculator1 = new BigIntCalculator(new BigInteger(10));
        using var calculator2 = new BigIntCalculator(new BigInteger(15));

        // Act & Assert
        Assert.Equal(-1, calculator1.CompareTo(calculator2));
        Assert.Equal(1, calculator2.CompareTo(calculator1));
        Assert.Equal(0, calculator1.CompareTo(calculator1));
    }

    /// <summary>
    /// Tests the inherited arithmetic operator surface on <see cref="Calculator{BigInteger}"/>:
    /// <c>+</c>, <c>-</c>, <c>*</c>, <c>/</c>, <c>%</c> — each one applied with operand
    /// pairs that exercise both exact-division and non-zero-remainder paths.
    /// </summary>
    [Fact]
    public void ArithmeticOperations_ShouldReturnCorrectResults()
    {
        // Arrange — operands 5 / 10 / 11 are reused; expected results pre-allocated.
        using Calculator<BigInteger> calculator = new BigIntCalculator(new BigInteger(10));
        using Calculator<BigInteger> rhs5 = new BigIntCalculator(new BigInteger(5));
        using Calculator<BigInteger> rhs10 = new BigIntCalculator(new BigInteger(10));
        using Calculator<BigInteger> rhs11 = new BigIntCalculator(new BigInteger(11));
        using Calculator<BigInteger> expected15 = new BigIntCalculator(new BigInteger(15));
        using Calculator<BigInteger> expected50 = new BigIntCalculator(new BigInteger(50));
        using Calculator<BigInteger> expected2 = new BigIntCalculator(new BigInteger(2));
        using Calculator<BigInteger> expected1 = new BigIntCalculator(new BigInteger(1));
        using Calculator<BigInteger> expected0 = new BigIntCalculator(new BigInteger(0));

        // Act
        using var sum = calculator + rhs5;
        using var difference = calculator - rhs5;
        using var product = calculator * rhs5;
        using var quotientBy5 = calculator / rhs5;
        using var quotientBy10 = calculator / rhs10;
        using var moduloBy5 = calculator % rhs5;
        using var moduloBy11 = calculator % rhs11;

        // Assert
        Assert.Equal(expected15, sum);
        Assert.Equal(rhs5, difference);
        Assert.Equal(expected50, product);
        Assert.Equal(expected2, quotientBy5);
        Assert.Equal(expected1, quotientBy10);
        Assert.Equal(expected0, moduloBy5);
        Assert.Equal(rhs10, moduloBy11);
    }

    /// <summary>
    /// Tests that the <c>++</c> operator on <see cref="Calculator{BigInteger}"/> returns a
    /// new calculator whose value is <c>source + 1</c>.
    /// </summary>
    [Fact]
    public void Increment_ShouldIncreaseValueByOne()
    {
        // Arrange
        Calculator<BigInteger> calculator = new BigIntCalculator(new BigInteger(10));

        // Act
        using var incrementedCalculator = ++calculator;

        // Assert
        Assert.Equal(new BigInteger(11), incrementedCalculator.Value);
    }

    /// <summary>
    /// Tests that the <c>--</c> operator on <see cref="Calculator{BigInteger}"/> returns a
    /// new calculator whose value is <c>source - 1</c>.
    /// </summary>
    [Fact]
    public void Decrement_ShouldDecreaseValueByOne()
    {
        // Arrange
        Calculator<BigInteger> calculator = new BigIntCalculator(new BigInteger(10));

        // Act
        using var decrementedCalculator = --calculator;

        // Assert
        Assert.Equal(new BigInteger(9), decrementedCalculator.Value);
    }

    /// <summary>
    /// Tests that <see cref="BigIntCalculator.Abs"/> returns the absolute value for a
    /// negative source.
    /// </summary>
    [Fact]
    public void Abs_ShouldReturnAbsoluteValue()
    {
        // Arrange
        using Calculator<BigInteger> calculator = new BigIntCalculator(new BigInteger(-10));

        // Act
        using var absCalculator = calculator.Abs();

        // Assert
        Assert.Equal(new BigInteger(10), absCalculator.Value);
    }

    /// <summary>
    /// Tests that <see cref="BigIntCalculator.Pow(int)"/> raises the base value to the
    /// supplied integer exponent (<c>2^3 = 8</c>).
    /// </summary>
    [Fact]
    public void Pow_ShouldReturnCorrectPower()
    {
        // Arrange
        using Calculator<BigInteger> calculator = new BigIntCalculator(new BigInteger(2));

        // Act
        using var result = calculator.Pow(3);

        // Assert
        Assert.Equal(new BigInteger(8), result.Value);
    }

    /// <summary>
    /// Tests that <see cref="BigIntCalculator.IsZero"/> distinguishes zero from non-zero values.
    /// </summary>
    [Fact]
    public void IsZero_ShouldReturnCorrectResult()
    {
        // Arrange
        using Calculator<BigInteger> zeroCalculator = new BigIntCalculator(new BigInteger(0));
        using Calculator<BigInteger> nonZeroCalculator = new BigIntCalculator(new BigInteger(5));

        // Act & Assert
        Assert.True(zeroCalculator.IsZero);
        Assert.False(nonZeroCalculator.IsZero);
    }

    /// <summary>
    /// Tests that <see cref="BigIntCalculator.IsOne"/> distinguishes one from non-one values.
    /// </summary>
    [Fact]
    public void IsOne_ShouldReturnCorrectResult()
    {
        // Arrange
        using Calculator<BigInteger> oneCalculator = new BigIntCalculator(new BigInteger(1));
        using Calculator<BigInteger> nonOneCalculator = new BigIntCalculator(new BigInteger(5));

        // Act & Assert
        Assert.True(oneCalculator.IsOne);
        Assert.False(nonOneCalculator.IsOne);
    }

    /// <summary>
    /// Tests that <see cref="BigIntCalculator.IsEven"/> distinguishes even from odd values.
    /// </summary>
    [Fact]
    public void IsEven_ShouldReturnCorrectResult()
    {
        // Arrange
        using Calculator<BigInteger> evenCalculator = new BigIntCalculator(new BigInteger(6));
        using Calculator<BigInteger> oddCalculator = new BigIntCalculator(new BigInteger(5));

        // Act & Assert
        Assert.True(evenCalculator.IsEven);
        Assert.False(oddCalculator.IsEven);
    }

    /// <summary>
    /// Tests that <see cref="BigIntCalculator.ByteRepresentation"/> returns the same byte
    /// sequence that the BCL's <see cref="BigInteger.ToByteArray()"/> produces — pinned in
    /// a <see cref="PinnedPoolArray{Byte}"/> rather than a managed array.
    /// </summary>
    [Fact]
    public void ByteRepresentation_ShouldReturnCorrectBytes()
    {
        // Arrange
        var value = new BigInteger(1234567890);
        using var calculator = new BigIntCalculator(value);

        // Act
        using var calculatorByteRepresentation = calculator.ByteRepresentation;

        // Assert
        var expectedByteArray = value.ToByteArray();
        Assert.Equal(expectedByteArray.Length, calculatorByteRepresentation.Length);
        Assert.True(expectedByteArray.SequenceEqual(calculatorByteRepresentation.PoolArray.Take(calculatorByteRepresentation.Length)));
    }

    /// <summary>
    /// Tests that <see cref="BigIntCalculator.ByteCount"/> matches the length of
    /// <see cref="BigInteger.ToByteArray()"/> — the lazy cached count must reflect the
    /// pinned byte representation's logical length.
    /// </summary>
    [Fact]
    public void ByteCount_ShouldReturnCorrectNumberOfBytes()
    {
        // Arrange
        var value = new BigInteger(1234567890);
        using var calculator = new BigIntCalculator(value);

        // Act & Assert
        Assert.Equal(value.ToByteArray().Length, calculator.ByteCount);
    }
}
