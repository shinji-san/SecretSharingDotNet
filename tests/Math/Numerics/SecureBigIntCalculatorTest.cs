// ----------------------------------------------------------------------------
// <copyright file="SecureBigIntCalculatorTest.cs" company="Private">
// Copyright (c) 2025 All Rights Reserved
// </copyright>
// <author>Sebastian Walther</author>
// <date>12/22/2025 01:05:28 AM</date>
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
using SecretSharingDotNet.Math;
using SecretSharingDotNet.Math.Numerics;
using System.Linq;
using Xunit;

public class SecureBigIntCalculatorTest
{
    [Fact]
    public void Constructor_WithSecureBigInteger_ShouldInitializeValue()
    {
        // Arrange
        using SecureBigInteger value = 12345;

        // Act
        using Calculator<SecureBigInteger> calculator = new SecureBigIntCalculator(value);

        // Assert
        Assert.Equal(value, calculator.Value);
    }

    [Fact]
    public void Constructor_WithByteArray_ShouldInitializeValue()
    {
        // Arrange
        using var expected = new SecureBigInteger(long.MinValue);
        using var data = expected.ToByteArray();

        // Act
        using Calculator<SecureBigInteger> calculator = new SecureBigIntCalculator(data.PoolArray, data.Length);

        // Assert
        Assert.Equal(expected, calculator.Value);
    }

    [Fact]
    public void Equals_ShouldReturnTrue_ForEqualValues()
    {
        // Arrange
        using Calculator<SecureBigInteger> calculator1 = new SecureBigIntCalculator(new SecureBigInteger(12345));
        using Calculator<SecureBigInteger> calculator2 = new SecureBigIntCalculator(new SecureBigInteger(12345));

        // Act & Assert
        Assert.True(calculator1.Equals(calculator2));
    }

    [Fact]
    public void Equals_ShouldReturnFalse_ForDifferentValues()
    {
        // Arrange
        using Calculator<SecureBigInteger> calculator1 = new SecureBigIntCalculator(new SecureBigInteger(12345));
        using Calculator<SecureBigInteger> calculator2 = new SecureBigIntCalculator(new SecureBigInteger(67890));

        // Act & Assert
        Assert.False(calculator1.Equals(calculator2));
    }

    [Fact]
    public void GreaterThan_ShouldReturnCorrectResult()
    {
        // Arrange
        using Calculator<SecureBigInteger> calculator = new SecureBigIntCalculator(new SecureBigInteger(10));

        // Act & Assert
        Assert.True(calculator >  new SecureBigIntCalculator(new SecureBigInteger(5)));
        Assert.False(calculator >  new SecureBigIntCalculator(new SecureBigInteger(15)));
    }

    [Fact]
    public void LowerThan_ShouldReturnCorrectResult()
    {
        // Arrange
        using Calculator<SecureBigInteger> calculator = new SecureBigIntCalculator(new SecureBigInteger(10));

        // Act & Assert
        Assert.True(calculator <  new SecureBigIntCalculator(new SecureBigInteger(15)));
        Assert.False(calculator <  new SecureBigIntCalculator(new SecureBigInteger(5)));
    }

    [Fact]
    public void EqualOrGreaterThan_ShouldReturnCorrectResult()
    {
        // Arrange
        using Calculator<SecureBigInteger> calculator = new SecureBigIntCalculator(new SecureBigInteger(10));

        // Act & Assert
        Assert.True(calculator >= new SecureBigIntCalculator(new SecureBigInteger(10)));
        Assert.True(calculator >= new SecureBigIntCalculator(new SecureBigInteger(5)));
        Assert.False(calculator >=  new SecureBigIntCalculator(new SecureBigInteger(11)));
    }

    [Fact]
    public void EqualOrLowerThan_ShouldReturnCorrectResult()
    {
        // Arrange
        using Calculator<SecureBigInteger> calculator = new SecureBigIntCalculator(new SecureBigInteger(10));

        // Act & Assert
        Assert.True(calculator <= new SecureBigIntCalculator(new SecureBigInteger(10)));
        Assert.True(calculator <= new SecureBigIntCalculator(new SecureBigInteger(11)));
        Assert.False(calculator <=  new SecureBigIntCalculator(new SecureBigInteger(5)));
    }

    [Fact]
    public void CompareTo_ShouldReturnCorrectComparison()
    {
        // Arrange
        using var calculator1 = new SecureBigIntCalculator(new SecureBigInteger(10));
        using var calculator2 = new SecureBigIntCalculator(new SecureBigInteger(15));

        // Act & Assert
        Assert.Equal(-1, calculator1.CompareTo(calculator2));
        Assert.Equal(1, calculator2.CompareTo(calculator1));
        Assert.Equal(0, calculator1.CompareTo(calculator1));
    }

    [Fact]
    public void ArithmeticOperations_ShouldReturnCorrectResults()
    {
        // Arrange
        using Calculator<SecureBigInteger> calculator = new SecureBigIntCalculator(new SecureBigInteger(10));

        // Act & Assert
        Assert.Equal(new SecureBigIntCalculator(new SecureBigInteger(15)), calculator + new SecureBigIntCalculator(new SecureBigInteger(5)));
        Assert.Equal(new SecureBigIntCalculator(new SecureBigInteger(5)), calculator - new SecureBigIntCalculator(new SecureBigInteger(5)));
        Assert.Equal(new SecureBigIntCalculator(new SecureBigInteger(50)), calculator * new SecureBigIntCalculator(new SecureBigInteger(5)));
        Assert.Equal(new SecureBigIntCalculator(new SecureBigInteger(2)), calculator / new SecureBigIntCalculator(new SecureBigInteger(5)));
        Assert.Equal(new SecureBigIntCalculator(new SecureBigInteger(1)), calculator / new SecureBigIntCalculator(new SecureBigInteger(10)));
        Assert.Equal(new SecureBigIntCalculator(new SecureBigInteger(0)), calculator % new SecureBigIntCalculator(new SecureBigInteger(5)));
        Assert.Equal(new SecureBigIntCalculator(new SecureBigInteger(10)), calculator % new SecureBigIntCalculator(new SecureBigInteger(11)));
    }

    [Fact]
    public void Increment_ShouldIncreaseValueByOne()
    {
        // Arrange
        Calculator<SecureBigInteger> calculator = new SecureBigIntCalculator(new SecureBigInteger(10));

        // Act
        using var incrementedCalculator = ++calculator;

        // Assert
        Assert.Equal(new SecureBigInteger(11), incrementedCalculator.Value);
        calculator.Dispose();
    }

    [Fact]
    public void Decrement_ShouldDecreaseValueByOne()
    {
        // Arrange
        Calculator<SecureBigInteger> calculator = new SecureBigIntCalculator(new SecureBigInteger(10));

        // Act
        using var decrementedCalculator = --calculator;

        // Assert
        Assert.Equal(new SecureBigInteger(9), decrementedCalculator.Value);
        calculator.Dispose();
    }

    [Fact]
    public void Abs_ShouldReturnAbsoluteValue()
    {
        // Arrange
        using Calculator<SecureBigInteger> calculator = new SecureBigIntCalculator(new SecureBigInteger(-10));

        // Act
        using var absCalculator = calculator.Abs();

        // Assert
        using var expected = new SecureBigInteger(10);
        Assert.Equal(expected, absCalculator.Value);
    }

    [Fact]
    public void Pow_ShouldReturnCorrectPower()
    {
        using Calculator<SecureBigInteger> calculator = new SecureBigIntCalculator(new SecureBigInteger(2));
        using var result = calculator.Pow(3);

        using var expected = new SecureBigInteger(8);
        Assert.Equal(expected, result.Value);
    }

    [Fact]
    public void IsZero_ShouldReturnCorrectResult()
    {
        // Arrange
        using Calculator<SecureBigInteger> zeroCalculator = new SecureBigIntCalculator(new SecureBigInteger(0));
        using Calculator<SecureBigInteger> nonZeroCalculator = new SecureBigIntCalculator(new SecureBigInteger(5));

        // Act & Assert
        Assert.True(zeroCalculator.IsZero);
        Assert.False(nonZeroCalculator.IsZero);
    }

    [Fact]
    public void IsOne_ShouldReturnCorrectResult()
    {
        // Arrange
        using Calculator<SecureBigInteger> oneCalculator = new SecureBigIntCalculator(new SecureBigInteger(1));
        using Calculator<SecureBigInteger> nonOneCalculator = new SecureBigIntCalculator(new SecureBigInteger(5));

        // Act & Assert
        Assert.True(oneCalculator.IsOne);
        Assert.False(nonOneCalculator.IsOne);
    }

    [Fact]
    public void IsEven_ShouldReturnCorrectResult()
    {
        // Arrange
        using Calculator<SecureBigInteger> evenCalculator = new SecureBigIntCalculator(new SecureBigInteger(6));
        using Calculator<SecureBigInteger> oddCalculator = new SecureBigIntCalculator(new SecureBigInteger(5));

        // Act & Assert
        Assert.True(evenCalculator.IsEven);
        Assert.False(oddCalculator.IsEven);
    }

    [Fact]
    public void Sqrt_ShouldReturnCorrectResultForPerfectSquare()
    {
        // Arrange
        using Calculator<SecureBigInteger> calculator = new SecureBigIntCalculator(new SecureBigInteger(16));

        // Act
        using var result = calculator.Sqrt();

        // Assert
        using var expected = new SecureBigInteger(4);
        Assert.Equal(expected, result.Value);
    }

    [Fact]
    public void Sqrt_ShouldThrowExceptionForNegativeValue()
    {
        // Arrange
        using Calculator<SecureBigInteger> calculator = new SecureBigIntCalculator(new SecureBigInteger(-16));

        // Act & Assert
        var arithmeticException = Assert.Throws<ArithmeticException>(() => calculator.Sqrt());
        Assert.Equal("NaN", arithmeticException.Message);
    }

    [Fact]
    public void ByteRepresentation_ShouldReturnCorrectBytes()
    {
        // Arrange
        using var value = new SecureBigInteger(1234567890);
        using var calculator = new SecureBigIntCalculator(value);
        using var expectedPinnedPoolArray = value.ToByteArray();

        // Act
        using var actualPinnedPoolArray = calculator.ByteRepresentation;

        // Assert
        Assert.Equal(expectedPinnedPoolArray.Length, actualPinnedPoolArray.Length);
        Assert.True(expectedPinnedPoolArray.PoolArray
            .Take(expectedPinnedPoolArray.Length)
            .SequenceEqual(actualPinnedPoolArray.PoolArray.Take(actualPinnedPoolArray.Length)));
    }

    [Fact]
    public void ByteCount_ShouldReturnCorrectNumberOfBytes()
    {
        // Arrange
        using var value = new SecureBigInteger(1234567890);
        using var calculator = new SecureBigIntCalculator(value);

        // Act & Assert
        Assert.Equal(value.ByteCount, calculator.ByteCount);
    }
}
