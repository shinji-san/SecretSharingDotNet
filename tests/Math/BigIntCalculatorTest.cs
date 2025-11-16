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

using System;
using System.Linq;
using System.Numerics;
using SecretSharingDotNet.Math;
using Xunit;

namespace SecretSharingDotNetTest.Math;

public class BigIntCalculatorTest
{
    [Fact]
    public void Constructor_WithBigInteger_ShouldInitializeValue()
    {
        // Arrange
        BigInteger value = 12345;

        // Act
        Calculator<BigInteger> calculator = new BigIntCalculator(value);

        // Assert
        Assert.Equal(value, calculator.Value);
    }

    [Fact]
    public void Constructor_WithByteArray_ShouldInitializeValue()
    {
        // Arrange
        byte[] data = [1, 2, 3, 4];

        // Act
        Calculator<BigInteger> calculator = new BigIntCalculator(data);

        // Assert
        Assert.Equal(new BigInteger(data), calculator.Value);
    }

    [Fact]
    public void Equals_ShouldReturnTrue_ForEqualValues()
    {
        // Arrange
        Calculator<BigInteger> calculator1 = new BigIntCalculator(new BigInteger(12345));
        Calculator<BigInteger> calculator2 = new BigIntCalculator(new BigInteger(12345));

        // Act & Assert
        Assert.True(calculator1.Equals(calculator2));
    }

    [Fact]
    public void Equals_ShouldReturnFalse_ForDifferentValues()
    {
        // Arrange
        Calculator<BigInteger> calculator1 = new BigIntCalculator(new BigInteger(12345));
        Calculator<BigInteger> calculator2 = new BigIntCalculator(new BigInteger(67890));

        // Act & Assert
        Assert.False(calculator1.Equals(calculator2));
    }

    [Fact]
    public void GreaterThan_ShouldReturnCorrectResult()
    {
        // Arrange
        Calculator<BigInteger> calculator = new BigIntCalculator(new BigInteger(10));

        // Act & Assert
        Assert.True(calculator >  new BigIntCalculator(new BigInteger(5)));
        Assert.False(calculator >  new BigIntCalculator(new BigInteger(15)));
    }

    [Fact]
    public void LowerThan_ShouldReturnCorrectResult()
    {
        // Arrange
        Calculator<BigInteger> calculator = new BigIntCalculator(new BigInteger(10));

        // Act & Assert
        Assert.True(calculator <  new BigIntCalculator(new BigInteger(15)));
        Assert.False(calculator <  new BigIntCalculator(new BigInteger(5)));
    }

    [Fact]
    public void EqualOrGreaterThan_ShouldReturnCorrectResult()
    {
        // Arrange
        Calculator<BigInteger> calculator = new BigIntCalculator(new BigInteger(10));

        // Act & Assert
        Assert.True(calculator >= new BigIntCalculator(new BigInteger(10)));
        Assert.True(calculator >= new BigIntCalculator(new BigInteger(5)));
        Assert.False(calculator >=  new BigIntCalculator(new BigInteger(11)));
    }

    [Fact]
    public void EqualOrLowerThan_ShouldReturnCorrectResult()
    {
        // Arrange
        Calculator<BigInteger> calculator = new BigIntCalculator(new BigInteger(10));

        // Act & Assert
        Assert.True(calculator <= new BigIntCalculator(new BigInteger(10)));
        Assert.True(calculator <= new BigIntCalculator(new BigInteger(11)));
        Assert.False(calculator <=  new BigIntCalculator(new BigInteger(5)));
    }

    [Fact]
    public void ToInt32_ShouldConvertCorrectly()
    {
        // Arrange
        var calculator = new BigIntCalculator(new BigInteger(123));

        // Act & Assert
        Assert.Equal(123, calculator.ToInt32());
    }

    [Fact]
    public void ToInt32_ShouldThrowOverflowException_OnLargeValue()
    {
        // Arrange
        var calculator = new BigIntCalculator(BigInteger.Parse("12345678901234567890"));

        // Act & Assert
        Assert.Throws<OverflowException>(() => calculator.ToInt32());
    }

    [Fact]
    public void CompareTo_ShouldReturnCorrectComparison()
    {
        // Arrange
        var calculator1 = new BigIntCalculator(new BigInteger(10));
        var calculator2 = new BigIntCalculator(new BigInteger(15));

        // Act & Assert
        Assert.Equal(-1, calculator1.CompareTo(calculator2));
        Assert.Equal(1, calculator2.CompareTo(calculator1));
        Assert.Equal(0, calculator1.CompareTo(calculator1));
    }

    [Fact]
    public void ArithmeticOperations_ShouldReturnCorrectResults()
    {
        // Arrange
        Calculator<BigInteger> calculator = new BigIntCalculator(new BigInteger(10));

        // Act & Assert
        Assert.Equal(new BigIntCalculator(new BigInteger(15)), calculator + new BigIntCalculator(new BigInteger(5)));
        Assert.Equal(new BigIntCalculator(new BigInteger(5)), calculator - new BigIntCalculator(new BigInteger(5)));
        Assert.Equal(new BigIntCalculator(new BigInteger(50)), calculator * new BigIntCalculator(new BigInteger(5)));
        Assert.Equal(new BigIntCalculator(new BigInteger(2)), calculator / new BigIntCalculator(new BigInteger(5)));
        Assert.Equal(new BigIntCalculator(new BigInteger(1)), calculator / new BigIntCalculator(new BigInteger(10)));
        Assert.Equal(new BigIntCalculator(new BigInteger(0)), calculator % new BigIntCalculator(new BigInteger(5)));
        Assert.Equal(new BigIntCalculator(new BigInteger(10)), calculator % new BigIntCalculator(new BigInteger(11)));
    }

    [Fact]
    public void Increment_ShouldIncreaseValueByOne()
    {
        // Arrange
        Calculator<BigInteger> calculator = new BigIntCalculator(new BigInteger(10));

        // Act
        var incrementedCalculator = ++calculator;

        // Assert
        Assert.Equal(new BigInteger(11), incrementedCalculator.Value);
    }

    [Fact]
    public void Decrement_ShouldDecreaseValueByOne()
    {
        // Arrange
        Calculator<BigInteger> calculator = new BigIntCalculator(new BigInteger(10));

        // Act
        var decrementedCalculator = --calculator;

        // Assert
        Assert.Equal(new BigInteger(9), decrementedCalculator.Value);
    }

    [Fact]
    public void Abs_ShouldReturnAbsoluteValue()
    {
        // Arrange
        Calculator<BigInteger> calculator = new BigIntCalculator(new BigInteger(-10));

        // Act
        var absCalculator = calculator.Abs();

        // Assert
        Assert.Equal(new BigInteger(10), absCalculator.Value);
    }

    [Fact]
    public void Pow_ShouldReturnCorrectPower()
    {
        Calculator<BigInteger> calculator = new BigIntCalculator(new BigInteger(2));
        var result = calculator.Pow(3);

        Assert.Equal(new BigInteger(8), result.Value);
    }

    [Fact]
    public void IsZero_ShouldReturnCorrectResult()
    {
        // Arrange
        Calculator<BigInteger> zeroCalculator = new BigIntCalculator(new BigInteger(0));
        Calculator<BigInteger> nonZeroCalculator = new BigIntCalculator(new BigInteger(5));

        // Act & Assert
        Assert.True(zeroCalculator.IsZero);
        Assert.False(nonZeroCalculator.IsZero);
    }

    [Fact]
    public void IsOne_ShouldReturnCorrectResult()
    {
        // Arrange
        Calculator<BigInteger> oneCalculator = new BigIntCalculator(new BigInteger(1));
        Calculator<BigInteger> nonOneCalculator = new BigIntCalculator(new BigInteger(5));

        // Act & Assert
        Assert.True(oneCalculator.IsOne);
        Assert.False(nonOneCalculator.IsOne);
    }

    [Fact]
    public void IsEven_ShouldReturnCorrectResult()
    {
        // Arrange
        Calculator<BigInteger> evenCalculator = new BigIntCalculator(new BigInteger(6));
        Calculator<BigInteger> oddCalculator = new BigIntCalculator(new BigInteger(5));

        // Act & Assert
        Assert.True(evenCalculator.IsEven);
        Assert.False(oddCalculator.IsEven);
    }

    [Fact]
    public void Sqrt_ShouldReturnCorrectResultForPerfectSquare()
    {
        // Arrange
        Calculator<BigInteger> calculator = new BigIntCalculator(new BigInteger(16));

        // Act
        var result = calculator.Sqrt();

        // Assert
        Assert.Equal(new BigInteger(4), result.Value);
    }

    [Fact]
    public void Sqrt_ShouldThrowExceptionForNegativeValue()
    {
        // Arrange
        Calculator<BigInteger> calculator = new BigIntCalculator(new BigInteger(-16));

        // Act & Assert
        var arithmeticException = Assert.Throws<ArithmeticException>(() => calculator.Sqrt());
        Assert.Equal("NaN", arithmeticException.Message);
    }

    [Fact]
    public void ByteRepresentation_ShouldReturnCorrectBytes()
    {
        var value = new BigInteger(1234567890);
        var calculator = new BigIntCalculator(value);

        Assert.True(calculator.ByteRepresentation.SequenceEqual(value.ToByteArray()));
    }

    [Fact]
    public void ByteCount_ShouldReturnCorrectNumberOfBytes()
    {
        // Arrange
        var value = new BigInteger(1234567890);
        var calculator = new BigIntCalculator(value);

        // Act & Assert
        Assert.Equal(value.ToByteArray().Length, calculator.ByteCount);
    }
}
