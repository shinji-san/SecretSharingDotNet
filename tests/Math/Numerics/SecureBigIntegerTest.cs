// ----------------------------------------------------------------------------
// <copyright file="MersennePrimeProviderTest.cs" company="Private">
// Copyright (c) 2019 All Rights Reserved
// </copyright>
// <author>Sebastian Walther</author>
// <date>12/07/2025 11:20:32 PM</date>
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

using SecretSharingDotNet.Math.Numerics;
using System;
using System.Numerics;
using Xunit;

public class SecureBigIntegerTests
{
    [Theory]
    [InlineData(new byte[] {5, 4, 3, 2, 1}, 4328719365L)]
    [InlineData(new byte[] {0}, 0L)]
    [InlineData(new byte[] {251, 251, 252, 253, 254}, -4328719365L)]
    public void Constructor_FromByteArray_CreatesCorrectValue(byte[] byteArray, long expected)
    {
        // Arrange & Act
        using var num = new SecureBigInteger(byteArray);

        // Assert
        Assert.Equal(expected, num);
    }

    [Fact]
    public void Constructor_Default_CreatesZero()
    {
        // Arrange & Act
        using var num = new SecureBigInteger();

        // Assert
        Assert.True(num.IsZero);
        Assert.Equal(0, num.Sign);
        using var pinnedCharArray = num.ToPinnedCharArray();
        var s = new string(pinnedCharArray.PoolArray, 0, pinnedCharArray.Length);
        Assert.Equal("0", s);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(-1)]
    [InlineData(42)]
    [InlineData(-42)]
    [InlineData(int.MaxValue)]
    [InlineData(int.MinValue)]
    public void Constructor_FromInt_CreatesCorrectValue(int value)
    {
        // Arrange & Act
        using var num = new SecureBigInteger(value);

        // Assert
        using var pinnedCharArray = num.ToPinnedCharArray();
        var s = new string(pinnedCharArray.PoolArray, 0, pinnedCharArray.Length);
        Assert.Equal(value.ToString(), s);
    }

    [Theory]
    [InlineData(0L)]
    [InlineData(1L)]
    [InlineData(-1L)]
    [InlineData(123456789L)]
    [InlineData(-123456789L)]
    [InlineData(long.MaxValue)]
    [InlineData(long.MinValue)]
    public void Constructor_FromLong_CreatesCorrectValue(long value)
    {
        // Arrange & Act
        using var num = new SecureBigInteger(value);

        // Assert
        using var pinnedCharArray = num.ToPinnedCharArray();
        var s = new string(pinnedCharArray.PoolArray, 0, pinnedCharArray.Length);
        Assert.Equal(value.ToString(), s);
    }

    [Theory]
    [InlineData(0UL)]
    [InlineData(1UL)]
    [InlineData(123456789UL)]
    [InlineData((ulong)long.MaxValue)]
    // Above long.MaxValue — the value the long ctor cannot represent.
    [InlineData((ulong)long.MaxValue + 1UL)]
    [InlineData(ulong.MaxValue)]
    public void Constructor_FromUlong_CreatesCorrectValue(ulong value)
    {
        // Arrange & Act
        using var num = new SecureBigInteger(value);

        // Assert
        using var pinnedCharArray = num.ToPinnedCharArray();
        var s = new string(pinnedCharArray.PoolArray, 0, pinnedCharArray.Length);
        Assert.Equal(value.ToString(), s);
    }

    [Theory]
    [InlineData(0UL)]
    [InlineData(123456789UL)]
    [InlineData((ulong)long.MaxValue + 1UL)]
    [InlineData(ulong.MaxValue)]
    public void ImplicitConversion_FromUlong_ProducesCorrectInstance(ulong value)
    {
        // Arrange & Act — implicit conversion routed through the ulong ctor.
        using SecureBigInteger num = value;

        // Assert
        using var pinnedCharArray = num.ToPinnedCharArray();
        var s = new string(pinnedCharArray.PoolArray, 0, pinnedCharArray.Length);
        Assert.Equal(value.ToString(), s);
    }

    [Fact]
    public void Constructor_Copy_CreatesIndependentCopy()
    {
        // Arrange
        using var original = new SecureBigInteger(42);

        // Act
        using var copy = new SecureBigInteger(original);

        // Assert
        Assert.Equal(original, copy);
        Assert.NotSame(original, copy);
    }

    [Theory]
    [InlineData("0")]
    [InlineData("1")]
    [InlineData("-1")]
    [InlineData("123456789")]
    [InlineData("-123456789")]
    [InlineData("123456789012345678901234567890")]
    [InlineData("-123456789012345678901234567890")]
    public void Constructor_FromString_CreatesCorrectValue(string value)
    {
        // Arrange & Act
        using var num = new SecureBigInteger(value);
        string expected = value.TrimStart('+');

        // Assert
        using var pinnedCharArray = num.ToPinnedCharArray();
        Assert.Equal(expected, new string(pinnedCharArray.PoolArray, 0, pinnedCharArray.Length));
    }

    [Theory]
    [InlineData("+5", 5)]
    [InlineData("+0", 0)]
    [InlineData("-0", 0)]
    [InlineData("00000", 0)]
    [InlineData("  5  ", 5)]
    [InlineData("\t-42\t", -42)]
    public void Constructor_FromString_ValidSignAndWhitespace_Parses(string value, int expected)
    {
        // Arrange & Act
        using var num = new SecureBigInteger(value);

        // Assert
        Assert.Equal(expected, (int)num);
    }

    [Theory]
    [InlineData("")]
    [InlineData(" ")]
    [InlineData("   ")]
    [InlineData("\t")]
    [InlineData("\t\n ")]
    public void Constructor_FromString_EmptyOrWhitespace_ThrowsArgumentException(string value)
    {
        Assert.Throws<ArgumentException>(() =>
        {
            using var _ = new SecureBigInteger(value);
        });
    }

    [Theory]
    [InlineData("-")]
    [InlineData("+")]
    [InlineData(" - ")]
    [InlineData(" + ")]
    [InlineData("\t-\t")]
    public void Constructor_FromString_OnlySign_ThrowsFormatException(string value)
    {
        Assert.Throws<FormatException>(() =>
        {
            using var _ = new SecureBigInteger(value);
        });
    }

    [Fact]
    public void IsZero_WithZero_ReturnsTrue()
    {
        // Arrange & Act
        using var num1 = new SecureBigInteger(0);
        using var num2 = new SecureBigInteger(0L);

        // Assert
        Assert.True(num1.IsZero);
        Assert.True(num2.IsZero);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(-1)]
    [InlineData(100)]
    public void IsZero_WithNonZero_ReturnsFalse(int value)
    {
        // Arrange & Act
        using var num = new SecureBigInteger(value);

        // Assert
        Assert.False(num.IsZero);
    }

    [Fact]
    public void IsOne_WithOne_ReturnsTrue()
    {
        // Arrange & Act
        using var num1 = new SecureBigInteger(1);
        using var num2 = new SecureBigInteger(1L);

        // Assert
        Assert.True(num1.IsOne);
        Assert.True(num2.IsOne);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    [InlineData(2)]
    [InlineData(-100)]
    [InlineData(100)]
    [InlineData(1000)]
    [InlineData(-1000)]
    public void IsOne_WithNonOne_ReturnsFalse(int value)
    {
        // Arrange & Act
        using var num = new SecureBigInteger(value);

        // Assert
        Assert.False(num.IsOne);
    }

    [Theory]
    [InlineData(0, true)]
    [InlineData(1, false)]
    [InlineData(2, true)]
    [InlineData(3, false)]
    [InlineData(-2, true)]
    [InlineData(-3, false)]
    [InlineData(int.MaxValue, false)]
    [InlineData(int.MinValue, true)]
    [InlineData(long.MaxValue, false)]
    [InlineData(long.MinValue, true)]
    public void IsEven_ReturnsCorrectResult(long value, bool expectedEven)
    {
        // Arrange
        using var num = new SecureBigInteger(value);

        // Act & Assert
        Assert.Equal(expectedEven, num.IsEven);
    }

    [Fact]
    public void IsEven_AfterDispose_ThrowsObjectDisposedException()
    {
        // Arrange
        var num = new SecureBigInteger(42);
        num.Dispose();

        // Act & Assert
        Assert.Throws<ObjectDisposedException>(() => num.IsEven);
    }

    [Theory]
    [InlineData(0, 0)]
    [InlineData(1, 1)]
    [InlineData(-1, -1)]
    [InlineData(42, 1)]
    [InlineData(-42, -1)]
    public void Sign_ReturnsCorrectSign(int value, int expectedSign)
    {
        // Arrange & Act
        using var num = new SecureBigInteger(value);

        // Assert
        Assert.Equal(expectedSign, num.Sign);
    }

    [Theory]
    [InlineData(0, 0, 0)]
    [InlineData(1, 1, 2)]
    [InlineData(5, 3, 8)]
    [InlineData(-5, -3, -8)]
    [InlineData(5, -3, 2)]
    [InlineData(-5, 3, -2)]
    [InlineData(100, 200, 300)]
    public void Add_ReturnsCorrectSum(int a, int b, int expected)
    {
        // Arrange
        using var num1 = new SecureBigInteger(a);
        using var num2 = new SecureBigInteger(b);

        // Act
        using var result = SecureBigInteger.Add(num1, num2);

        // Assert
        using var pinnedCharArray = result.ToPinnedCharArray();
        var s = new string(pinnedCharArray.PoolArray, 0, pinnedCharArray.Length);
        Assert.Equal(expected.ToString(), s);
    }

    [Fact]
    public void AddOperator_ReturnsCorrectSum()
    {
        // Arrange
        using var num1 = new SecureBigInteger(3333);
        using var num2 = new SecureBigInteger(2222);

        // Act
        using var result = num1 + num2;

        // Assert
        using var pinnedCharArray = result.ToPinnedCharArray();
        var s = new string(pinnedCharArray.PoolArray, 0, pinnedCharArray.Length);
        Assert.Equal("5555", s);
    }

    [Theory]
    [InlineData(0, 0, 0)]
    [InlineData(10000, 1, 9999)]
    [InlineData(5, 3, 2)]
    [InlineData(3, 5, -2)]
    [InlineData(-5, -3, -2)]
    [InlineData(-3, -5, 2)]
    [InlineData(5, -3, 8)]
    [InlineData(-5, 3, -8)]
    [InlineData(0, 5, -5)]
    [InlineData(5, 0, 5)]
    [InlineData(0, -5, 5)]
    [InlineData(int.MaxValue, 1, int.MaxValue - 1)]
    [InlineData(1, int.MaxValue, 1 - int.MaxValue)]
    public void Subtract_ReturnsCorrectDifference(int a, int b, int expected)
    {
        // Arrange
        using var num1 = new SecureBigInteger(a);
        using var num2 = new SecureBigInteger(b);

        // Act
        using var result = SecureBigInteger.Subtract(num1, num2);

        // Assert
        using var pinnedCharArray = result.ToPinnedCharArray();
        var s = new string(pinnedCharArray.PoolArray, 0, pinnedCharArray.Length);
        Assert.Equal(expected.ToString(), s);
    }

    [Fact]
    public void SubtractOperator_ReturnsCorrectDifference()
    {
        // Arrange
        using var num1 = new SecureBigInteger(30);
        using var num2 = new SecureBigInteger(10);

        // Act
        using var result = num1 - num2;

        // Assert
        using var pinnedCharArray = result.ToPinnedCharArray();
        var s = new string(pinnedCharArray.PoolArray, 0, pinnedCharArray.Length);
        Assert.Equal("20", s);
    }

    [Theory]
    [InlineData(0, 5, 0)]
    [InlineData(5, 0, 0)]
    [InlineData(1, 5, 5)]
    [InlineData(5, 1, 5)]
    [InlineData(3, 4, 12)]
    [InlineData(-3, 4, -12)]
    [InlineData(3, -4, -12)]
    [InlineData(-3, -4, 12)]
    [InlineData(100, 200, 20000)]
    [InlineData(int.MaxValue, int.MaxValue, 4611686014132420609)]
    public void Multiply_ReturnsCorrectProduct(int a, int b, BigInteger expected)
    {
        // Arrange
        using var num1 = new SecureBigInteger(a);
        using var num2 = new SecureBigInteger(b);

        // Act
        using var result = SecureBigInteger.Multiply(num1, num2);

        // Assert
        using var pinnedCharArray = result.ToPinnedCharArray();
        var s = new string(pinnedCharArray.PoolArray, 0, pinnedCharArray.Length);
        Assert.Equal(expected.ToString(), s);
    }

    [Fact]
    public void Multiply_LargeNumbers_ReturnsCorrectProduct()
    {
        // Arrange
        using var num1 = new SecureBigInteger("123456789");
        using var num2 = new SecureBigInteger("987654321");

        // Act
        using var result = SecureBigInteger.Multiply(num1, num2);

        // Assert
        using var pinnedCharArray = result.ToPinnedCharArray();
        var s = new string(pinnedCharArray.PoolArray, 0, pinnedCharArray.Length);
        Assert.Equal("121932631112635269", s);
    }

    [Fact]
    public void MultiplyOperator_ReturnsCorrectProduct()
    {
        // Arrange
        using var num1 = new SecureBigInteger(6);
        using var num2 = new SecureBigInteger(7);

        // Act
        using var result = num1 * num2;

        // Assert
        using var pinnedCharArray = result.ToPinnedCharArray();
        var s = new string(pinnedCharArray.PoolArray, 0, pinnedCharArray.Length);
        Assert.Equal("42", s);
    }

    [Theory]
    [InlineData(10, 2, 5)]
    [InlineData(10, 3, 3)]
    [InlineData(0, 5, 0)]
    [InlineData(-10, 2, -5)]
    [InlineData(10, -2, -5)]
    [InlineData(-10, -2, 5)]
    [InlineData(100, 10, 10)]
    public void Divide_ReturnsCorrectQuotient(int a, int b, int expected)
    {
        // Arrange
        using var num1 = new SecureBigInteger(a);
        using var num2 = new SecureBigInteger(b);

        // Act
        using var result = SecureBigInteger.Divide(num1, num2);

        // Assert
        using var pinnedCharArray = result.ToPinnedCharArray();
        var s = new string(pinnedCharArray.PoolArray, 0, pinnedCharArray.Length);
        Assert.Equal(expected.ToString(), s);
    }

    [Fact]
    public void Divide_ByZero_ThrowsDivideByZeroException()
    {
        // Arrange
        using var num1 = new SecureBigInteger(10);
        using var num2 = new SecureBigInteger(0);

        // Act & Assert
        Assert.Throws<DivideByZeroException>(() =>
        {
            using var _ = SecureBigInteger.Divide(num1, num2);
        });
    }

    [Fact]
    public void DivideOperator_ReturnsCorrectQuotient()
    {
        // Arrange
        using var num1 = new SecureBigInteger(20);
        using var num2 = new SecureBigInteger(4);

        // Act
        using var result = num1 / num2;

        // Assert
        using var pinnedCharArray = result.ToPinnedCharArray();
        var s = new string(pinnedCharArray.PoolArray, 0, pinnedCharArray.Length);
        Assert.Equal("5", s);
    }

    [Theory]
    [InlineData(10, 3, 1)]
    [InlineData(10, 5, 0)]
    [InlineData(7, 3, 1)]
    [InlineData(-10, 3, -1)]
    [InlineData(10, -3, 1)]
    public void Remainder_ReturnsCorrectRemainder(int a, int b, int expected)
    {
        // Arrange
        using var num1 = new SecureBigInteger(a);
        using var num2 = new SecureBigInteger(b);

        // Act
        using var result = SecureBigInteger.Remainder(num1, num2);
        
        // Assert
        using var pinnedCharArray = result.ToPinnedCharArray();
        var s = new string(pinnedCharArray.PoolArray, 0, pinnedCharArray.Length);
        Assert.Equal(expected.ToString(), s);
    }

    [Fact]
    public void Remainder_ByZero_ThrowsDivideByZeroException()
    {
        // Arrange
        using var num1 = new SecureBigInteger(10);
        using var num2 = new SecureBigInteger(0);
        
        // Act & Assert
        Assert.Throws<DivideByZeroException>(() =>
        {
            using var _ = SecureBigInteger.Remainder(num1, num2);
        });
    }

    [Fact]
    public void ModuloOperator_ReturnsCorrectRemainder()
    {
        // Arrange
        using var num1 = new SecureBigInteger(17);
        using var num2 = new SecureBigInteger(5);

        // Act
        using var result = num1 % num2;

        // Assert
        using var pinnedCharArray = result.ToPinnedCharArray();
        var s = new string(pinnedCharArray.PoolArray, 0, pinnedCharArray.Length);
        Assert.Equal("2", s);
    }

    [Theory]
    [InlineData(0, 0)]
    [InlineData(1, 1)]
    [InlineData(2, 4)]
    [InlineData(5, 25)]
    [InlineData(-5, 25)]
    [InlineData(10, 100)]
    [InlineData(12, 144)]
    public void Square_ReturnsCorrectSquare(int value, int expected)
    {
        // Arrange
        using var num = new SecureBigInteger(value);

        // Act
        using var result = num.Square();

        // Assert
        using var pinnedCharArray = result.ToPinnedCharArray();
        var s = new string(pinnedCharArray.PoolArray, 0, pinnedCharArray.Length);
        Assert.Equal(expected.ToString(), s);
    }

    [Theory]
    [InlineData(0, 0)]
    [InlineData(1, 1)]
    [InlineData(4, 2)]
    [InlineData(9, 3)]
    [InlineData(16, 4)]
    [InlineData(25, 5)]
    [InlineData(100, 10)]
    [InlineData(144, 12)]
    [InlineData(10, 3)]
    public void Sqrt_ReturnsCorrectRoot(int value, int expected)
    {
        // Arrange
        using var num = new SecureBigInteger(value);

        // Act
        using var result = num.Sqrt();
        
        // Assert
        using var pinnedCharArray = result.ToPinnedCharArray();
        var s = new string(pinnedCharArray.PoolArray, 0, pinnedCharArray.Length);
        Assert.Equal(expected.ToString(), s);
    }

    [Fact]
    public void Sqrt_NegativeNumber_ThrowsInvalidOperationException()
    {
        // Arrange
        using var num = new SecureBigInteger(-4);
        
        // Act & Assert
        Assert.Throws<InvalidOperationException>(() =>
        {
            using var _ = num.Sqrt();
        });
    }

    [Theory]
    [InlineData(8, 3, 2)]
    [InlineData(27, 3, 3)]
    [InlineData(64, 3, 4)]
    [InlineData(16, 4, 2)]
    [InlineData(32, 5, 2)]
    [InlineData(100, 2, 10)]
    public void NthRoot_ReturnsCorrectRoot(int value, int n, int expected)
    {
        // Arrange
        using var num = new SecureBigInteger(value);

        // Act
        using var result = num.NthRoot(n);

        // Assert
        using var pinnedCharArray = result.ToPinnedCharArray();
        var s = new string(pinnedCharArray.PoolArray, 0, pinnedCharArray.Length);
        Assert.Equal(expected.ToString(), s);
    }

    [Fact]
    public void NthRoot_NegativeWithOddRoot_ReturnsCorrectRoot()
    {
        // Arrange
        using var num = new SecureBigInteger(-8);

        // Act
        using var result = num.NthRoot(3);

        // Assert
        using var pinnedCharArray = result.ToPinnedCharArray();
        var s = new string(pinnedCharArray.PoolArray, 0, pinnedCharArray.Length);
        Assert.Equal("-2", s);
    }

    [Fact]
    public void NthRoot_NegativeWithEvenRoot_ThrowsInvalidOperationException()
    {
        // Arrange
        using var num = new SecureBigInteger(-16);

        // Act & Assert
        Assert.Throws<InvalidOperationException>(() =>
        {
            using var _ = num.NthRoot(2);
        });
    }

    [Fact]
    public void NthRoot_ZeroOrNegativeExponent_ThrowsArgumentException()
    {
        // Arrange
        using var num = new SecureBigInteger(8);

        // Act & Assert
        Assert.Throws<ArgumentException>(() =>
        {
            using var _ = num.NthRoot(0);
        });
        Assert.Throws<ArgumentException>(() =>
        {
            using var _ = num.NthRoot(-1);
        });
    }

    [Theory]
    [InlineData(0, 0)]
    [InlineData(5, 5)]
    [InlineData(-5, 5)]
    [InlineData(100, 100)]
    [InlineData(-100, 100)]
    public void Abs_ReturnsAbsoluteValue(int value, int expected)
    {
        // Arrange
        using var num = new SecureBigInteger(value);

        // Act
        using var result = num.Abs();

        // Assert
        using var pinnedCharArray = result.ToPinnedCharArray();
        var s = new string(pinnedCharArray.PoolArray, 0, pinnedCharArray.Length);
        Assert.Equal(expected.ToString(), s);
    }

    [Theory]
    [InlineData(0, 0)]
    [InlineData(5, -5)]
    [InlineData(-5, 5)]
    [InlineData(100, -100)]
    public void Negate_ReturnsNegatedValue(int value, int expected)
    {
        // Arrange
        using var num = new SecureBigInteger(value);

        // Act
        using var result = num.Negate();

        // Assert
        using var pinnedCharArray = result.ToPinnedCharArray();
        var s = new string(pinnedCharArray.PoolArray, 0, pinnedCharArray.Length);
        Assert.Equal(expected.ToString(), s);
    }

    [Fact]
    public void NegateOperator_ReturnsNegatedValue()
    {
        // Arrange
        using var num = new SecureBigInteger(42);

        // Act
        using var result = -num;

        // Assert
        using var pinnedCharArray = result.ToPinnedCharArray();
        var s = new string(pinnedCharArray.PoolArray, 0, pinnedCharArray.Length);
        Assert.Equal("-42", s);
    }

    [Fact]
    public void NegateOperator_NullInput_ThrowsArgumentNullException()
    {
        // Arrange
        SecureBigInteger value = null;

        // Act
        var ex = Assert.Throws<ArgumentNullException>(() =>
        {
            using var _ = -value;
        });

        // Assert
        Assert.Equal("value", ex.ParamName);
    }

    [Theory]
    [InlineData(2, 0, 1)]
    [InlineData(2, 1, 2)]
    [InlineData(2, 3, 8)]
    [InlineData(2, 10, 1024)]
    [InlineData(2, 13, 8192)]
    [InlineData(2, 17, 131072)]
    [InlineData(5, 3, 125)]
    [InlineData(-2, 3, -8)]
    [InlineData(-2, 4, 16)]
    [InlineData(10, 6, 1000000)]
    public void Pow_ReturnsCorrectPower(int baseValue, int exponent, int expected)
    {
        // Arrange
        using var num = new SecureBigInteger(baseValue);

        // Act
        using var result = num.Pow(exponent);

        // Assert
        using var pinnedCharArray = result.ToPinnedCharArray();
        var s = new string(pinnedCharArray.PoolArray, 0, pinnedCharArray.Length);
        Assert.Equal(expected.ToString(), s);
    }

    [Fact]
    public void Pow_NegativeExponent_ThrowsArgumentException()
    {
        // Arrange
        using var num = new SecureBigInteger(2);

        // Act & Assert
        Assert.Throws<ArgumentException>(() =>
        {
            using var _ = num.Pow(-1);
        });
    }

    [Fact]
    public void Pow_LargeExponent_ReturnsCorrectPower()
    {
        // Arrange
        using var num = new SecureBigInteger(2);

        // Act
        using var result = num.Pow(20);

        // Assert
        using var pinnedCharArray = result.ToPinnedCharArray();
        var s = new string(pinnedCharArray.PoolArray, 0, pinnedCharArray.Length);
        Assert.Equal("1048576", s);
    }

    [Theory]
    [InlineData(1, 10, 0.0)]
    [InlineData(10, 10, 1.0)]
    [InlineData(100, 10, 2.0)]
    [InlineData(1000, 10, 3.0)]
    [InlineData(8, 2, 3.0)]
    [InlineData(16, 2, 4.0)]
    [InlineData(27, 3, 3.0)]
    public void Log_WithValidInputs_ReturnsCorrectValue(int value, double baseValue, double expected)
    {
        // Arrange
        using var num = new SecureBigInteger(value);

        // Act
        var result = SecureBigInteger.Log(num, baseValue);

        // Assert
        Assert.Equal(expected, result, 10);
    }

    [Fact]
    public void Log_WithBase10_MatchesStandardLog10()
    {
        // Arrange
        using var num = new SecureBigInteger(12345);

        // Act
        var result = SecureBigInteger.Log(num, 10);

        // Assert
        var expected = Math.Log10(12345);
        Assert.Equal(expected, result, 10);
    }

    [Fact]
    public void Log_WithBaseE_MatchesNaturalLog()
    {
        // Arrange
        using var num = new SecureBigInteger(12345);

        // Act
        var result = SecureBigInteger.Log(num, Math.E);

        // Assert
        var expected = Math.Log(12345);
        Assert.Equal(expected, result, 10);
    }

    [Fact]
    public void Log_WithBase2_MatchesLog2()
    {
        // Arrange
        using var num = new SecureBigInteger(1024);

        // Act
        var result = SecureBigInteger.Log(num, 2);

        // Assert
        Assert.Equal(10.0, result, 10);
    }

    [Fact]
    public void Log_OfZero_ReturnsNegativeInfinity()
    {
        // Arrange
        using var num = new SecureBigInteger(0);

        // Act
        var result = SecureBigInteger.Log(num, 10);

        // Assert
        Assert.Equal(double.NegativeInfinity, result);
    }

    [Fact]
    public void Log_OfNegativeNumber_ReturnsNaN()
    {
        // Arrange
        using var num = new SecureBigInteger(-100);

        // Act
        var result = SecureBigInteger.Log(num, 10);

        // Assert
        Assert.True(double.IsNaN(result));
    }

    [Fact]
    public void Log_WithBase1_ReturnsNaN()
    {
        // Arrange
        using var num = new SecureBigInteger(100);

        // Act
        var result = SecureBigInteger.Log(num, 1.0);

        // Assert
        Assert.True(double.IsNaN(result));
    }

    [Fact]
    public void Log_WithNegativeBase_ReturnsNaN()
    {
        // Arrange
        using var num = new SecureBigInteger(100);

        // Act
        double result = SecureBigInteger.Log(num, -10);

        // Assert
        Assert.True(double.IsNaN(result));
    }

    [Fact]
    public void Log_WithNaNBase_ReturnsNaN()
    {
        // Arrange
        using var num = new SecureBigInteger(100);

        // Act
        double result = SecureBigInteger.Log(num, double.NaN);

        // Assert
        Assert.True(double.IsNaN(result));
    }

    [Fact]
    public void Log_WithInfiniteBase_ReturnsCorrectValue()
    {
        // Arrange
        using var one = new SecureBigInteger(1);
        using var other = new SecureBigInteger(100);

        // Act
        double resultOne = SecureBigInteger.Log(one, double.PositiveInfinity);
        double resultOther = SecureBigInteger.Log(other, double.PositiveInfinity);

        // Assert
        Assert.Equal(0.0, resultOne);
        Assert.True(double.IsNaN(resultOther));
    }

    [Fact]
    public void Log_WithZeroBase_ReturnsNaN()
    {
        // Arrange
        using var num = new SecureBigInteger(100);

        // Act
        double result = SecureBigInteger.Log(num, 0.0);

        // Assert
        Assert.True(double.IsNaN(result));
    }

    [Fact]
    public void Log_OfOneWithZeroBase_ReturnsZero()
    {
        // Arrange
        using var num = new SecureBigInteger(1);

        // Act
        double result = SecureBigInteger.Log(num, 0.0);

        // Assert
        Assert.Equal(0.0, result);
    }

    [Fact]
    public void Log_OfOne_ReturnsZero()
    {
        // Arrange
        using var num = new SecureBigInteger(1);

        // Act
        double result = SecureBigInteger.Log(num, 10);

        // Assert
        Assert.Equal(0.0, result);
    }

    [Theory]
    [InlineData(1, 0.0)]
    [InlineData(2, 0.693147180559945)]
    [InlineData(10, 2.302585092994046)]
    [InlineData(100, 4.605170185988092)]
    public void Log_Natural_ReturnsCorrectValue(int value, double expected)
    {
        // Arrange
        using var num = new SecureBigInteger(value);

        // Act
        double result = SecureBigInteger.Log(num);

        // Assert
        Assert.Equal(expected, result, 10);
    }

    [Fact]
    public void Log_Natural_MatchesMathLog()
    {
        // Arrange
        using var num = new SecureBigInteger(12345);

        // Act
        double result = SecureBigInteger.Log(num);

        // Assert
        double expected = Math.Log(12345);
        Assert.Equal(expected, result, 10);
    }

    [Fact]
    public void Log_Natural_OfZero_ReturnsNegativeInfinity()
    {
        // Arrange
        using var num = new SecureBigInteger(0);

        // Act
        double result = SecureBigInteger.Log(num);

        // Assert
        Assert.Equal(double.NegativeInfinity, result);
    }

    [Fact]
    public void Log_Natural_OfNegative_ReturnsNaN()
    {
        // Arrange
        using var num = new SecureBigInteger(-10);

        // Act
        double result = SecureBigInteger.Log(num);

        // Assert
        Assert.True(double.IsNaN(result));
    }

    [Theory]
    [InlineData(1, 0.0)]
    [InlineData(10, 1.0)]
    [InlineData(100, 2.0)]
    [InlineData(1000, 3.0)]
    [InlineData(10000, 4.0)]
    public void Log10_ReturnsCorrectValue(int value, double expected)
    {
        // Arrange
        using var num = new SecureBigInteger(value);

        // Act
        double result = SecureBigInteger.Log10(num);

        // Assert
        Assert.Equal(expected, result, 10);
    }

    [Fact]
    public void Log10_MatchesMathLog10()
    {
        // Arrange
        using var num = new SecureBigInteger(12345);

        // Act
        double result = SecureBigInteger.Log10(num);

        // Assert
        double expected = Math.Log10(12345);
        Assert.Equal(expected, result, 10);
    }

    [Fact]
    public void Log10_OfZero_ReturnsNegativeInfinity()
    {
        // Arrange
        using var num = new SecureBigInteger(0);

        // Act
        double result = SecureBigInteger.Log10(num);

        // Assert
        Assert.Equal(double.NegativeInfinity, result);
    }

    [Fact]
    public void Log10_OfNegative_ReturnsNaN()
    {
        // Arrange
        using var num = new SecureBigInteger(-10);

        // Act
        double result = SecureBigInteger.Log10(num);

        // Assert
        Assert.True(double.IsNaN(result));
    }

    [Theory]
    [InlineData(1, 0.0)]
    [InlineData(2, 1.0)]
    [InlineData(4, 2.0)]
    [InlineData(8, 3.0)]
    [InlineData(16, 4.0)]
    [InlineData(1024, 10.0)]
    public void Log2_ReturnsCorrectValue(int value, double expected)
    {
        // Arrange
        using var num = new SecureBigInteger(value);

        // Act
        double result = SecureBigInteger.Log2(num);

        // Assert
        Assert.Equal(expected, result, 10);
    }

    [Fact]
    public void Log2_MatchesMathLog2()
    {
        // Arrange
        using var num = new SecureBigInteger(12345);

        // Act
        double result = SecureBigInteger.Log2(num);

        // Assert
        double expected = Math.Log(12345, 2);
        Assert.Equal(expected, result, 10);
    }

    [Fact]
    public void Log2_OfZero_ReturnsNegativeInfinity()
    {
        // Arrange
        using var num = new SecureBigInteger(0);

        // Act
        double result = SecureBigInteger.Log2(num);

        // Assert
        Assert.Equal(double.NegativeInfinity, result);
    }

    [Fact]
    public void Log_VeryLargeNumber_ReturnsReasonableValue()
    {
        // Arrange
        // 2^1000
        using var num = new SecureBigInteger(2);
        using var large = num.Pow(1000);

        // Act
        double result = SecureBigInteger.Log2(large);

        // Assert
        // Sollte ungefähr 1000 sein
        Assert.True(Math.Abs(result - 1000.0) < 1.0);
    }

    [Fact]
    public void Log10_VeryLargeNumber_ReturnsReasonableValue()
    {
        // Arrange
        // 10^100 (Googol)
        using var num = new SecureBigInteger(10);
        using var googol = num.Pow(100);

        // Act
        double result = SecureBigInteger.Log10(googol);

        // Assert
        // Sollte genau 100 sein
        Assert.Equal(100.0, result, 5);
    }

    [Fact]
    public void Log_ConsistentAcrossBases()
    {
        // Arrange
        using var num = new SecureBigInteger(12345);

        // Act
        double log2 = SecureBigInteger.Log2(num);
        double log10 = SecureBigInteger.Log10(num);
        double logE = SecureBigInteger.Log(num);

        // Assert
        // Überprüfe Beziehungen zwischen den Logarithmen
        // log_b(x) = ln(x) / ln(b)
        double log2FromNatural = logE / Math.Log(2);
        double log10FromNatural = logE / Math.Log(10);

        Assert.Equal(log2, log2FromNatural, 10);
        Assert.Equal(log10, log10FromNatural, 10);
    }

    [Fact]
    public void Log_MatchesBigIntegerLog()
    {
        // Arrange
        var testValues = new[] { 2, 10, 100, 1000, 12345, 999999 };
        var bases = new[] { 2.0, Math.E, 10.0, 16.0 };

        // Act & Assert
        foreach (var value in testValues)
        {
            using var secure = new SecureBigInteger(value);
            var bigInt = new BigInteger(value);

            foreach (var baseValue in bases)
            {
                double secureResult = SecureBigInteger.Log(secure, baseValue);
                double bigIntResult = BigInteger.Log(bigInt, baseValue);

                Assert.Equal(bigIntResult, secureResult, 10);
            }
        }
    }

    [Fact]
    public void Log10_MatchesBigIntegerLog10()
    {
        // Arrange
        var testValues = new[] { 1, 10, 100, 1000, 12345, 999999 };

        // Act & Assert
        foreach (var value in testValues)
        {
            using var secure = new SecureBigInteger(value);
            var bigInt = new BigInteger(value);

            double secureResult = SecureBigInteger.Log10(secure);
            double bigIntResult = BigInteger.Log10(bigInt);

            Assert.Equal(bigIntResult, secureResult, 10);
        }
    }

    [Fact]
    public void Log_WithNull_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() => SecureBigInteger.Log(null, 10));
    }

    [Fact]
    public void Log_Natural_WithNull_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() => SecureBigInteger.Log(null));
    }

    [Fact]
    public void Log10_WithNull_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() => SecureBigInteger.Log10(null));
    }

    [Fact]
    public void Log2_WithNull_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() => SecureBigInteger.Log2(null));
    }

    [Theory]
    [InlineData(12, 8, 4)]
    [InlineData(54, 24, 6)]
    [InlineData(100, 50, 50)]
    [InlineData(17, 19, 1)]
    [InlineData(0, 5, 5)]
    [InlineData(5, 0, 5)]
    public void Gcd_ReturnsCorrectGcd(int a, int b, int expected)
    {
        // Arrange
        using var num1 = new SecureBigInteger(a);
        using var num2 = new SecureBigInteger(b);

        // Act
        using var result = SecureBigInteger.Gcd(num1, num2);

        // Assert
        using var pinnedCharArray = result.ToPinnedCharArray();
        var s = new string(pinnedCharArray.PoolArray, 0, pinnedCharArray.Length);
        Assert.Equal(expected.ToString(), s);
    }

    [Fact]
    public void Gcd_WithNegativeNumbers_ReturnsPositiveGcd()
    {
        // Arrange
        using var num1 = new SecureBigInteger(-12);
        using var num2 = new SecureBigInteger(8);

        // Act
        using var result = SecureBigInteger.Gcd(num1, num2);

        // Assert
        using var pinnedCharArray = result.ToPinnedCharArray();
        var s = new string(pinnedCharArray.PoolArray, 0, pinnedCharArray.Length);
        Assert.Equal("4", s);
    }

    [Theory]
    [InlineData(2, 3, 5, 3)] // 2^3 mod 5 = 8 mod 5 = 3
    [InlineData(3, 5, 7, 5)] // 3^5 mod 7 = 243 mod 7 = 5
    [InlineData(10, 0, 6, 1)] // Every number^0 is 1
    [InlineData(5, 3, 13, 8)] // 5^3 mod 13 = 125 mod 13 = 8
    [InlineData(4, 4, 9, 4)] // 4^4 mod
    [InlineData(7, 256, 1009, 383)]
    public void ModPow_ReturnsCorrectResult(int baseValue, int exponent, int modulus, int expected)
    {
        // Arrange
        using var b = new SecureBigInteger(baseValue);
        using var e = new SecureBigInteger(exponent);
        using var m = new SecureBigInteger(modulus);

        // Act
        using var result = SecureBigInteger.ModPow(b, e, m);

        // Assert
        using var pinnedCharArray = result.ToPinnedCharArray();
        var s = new string(pinnedCharArray.PoolArray, 0, pinnedCharArray.Length);
        Assert.Equal(expected.ToString(), s);
    }

    [Fact]
    public void ModPow_ZeroModulus_ThrowsDivideByZeroException()
    {
        // Arrange
        using var b = new SecureBigInteger(2);
        using var e = new SecureBigInteger(3);
        using var m = new SecureBigInteger(0);

        // Act & Assert
        Assert.Throws<DivideByZeroException>(() =>
        {
            using var _ = SecureBigInteger.ModPow(b, e, m);
        });
    }

    [Fact]
    public void ModPow_NegativeExponent_ThrowsArgumentException()
    {
        // Arrange
        using var b = new SecureBigInteger(2);
        using var e = new SecureBigInteger(-1);
        using var m = new SecureBigInteger(5);

        // Act & Assert
        Assert.Throws<ArgumentException>(() =>
        {
            using var _ = SecureBigInteger.ModPow(b, e, m);
        });
    }

    [Theory]
    [InlineData(5, 5, true)]
    [InlineData(5, 3, false)]
    [InlineData(-5, -5, true)]
    [InlineData(0, 0, true)]
    [InlineData(int.MaxValue, int.MaxValue, true)]
    [InlineData(int.MinValue, int.MinValue, true)]
    [InlineData(int.MaxValue, int.MinValue, false)]
    public void Equals_ReturnsCorrectResult(int a, int b, bool expected)
    {
        // Arrange
        using var num1 = new SecureBigInteger(a);
        using var num2 = new SecureBigInteger(b);

        // Act & Assert
        Assert.Equal(expected, num1.Equals(num2));
    }

    [Fact]
    public void EqualsOperator_ReturnsCorrectResult()
    {
        // Arrange
        using var num1 = new SecureBigInteger(42);
        using var num2 = new SecureBigInteger(42);
        using var num3 = new SecureBigInteger(43);

        // Act & Assert
        Assert.True(num1 == num2);
        Assert.False(num1 == num3);
    }

    [Fact]
    public void NotEqualsOperator_ReturnsCorrectResult()
    {
        // Arrange
        using var num1 = new SecureBigInteger(42);
        using var num2 = new SecureBigInteger(43);
        using var num3 = new SecureBigInteger(42);

        // Act & Assert
        Assert.True(num1 != num2);
        Assert.False(num1 != num3);
    }

    [Theory]
    [InlineData(3, 5, true)]
    [InlineData(5, 3, false)]
    [InlineData(5, 5, false)]
    [InlineData(-5, 3, true)]
    public void LessThan_ReturnsCorrectResult(int a, int b, bool expected)
    {
        // Arrange
        using var num1 = new SecureBigInteger(a);
        using var num2 = new SecureBigInteger(b);

        // Act & Assert
        Assert.Equal(expected, num1 < num2);
    }

    [Theory]
    [InlineData(5, 3, true)]
    [InlineData(3, 5, false)]
    [InlineData(5, 5, false)]
    [InlineData(3, -5, true)]
    public void GreaterThan_ReturnsCorrectResult(int a, int b, bool expected)
    {
        // Arrange
        using var num1 = new SecureBigInteger(a);
        using var num2 = new SecureBigInteger(b);

        // Act & Assert
        Assert.Equal(expected, num1 > num2);
    }

    [Theory]
    [InlineData(3, 5, true)]
    [InlineData(5, 3, false)]
    [InlineData(5, 5, true)]
    public void LessThanOrEqual_ReturnsCorrectResult(int a, int b, bool expected)
    {
        // Arrange
        using var num1 = new SecureBigInteger(a);
        using var num2 = new SecureBigInteger(b);

        // Acter & Assert
        Assert.Equal(expected, num1 <= num2);
    }

    [Fact]
    public void LessThanOrEqualOperator_NullLeft_ThrowsArgumentNullException()
    {
        // Arrange
        SecureBigInteger left = null;
        using var right = new SecureBigInteger(5);

        // Act
        var ex = Assert.Throws<ArgumentNullException>(() => left <= right);

        // Assert
        Assert.Equal("left", ex.ParamName);
    }

    [Fact]
    public void LessThanOrEqualOperator_NullRight_ThrowsArgumentNullException()
    {
        // Arrange
        using var left = new SecureBigInteger(5);
        SecureBigInteger right = null;

        // Act
        var ex = Assert.Throws<ArgumentNullException>(() => left <= right);

        // Assert
        Assert.Equal("right", ex.ParamName);
    }

    [Fact]
    public void GreaterThanOrEqualOperator_NullLeft_ThrowsArgumentNullException()
    {
        // Arrange
        SecureBigInteger left = null;
        using var right = new SecureBigInteger(5);

        // Act
        var ex = Assert.Throws<ArgumentNullException>(() => left >= right);

        // Assert
        Assert.Equal("left", ex.ParamName);
    }

    [Fact]
    public void GreaterThanOrEqualOperator_NullRight_ThrowsArgumentNullException()
    {
        // Arrange
        using var left = new SecureBigInteger(5);
        SecureBigInteger right = null;

        // Act
        var ex = Assert.Throws<ArgumentNullException>(() => left >= right);

        // Assert
        Assert.Equal("right", ex.ParamName);
    }

    [Theory]
    [InlineData(5, 3, true)]
    [InlineData(3, 5, false)]
    [InlineData(5, 5, true)]
    public void GreaterThanOrEqual_ReturnsCorrectResult(int a, int b, bool expected)
    {
        // Arrange
        using var num1 = new SecureBigInteger(a);
        using var num2 = new SecureBigInteger(b);

        // Act & Assert
        Assert.Equal(expected, num1 >= num2);
    }

    [Theory]
    [InlineData(3, 5, -1)]
    [InlineData(5, 3, 1)]
    [InlineData(5, 5, 0)]
    [InlineData(-5, 3, -1)]
    [InlineData(3, -5, 1)]
    public void CompareTo_ReturnsCorrectResult(int a, int b, int expected)
    {
        // Arrange
        using var num1 = new SecureBigInteger(a);
        using var num2 = new SecureBigInteger(b);

        // Act
        var result = num1.CompareTo(num2);

        // Assert
        Assert.Equal(expected, Math.Sign(result));
    }

    [Fact]
    public void Increment_IncreasesValueByOne()
    {
        // Arrange
        var num = new SecureBigInteger(41);

        // Act
        using var result = ++num;

        // Assert
        using var pinnedCharArray = result.ToPinnedCharArray();
        var s = new string(pinnedCharArray.PoolArray, 0, pinnedCharArray.Length);
        Assert.Equal("42", s);
        num.Dispose();
    }

    [Fact]
    public void Decrement_DecreasesValueByOne()
    {
        // Arrange
        var num = new SecureBigInteger(43);

        // Act
        using var result = --num;

        // Assert
        using var pinnedCharArray = result.ToPinnedCharArray();
        var s = new string(pinnedCharArray.PoolArray, 0, pinnedCharArray.Length);
        Assert.Equal("42", s);
        num.Dispose();
    }

    [Theory]
    [InlineData(0)]
    [InlineData(42)]
    [InlineData(-42)]
    [InlineData(int.MaxValue)]
    [InlineData(int.MinValue)]
    public void ExplicitCastToInt_ReturnsCorrectValue(int value)
    {
        // Arrange
        using var num = new SecureBigInteger(value);

        // Act
        int result = (int)num;

        // Assert
        Assert.Equal(value, result);
    }

    [Fact]
    public void ExplicitCastToInt_WithTooLargeValue_ThrowsOverflowException()
    {
        // Arrange
        using var num = new SecureBigInteger(long.MaxValue);

        // Act & Assert
        Assert.Throws<OverflowException>(() => (int)num);
    }

    [Theory]
    [InlineData(0L)]
    [InlineData(42L)]
    [InlineData(-42L)]
    [InlineData(long.MaxValue)]
    [InlineData(long.MinValue)]
    public void ExplicitCastToLong_ReturnsCorrectValue(long value)
    {
        // Arrange
        using var num = new SecureBigInteger(value);

        // Act
        long result = (long)num;

        // Assert
        Assert.Equal(value, result);
    }

    [Fact]
    public void ExplicitCastToLong_WithTooLargeValue_ThrowsOverflowException()
    {
        // Arrange
        using var num = new SecureBigInteger(long.MaxValue);
        using var bigNum = SecureBigInteger.Add(num, num);

        // Act & Assert
        Assert.Throws<OverflowException>(() => (long)bigNum);
    }

    [Theory]
    [InlineData(0, "SecureBigInteger(0)")]
    [InlineData(42, "SecureBigInteger(42)")]
    [InlineData(-42, "SecureBigInteger(-42)")]
    [InlineData(123456, "SecureBigInteger(123456)")]
    [InlineData(int.MaxValue, "SecureBigInteger(2147483647)")]
    [InlineData(int.MinValue, "SecureBigInteger(-2147483648)")]
    [InlineData(long.MaxValue, "SecureBigInteger(9223372036854775807)")]
    [InlineData(long.MinValue, "SecureBigInteger(-9223372036854775808)")]
    public void ToString_ReturnsCorrectString(long value, string expected)
    {
        // Arrange
        using var num = new SecureBigInteger(value);

        // Act & Assert
#if DEBUG
        Assert.Equal(expected, num.ToString());
#else
        Assert.Equal("*** Secured Value ***", num.ToString());
#endif
    }
    
    [Theory]
    [InlineData(0, "0")]
    [InlineData(42, "42")]
    [InlineData(-42, "-42")]
    [InlineData(123456, "123456")]
    [InlineData(int.MaxValue, "2147483647")]
    [InlineData(int.MinValue, "-2147483648")]
    [InlineData(long.MaxValue, "9223372036854775807")]
    [InlineData(long.MinValue, "-9223372036854775808")]
    public void ToPinnedCharArray_ReturnsCorrectString(long value, string expected)
    {
        // Arrange
        using var num = new SecureBigInteger(value);

        // Act
        using var pinnedCharArray = num.ToPinnedCharArray();

        // Assert
        var s = new string(pinnedCharArray.PoolArray, 0, pinnedCharArray.Length);
        Assert.Equal(expected, s);
    }

    [Theory]
    [InlineData(0, "00")]
    [InlineData(255, "FF")]
    [InlineData(256, "0100")]
    [InlineData(-255, "-FF")]
    [InlineData(65535, "FFFF")]
    [InlineData(-65535, "-FFFF")]
    public void ToHexadecimal_ReturnsCorrectHexString(int value, string expected)
    {
        // Arrange
        using var num = new SecureBigInteger(value);

        // Act
        using var result = num.ToHexadecimal();

        // Assert
        var s = new string(result.PoolArray, 0, result.Length);
        Assert.Equal(expected, s);
    }

    [Fact]
    public void Dispose_CanBeCalledMultipleTimes()
    {
        // Arrange
        var num = new SecureBigInteger(42);
        num.Dispose();

        // Act
        var exception = Record.Exception(num.Dispose);

        // Assert
        Assert.Null(exception);
    }

    [Fact]
    public void AfterDispose_OperationsThrowObjectDisposedException()
    {
        // Arrange
        var num = new SecureBigInteger(-42);
        using var live = new SecureBigInteger(7);
        num.Dispose();

        // Act & Assert — properties
        Assert.Throws<ObjectDisposedException>(() => num.IsZero);
        Assert.Throws<ObjectDisposedException>(() => num.IsOne);
        Assert.Throws<ObjectDisposedException>(() => num.IsEven);
        Assert.Throws<ObjectDisposedException>(() => num.Sign);
        Assert.Throws<ObjectDisposedException>(() => num.ByteCount);

        // Unary math
        Assert.Throws<ObjectDisposedException>(() =>
        {
            using var _ = num.Abs();
        });
        Assert.Throws<ObjectDisposedException>(() =>
        {
            using var _ = num.Negate();
        });
        Assert.Throws<ObjectDisposedException>(() =>
        {
            using var _ = num.Square();
        });
        Assert.Throws<ObjectDisposedException>(() =>
        {
            using var _ = num.Sqrt();
        });
        Assert.Throws<ObjectDisposedException>(() =>
        {
            using var _ = num.NthRoot(3);
        });
        Assert.Throws<ObjectDisposedException>(() =>
        {
            using var _ = num.Pow(2);
        });

        // Serialisation
        Assert.Throws<ObjectDisposedException>(() => num.ToString());
        Assert.Throws<ObjectDisposedException>(() =>
        {
            using var _ = num.ToPinnedCharArray();
        });
        Assert.Throws<ObjectDisposedException>(() =>
        {
            using var _ = num.ToByteArray();
        });
        Assert.Throws<ObjectDisposedException>(() =>
        {
            using var _ = num.ToHexadecimal();
        });

        // Equality / ordering / hashing
        Assert.Throws<ObjectDisposedException>(() => num.Equals(live));
        Assert.Throws<ObjectDisposedException>(() => num.Equals((object)live));
        Assert.Throws<ObjectDisposedException>(() => num.GetHashCode());
        Assert.Throws<ObjectDisposedException>(() => num.CompareTo(live));
    }

    [Fact]
    public void VeryLargeNumber_CanBeCreatedAndUsed()
    {
        // Arrange & Act
        using var num = new SecureBigInteger("12345678901234567890123456789012345678901234567890");

        // Assert
        Assert.False(num.IsZero);
        Assert.Equal(1, num.Sign);
    }

    [Fact]
    public void MultipleOperationsChained_WorksCorrectly()
    {
        // Arrange
        using var a = new SecureBigInteger(10);
        using var b = new SecureBigInteger(20);
        using var c = new SecureBigInteger(30);

        // Act
        using var result = (a + b) * c;

        // Assert
        using var pinnedCharArray = result.ToPinnedCharArray();
        var s = new string(pinnedCharArray.PoolArray, 0, pinnedCharArray.Length);
        Assert.Equal("900", s); // (10 + 20) * 30 = 900
    }

    [Fact]
    public void ZeroDividedByAnything_ReturnsZero()
    {
        // Arrange
        using var zero = new SecureBigInteger(0);
        using var divisor = new SecureBigInteger(42);

        // Act
        using var result = zero / divisor;

        // Assert
        Assert.True(result.IsZero);
    }

    [Fact]
    public void NegativeZero_IsNormalizedToPositiveZero()
    {
        // Arrange
        using var a = new SecureBigInteger(5);
        using var b = new SecureBigInteger(5);

        // Act
        using var result = a - b;

        // Assert
        Assert.True(result.IsZero);
        Assert.Equal(0, result.Sign);
    }

    [Fact]
    public void GetHashCode_SameValues_ReturnsSameHashCode()
    {
        // Arrange
        using var num1 = new SecureBigInteger(42);
        using var num2 = new SecureBigInteger(42);

        // Act & Assert
        Assert.Equal(num1.GetHashCode(), num2.GetHashCode());
    }

    [Fact]
    public void CompareTo_NullOther_ReturnsOne()
    {
        // Arrange
        // IComparable<T> convention: a non-null instance is greater than null.
        using var num = new SecureBigInteger(42);

        // Act & Assert
        Assert.Equal(1, num.CompareTo(null));
    }

    [Fact]
    public void EqualsObject_MatchingSecureBigInteger_ReturnsTrue()
    {
        // Arrange
        using var num = new SecureBigInteger(42);
        using var same = new SecureBigInteger(42);

        // Act & Assert
        Assert.True(num.Equals((object)same));
    }

    [Fact]
    public void EqualsObject_DifferingSecureBigInteger_ReturnsFalse()
    {
        // Arrange
        using var num = new SecureBigInteger(42);
        using var different = new SecureBigInteger(43);

        // Act & Assert
        Assert.False(num.Equals((object)different));
    }

    [Fact]
    public void EqualsObject_Null_ReturnsFalse()
    {
        using var num = new SecureBigInteger(42);

        Assert.False(num.Equals((object)null));
    }

    [Fact]
    public void EqualsObject_NonSecureBigIntegerType_ReturnsFalse()
    {
        // Arrange
        using var num = new SecureBigInteger(42);

        // Act & Assert
        // Cast to object to defeat the implicit `int → SecureBigInteger` conversion
        // that would otherwise pick the `Equals(SecureBigInteger)` overload.
        Assert.False(num.Equals("not a SecureBigInteger"));
        Assert.False(num.Equals((object)42));
    }

    [Fact]
    public void AllArithmeticOperations_WithNullOperand_ThrowArgumentNullException()
    {
        // Arrange
        // Aggregate guard: every static math/comparison/conversion API rejects null
        // operands with ArgumentNullException. The dedicated Add_WithNull*,
        // LessThanOrEqualOperator_Null*, GreaterThanOrEqualOperator_Null* and
        // NegateOperator_NullInput_* tests below assert ParamName per case; this
        // aggregate covers the full surface symmetrically so that a regression that
        // drops the guard on any single operation is caught.
        using var live = new SecureBigInteger(7);

        // Act & Assert
        // Binary arithmetic
        Assert.Throws<ArgumentNullException>(() => SecureBigInteger.Add(null, live));
        Assert.Throws<ArgumentNullException>(() => SecureBigInteger.Add(live, null));
        Assert.Throws<ArgumentNullException>(() => SecureBigInteger.Subtract(null, live));
        Assert.Throws<ArgumentNullException>(() => SecureBigInteger.Subtract(live, null));
        Assert.Throws<ArgumentNullException>(() => SecureBigInteger.Multiply(null, live));
        Assert.Throws<ArgumentNullException>(() => SecureBigInteger.Multiply(live, null));
        Assert.Throws<ArgumentNullException>(() => SecureBigInteger.Divide(null, live));
        Assert.Throws<ArgumentNullException>(() => SecureBigInteger.Divide(live, null));
        Assert.Throws<ArgumentNullException>(() => SecureBigInteger.Remainder(null, live));
        Assert.Throws<ArgumentNullException>(() => SecureBigInteger.Remainder(live, null));

        // Number-theoretic
        Assert.Throws<ArgumentNullException>(() => SecureBigInteger.Gcd(null, live));
        Assert.Throws<ArgumentNullException>(() => SecureBigInteger.Gcd(live, null));
        Assert.Throws<ArgumentNullException>(() => SecureBigInteger.ModPow(null, live, live));
        Assert.Throws<ArgumentNullException>(() => SecureBigInteger.ModPow(live, null, live));
        Assert.Throws<ArgumentNullException>(() => SecureBigInteger.ModPow(live, live, null));

        // Comparison operators
        Assert.Throws<ArgumentNullException>(() => { _ = (SecureBigInteger)null < live; });
        Assert.Throws<ArgumentNullException>(() => { _ = live < (SecureBigInteger)null; });
        Assert.Throws<ArgumentNullException>(() => { _ = (SecureBigInteger)null > live; });
        Assert.Throws<ArgumentNullException>(() => { _ = live > (SecureBigInteger)null; });
        Assert.Throws<ArgumentNullException>(() => { _ = (SecureBigInteger)null <= live; });
        Assert.Throws<ArgumentNullException>(() => { _ = live <= (SecureBigInteger)null; });
        Assert.Throws<ArgumentNullException>(() => { _ = (SecureBigInteger)null >= live; });
        Assert.Throws<ArgumentNullException>(() => { _ = live >= (SecureBigInteger)null; });

        // Explicit conversion operators
        Assert.Throws<ArgumentNullException>(() => (int)(SecureBigInteger)null);
        Assert.Throws<ArgumentNullException>(() => (long)(SecureBigInteger)null);
    }

    [Fact]
    public void Add_WithNullLeft_ThrowsArgumentNullException()
    {
        // Arrange
        using var num = new SecureBigInteger(42);

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() =>
        {
            using var _ = SecureBigInteger.Add(null, num);
        });
    }

    [Fact]
    public void Add_WithNullRight_ThrowsArgumentNullException()
    {
        // Arrange
        using var num = new SecureBigInteger(42);

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() =>
        {
            using var _ = SecureBigInteger.Add(num, null);
        });
    }

    [Fact]
    public void Constructor_Copy_WithDisposedSource_ThrowsObjectDisposedException()
    {
        // Arrange
        // The copy constructor must reject a disposed source — copying it would
        // either dereference the freed pool buffer or silently produce a corrupted
        // duplicate, both unacceptable for a secret container.
        var source = new SecureBigInteger(42);
        source.Dispose();

        // Act & Assert
        Assert.Throws<ObjectDisposedException>(() =>
        {
            using var _ = new SecureBigInteger(source);
        });
    }

    [Fact]
    public void Constructor_Copy_WithNull_ThrowsArgumentNullException()
    {
        // Arrange, Act & Assert
        Assert.Throws<ArgumentNullException>(() =>
        {
            using var _ = new SecureBigInteger(null as SecureBigInteger);
        });
        Assert.Throws<ArgumentNullException>(() =>
        {
            using var _ = new SecureBigInteger(null, false);
        });
        Assert.Throws<ArgumentNullException>(() =>
        {
            using var _ = new SecureBigInteger(null, true);
        });
        Assert.Throws<ArgumentNullException>(() =>
        {
            using var _ = new SecureBigInteger(null as byte[]);
        });
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(-1)]
    [InlineData(123456)]
    [InlineData(-123456)]
    [InlineData(305419896)]
    [InlineData(-305419896)]
    [InlineData(int.MaxValue)]
    [InlineData(int.MinValue)]
    public void Constructor_FromByteArray_ReturnsEquivalentInteger(int value)
    {
        // Arrange & Act
        using var fromInteger = new SecureBigInteger(value);
        using var data = fromInteger.ToByteArray();
        using var fromByteArray = new SecureBigInteger(data.PoolArray, data.Length);

        // Assert
        Assert.Equal(fromInteger, fromByteArray);
        Assert.Equal(value, (int)fromByteArray);
    }

    [Theory]
    [InlineData(0L)]
    [InlineData(1L)]
    [InlineData(-1L)]
    [InlineData(123456L)]
    [InlineData(-123456L)]
    [InlineData(305419896L)]
    [InlineData(-305419896L)]
    [InlineData(12345678901234L)]
    [InlineData(-12345678901234L)]
    [InlineData(long.MaxValue)]
    [InlineData(long.MinValue)]
    public void Constructor_FromByteArray_ReturnsEquivalentLong(long value)
    {
        // Arrange & Act
        using var fromInteger = new SecureBigInteger(value);
        using var data = fromInteger.ToByteArray();
        using var fromByteArray = new SecureBigInteger(data.PoolArray, data.Length);

        // Assert
        Assert.Equal(fromInteger, fromByteArray);
        Assert.Equal(value, (long)fromByteArray);
    }

    [Theory]
    [InlineData(127,   new byte[] { 0x7F })]
    [InlineData(128,   new byte[] { 0x80, 0x00 })]
    [InlineData(255,   new byte[] { 0xFF, 0x00 })]
    [InlineData(256,   new byte[] { 0x00, 0x01 })]
    [InlineData(32767, new byte[] { 0xFF, 0x7F })]
    [InlineData(32768, new byte[] { 0x00, 0x80, 0x00 })]
    public void ToByteArray_PositiveValue_MatchesTwosComplementForm(int value, byte[] expected)
    {
        // Mirror of Constructor_TwosComplement_PositiveBoundary_PreservesValue: same
        // value/byte pairs, opposite direction. ToByteArray must append a 0x00
        // sentinel when the high bit of the most-significant byte is set, so that
        // round-trip decoding (or any consumer that reads the bytes as
        // two's-complement) interprets the value as positive.
        using var num = new SecureBigInteger(value);

        // Act
        using var bytes = num.ToByteArray();

        // Assert
        Assert.Equal(expected.Length, bytes.Length);
        for (int i = 0; i < expected.Length; i++)
        {
            Assert.Equal(expected[i], bytes[i]);
        }
    }

    [Theory]
    [InlineData(new byte[] { 0x7F }, 127)]
    [InlineData(new byte[] { 0x80, 0x00 }, 128)]
    [InlineData(new byte[] { 0xFF, 0x00 }, 255)]
    [InlineData(new byte[] { 0x00, 0x01 }, 256)]
    [InlineData(new byte[] { 0xFF, 0x7F }, 32767)]
    [InlineData(new byte[] { 0x00, 0x80, 0x00 }, 32768)]
    public void Constructor_TwosComplement_PositiveBoundary_PreservesValue(byte[] data, int expected)
    {
        // Arrange & Act
        using var num = new SecureBigInteger(data);

        // Assert
        Assert.Equal(1, num.Sign);
        Assert.Equal(expected, (int)num);
    }

    [Theory]
    [InlineData(new byte[] { 0xFF }, -1)]
    [InlineData(new byte[] { 0x80 }, -128)]
    [InlineData(new byte[] { 0x7F, 0xFF }, -129)]
    [InlineData(new byte[] { 0x00, 0xFF }, -256)]
    [InlineData(new byte[] { 0x00, 0x80 }, -32768)]
    [InlineData(new byte[] { 0xFF, 0xFF }, -1)]
    public void Constructor_TwosComplement_NegativeBoundary_PreservesValue(byte[] data, int expected)
    {
        // Arrange & Act
        using var num = new SecureBigInteger(data);

        // Assert
        Assert.Equal(-1, num.Sign);
        Assert.Equal(expected, (int)num);
    }

    [Theory]
    [InlineData(new byte[] { 0x00 })]
    [InlineData(new byte[] { 0x00, 0x00 })]
    [InlineData(new byte[] { 0x00, 0x00, 0x00, 0x00 })]
    public void Constructor_TwosComplement_AllZero_IsZero(byte[] data)
    {
        // Arrange & Act
        using var num = new SecureBigInteger(data);

        // Assert
        Assert.True(num.IsZero);
        Assert.Equal(0, num.Sign);
    }

    [Theory]
    [InlineData(new byte[] { 0xFF, 0xFF }, -1, 1)]
    [InlineData(new byte[] { 0xFF, 0xFF, 0xFF, 0xFF }, -1, 1)]
    [InlineData(new byte[] { 0x00, 0xFF }, -256, 2)]
    public void Constructor_TwosComplement_NegativeMultiByte_TrimsToCanonicalMagnitude(
        byte[] data,
        int expected,
        int expectedByteCount)
    {
        // Arrange & Act
        using var fromBytes = new SecureBigInteger(data);
        using var fromInt = new SecureBigInteger(expected);

        // Assert
        Assert.Equal(fromInt, fromBytes);
        Assert.Equal(expectedByteCount, fromBytes.ByteCount);
    }

    [Fact]
    public void Constructor_TwosComplement_NegativeOne_AbsIsOne()
    {
        // Arrange & Act
        using var minusOne = new SecureBigInteger(new byte[] { 0xFF, 0xFF, 0xFF });
        using var abs = minusOne.Abs();

        // Assert
        Assert.False(minusOne.IsOne);
        Assert.True(abs.IsOne);
    }

    [Theory]
    [InlineData(-1)]
    [InlineData(int.MinValue)]
    public void Constructor_FromByteArrayLengthSign_NegativeLength_ThrowsWithParamNameLength(int length)
    {
        // Act
        var ex = Assert.Throws<ArgumentOutOfRangeException>(() =>
        {
            using var _ = new SecureBigInteger(new byte[] { 0x01 }, length, false);
        });

        // Assert
        Assert.Equal("length", ex.ParamName);
    }

    [Theory]
    [InlineData(-1)]
    [InlineData(int.MinValue)]
    public void Constructor_FromByteArrayLength_NegativeLength_ThrowsWithParamNameLength(int length)
    {
        // Act
        var ex = Assert.Throws<ArgumentOutOfRangeException>(() =>
        {
            using var _ = new SecureBigInteger(new byte[] { 0x01 }, length);
        });

        // Assert
        Assert.Equal("length", ex.ParamName);
    }

    [Theory]
    [InlineData(2)]
    [InlineData(100)]
    public void Constructor_FromByteArrayLengthSign_LengthExceedsArray_ThrowsWithParamNameLength(int length)
    {
        // Act
        var ex = Assert.Throws<ArgumentOutOfRangeException>(() =>
        {
            using var _ = new SecureBigInteger(new byte[] { 0x01 }, length, false);
        });

        // Assert
        Assert.Equal("length", ex.ParamName);
    }

    [Theory]
    [InlineData(2)]
    [InlineData(100)]
    public void Constructor_FromByteArrayLength_LengthExceedsArray_ThrowsWithParamNameLength(int length)
    {
        // Act
        var ex = Assert.Throws<ArgumentOutOfRangeException>(() =>
        {
            using var _ = new SecureBigInteger(new byte[] { 0x01 }, length);
        });

        // Assert
        Assert.Equal("length", ex.ParamName);
    }

    [Fact]
    public void Constructor_FromByteArrayLengthSign_ZeroLength_IsZero()
    {
        // Arrange
        using var num = new SecureBigInteger(new byte[] { 0xFF, 0xFF }, 0, false);

        // Act & Assert
        Assert.True(num.IsZero);
        Assert.Equal(0, num.Sign);
    }

    [Fact]
    public void Constructor_FromByteArrayLengthSign_ZeroLengthAndIsNegative_IsZeroWithoutSign()
    {
        // Arrange
        using var num = new SecureBigInteger(new byte[] { 0xFF, 0xFF }, 0, true);

        // Act & Assert
        Assert.True(num.IsZero);
        Assert.Equal(0, num.Sign);
    }

    [Fact]
    public void Constructor_FromByteArrayLength_ZeroLength_IsZero()
    {
        // Arrange
        using var num = new SecureBigInteger(new byte[] { 0xFF, 0xFF }, 0);

        // Act & Assert
        Assert.True(num.IsZero);
        Assert.Equal(0, num.Sign);
    }

    [Fact]
    public void Constructor_FromString_InvalidChar_RepeatedFailures_DoNotCrash()
    {
        // Act & Assert
        for (int i = 0; i < 100; i++)
        {
            Assert.Throws<FormatException>(() =>
            {
                using var _ = new SecureBigInteger("12abc");
            });
        }
    }

    [Fact]
    public void Sqrt_RepeatedCalls_ReturnsConsistentResult()
    {
        // Arrange
        using var value = new SecureBigInteger(123456789);

        // Act & Assert
        for (int i = 0; i < 100; i++)
        {
            using var root = value.Sqrt();
            Assert.Equal(11111, (int)root);
        }
    }

    [Fact]
    public void Gcd_RepeatedCalls_ReturnsConsistentResult()
    {
        // Arrange
        using var a = new SecureBigInteger(48);
        using var b = new SecureBigInteger(18);

        // Act & Assert
        for (int i = 0; i < 100; i++)
        {
            using var g = SecureBigInteger.Gcd(a, b);
            Assert.Equal(6, (int)g);
        }
    }

    [Fact]
    public void ToPinnedCharArray_RepeatedCalls_ReturnsConsistentString()
    {
        // Arrange
        using var value = new SecureBigInteger(-12345);

        // Act & Assert
        for (int i = 0; i < 100; i++)
        {
            using var arr = value.ToPinnedCharArray();
            var s = new string(arr.PoolArray, 0, arr.Length);
            Assert.Equal("-12345", s);
        }
    }
}