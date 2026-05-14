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

using SecretSharingDotNet.Cryptography.SecureInput;
using SecretSharingDotNet.Math.Numerics;
using System;
using System.Linq;
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
    // Mixed-sign Add and same-sign Subtract on equal magnitudes used to take a
    // distinct early-return path (H1 fix). Verify the result is a canonical +0
    // — IsZero, Sign, Equals, and GetHashCode all agree with a clean zero.
    [InlineData(5, -5)]
    [InlineData(-5, 5)]
    [InlineData(int.MaxValue, -int.MaxValue)]
    [InlineData(-int.MaxValue, int.MaxValue)]
    public void Add_OppositeSignsEqualMagnitudes_EqualsCleanZero(int a, int b)
    {
        // Arrange
        using var left = new SecureBigInteger(a);
        using var right = new SecureBigInteger(b);
        using var cleanZero = new SecureBigInteger(0);

        // Act
        using var sum = SecureBigInteger.Add(left, right);

        // Assert
        Assert.True(sum.IsZero);
        Assert.Equal(0, sum.Sign);
        Assert.Equal(cleanZero, sum);
        Assert.Equal(cleanZero.GetHashCode(), sum.GetHashCode());
    }

    [Theory]
    [InlineData(5, 5)]
    [InlineData(-5, -5)]
    [InlineData(int.MaxValue, int.MaxValue)]
    [InlineData(-int.MaxValue, -int.MaxValue)]
    public void Subtract_SameSignEqualMagnitudes_EqualsCleanZero(int a, int b)
    {
        // Arrange
        using var minuend = new SecureBigInteger(a);
        using var subtrahend = new SecureBigInteger(b);
        using var cleanZero = new SecureBigInteger(0);

        // Act
        using var diff = SecureBigInteger.Subtract(minuend, subtrahend);

        // Assert
        Assert.True(diff.IsZero);
        Assert.Equal(0, diff.Sign);
        Assert.Equal(cleanZero, diff);
        Assert.Equal(cleanZero.GetHashCode(), diff.GetHashCode());
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

    [Theory]
    // First row preserves the original Multiply_LargeNumbers test values
    // (123456789 × 987654321 = 121932631112635269) verbatim. Subsequent rows
    // add coverage for full-32-bit operands, half-and-half magnitudes, and a
    // 20-decimal × 20-decimal case that exercises a wider operand window than
    // the original.
    [InlineData("123456789", "987654321", "121932631112635269")]
    [InlineData("4294967295", "4294967295", "18446744065119617025")]
    [InlineData("99999999", "99999999", "9999999800000001")]
    [InlineData("12345678901234567890", "98765432109876543210", "1219326311370217952237463801111263526900")]
    public void Multiply_LargeNumbers_ReturnsCorrectProduct(string leftFactor, string rightFactor, string expectedProduct)
    {
        // Arrange
        using var left = BigInteger.Parse(leftFactor).ToSecureBigInteger();
        using var right = BigInteger.Parse(rightFactor).ToSecureBigInteger();

        // Act
        using var result = SecureBigInteger.Multiply(left, right);

        // Assert
        using var pinnedCharArray = result.ToPinnedCharArray();
        var actualProduct = new string(pinnedCharArray.PoolArray, 0, pinnedCharArray.Length);
        Assert.Equal(expectedProduct, actualProduct);
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

    [Theory]
    // After H2 (zero-operand short-circuit removal), zero-operand inputs flow
    // through MultiplyUnsigned/DivideUnsigned. Verify the result is still
    // numerically correct AND a canonical +0.
    [InlineData(0, 5)]
    [InlineData(0, -5)]
    [InlineData(5, 0)]
    [InlineData(-5, 0)]
    [InlineData(0, 0)]
    public void Multiply_WithZeroOperand_EqualsCleanZero(int a, int b)
    {
        // Arrange
        using var left = new SecureBigInteger(a);
        using var right = new SecureBigInteger(b);
        using var cleanZero = new SecureBigInteger(0);

        // Act
        using var product = SecureBigInteger.Multiply(left, right);

        // Assert
        Assert.True(product.IsZero);
        Assert.Equal(0, product.Sign);
        Assert.Equal(cleanZero, product);
        Assert.Equal(cleanZero.GetHashCode(), product.GetHashCode());
    }

    [Theory]
    [InlineData(0, 5)]
    [InlineData(0, -5)]
    public void Divide_ZeroDividend_EqualsCleanZero(int a, int b)
    {
        // Arrange
        using var dividend = new SecureBigInteger(a);
        using var divisor = new SecureBigInteger(b);
        using var cleanZero = new SecureBigInteger(0);

        // Act
        using var quotient = SecureBigInteger.Divide(dividend, divisor);

        // Assert
        Assert.True(quotient.IsZero);
        Assert.Equal(0, quotient.Sign);
        Assert.Equal(cleanZero, quotient);
        Assert.Equal(cleanZero.GetHashCode(), quotient.GetHashCode());
    }

    [Theory]
    [InlineData(0, 5)]
    [InlineData(0, -5)]
    public void Remainder_ZeroDividend_EqualsCleanZero(int a, int b)
    {
        // Arrange
        using var dividend = new SecureBigInteger(a);
        using var divisor = new SecureBigInteger(b);
        using var cleanZero = new SecureBigInteger(0);

        // Act
        using var remainder = SecureBigInteger.Remainder(dividend, divisor);

        // Assert
        Assert.True(remainder.IsZero);
        Assert.Equal(0, remainder.Sign);
        Assert.Equal(cleanZero, remainder);
        Assert.Equal(cleanZero.GetHashCode(), remainder.GetHashCode());
    }

    [Theory]
    // Mixed-sign Divide where the magnitude of the dividend is smaller than the
    // divisor, producing a zero quotient. Without H4 fix, the result has
    // isNegative=true on a magnitude-0 result ("negative zero"), and Equals
    // against a clean +0 returns false.
    [InlineData(3, -5)]
    [InlineData(-3, 5)]
    [InlineData(-7, 11)]
    [InlineData(1, -1000000)]
    public void Divide_MixedSignWithZeroQuotient_EqualsCleanZero(int a, int b)
    {
        // Arrange
        using var dividend = new SecureBigInteger(a);
        using var divisor = new SecureBigInteger(b);
        using var cleanZero = new SecureBigInteger(0);

        // Act
        using var quotient = SecureBigInteger.Divide(dividend, divisor);

        // Assert
        Assert.True(quotient.IsZero);
        Assert.Equal(0, quotient.Sign);
        Assert.Equal(cleanZero, quotient);
        Assert.Equal(cleanZero.GetHashCode(), quotient.GetHashCode());
    }

    [Theory]
    // Exact divisions with non-positive dividend produce a zero remainder.
    // Without H4 fix, the remainder inherits dividend.isNegative=true on a
    // magnitude-0 result ("negative zero"); Equals(rem, +0) returns false.
    [InlineData(-10, 5)]
    [InlineData(-100, 25)]
    [InlineData(-1, 1)]
    public void Remainder_ExactDivisionNegativeDividend_EqualsCleanZero(int a, int b)
    {
        // Arrange
        using var dividend = new SecureBigInteger(a);
        using var divisor = new SecureBigInteger(b);
        using var cleanZero = new SecureBigInteger(0);

        // Act
        using var remainder = SecureBigInteger.Remainder(dividend, divisor);

        // Assert
        Assert.True(remainder.IsZero);
        Assert.Equal(0, remainder.Sign);
        Assert.Equal(cleanZero, remainder);
        Assert.Equal(cleanZero.GetHashCode(), remainder.GetHashCode());
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

        // Self-equality on a disposed instance must throw, not silently return true
        // via the ReferenceEquals fast-path (L1 fix — disposal check now runs before
        // the reference-equality short-circuit in both Equals and operator==).
        Assert.Throws<ObjectDisposedException>(() => num.Equals(num));
        Assert.Throws<ObjectDisposedException>(() =>
        {
            var _ = num == num;
        });
    }

    [Theory]
    // First row preserves the original 50-decimal-digit test value verbatim.
    // The remaining rows extend the surface to 60 digits (positive), 60
    // digits (negative magnitude — verifies sign carries through the
    // BigInteger → hex → SecureBigInteger bridge), and a Mersenne-shaped
    // value that crosses the M127 boundary the Shamir hot path operates near.
    [InlineData("12345678901234567890123456789012345678901234567890", 1)]
    [InlineData("987654321098765432109876543210987654321098765432109876543210", 1)]
    [InlineData("-987654321098765432109876543210987654321098765432109876543210", -1)]
    [InlineData("170141183460469231731687303715884105727", 1)]
    public void VeryLargeNumber_CanBeCreatedAndUsed(string decimalValue, int expectedSign)
    {
        // Arrange & Act
        using var num = BigInteger.Parse(decimalValue).ToSecureBigInteger();

        // Assert
        Assert.False(num.IsZero);
        Assert.Equal(expectedSign, num.Sign);
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
        Assert.Equal(expected, bytes.PoolArray.Take(bytes.Length));
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

    [Theory]
    // First row preserves the spirit of the original
    // Constructor_FromString_InvalidChar_RepeatedFailures test, which fed
    // "12abc" to the (now-removed) decimal ctor. "12abc" is valid hex, so it
    // can no longer test rejection — replaced with "1G2" which is invalid hex
    // for the same structural reason ('G' is the smallest letter past 'F').
    // Subsequent rows extend coverage to whitespace, punctuation, and a fully
    // non-hex Latin sample. Repeating the failure path 100× guards against a
    // regression where the exception path leaks pinned buffers
    // (no SecureClear on throw).
    [InlineData("1G2")]
    [InlineData("12 34")]
    [InlineData("12.34")]
    [InlineData("XYZ")]
    public void FromHexadecimal_InvalidChar_RepeatedFailures_DoNotCrash(string invalidHex)
    {
        // Arrange — none beyond the parameterised invalid input.

        // Act & Assert
        Assert.All(Enumerable.Range(0, 100), _ =>
        {
            using var hex = invalidHex.ToPinnedSecure();
            Assert.Throws<FormatException>(() =>
            {
                using var inner = SecureBigInteger.FromHexadecimal(hex);
            });
        });
    }

    [Theory]
    // Companion to the invalid-char test above: "12abc" was REJECTED by the
    // old decimal ctor as having non-digit characters; under the new hex API
    // it is ACCEPTED as a valid lower-case hex literal (= 0x12ABC = 76732).
    // Preserved as a regression guard against future tightening that might
    // re-reject mixed-case hex.
    [InlineData("12abc", 0x12ABC)]
    [InlineData("DEADBEEF", 0xDEADBEEFL)]
    [InlineData("AbCdEf", 0xABCDEF)]
    public void FromHexadecimal_MixedCaseHex_ParsesCorrectly(string hexValue, long expectedValue)
    {
        // Arrange
        using var pinnedHex = hexValue.ToPinnedSecure();

        // Act
        using var num = SecureBigInteger.FromHexadecimal(pinnedHex);

        // Assert
        Assert.Equal(expectedValue, (long)num);
    }

    [Fact]
    public void ToPinnedCharArray_RepeatedCalls_ReturnsConsistentString()
    {
        // Arrange
        using var value = new SecureBigInteger(-12345);

        // Act & Assert
        Assert.All(Enumerable.Range(0, 100), _ =>
        {
            using var arr = value.ToPinnedCharArray();
            var s = new string(arr.PoolArray, 0, arr.Length);
            Assert.Equal("-12345", s);
        });
    }

    [Fact]
    public void FromHexadecimal_NullInput_ThrowsArgumentNullException()
    {
        // Arrange — none.

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() =>
        {
            using var _ = SecureBigInteger.FromHexadecimal(null!);
        });
    }

    [Fact]
    public void FromHexadecimal_EmptyInput_ThrowsArgumentException()
    {
        // Arrange
        using var emptyHex = string.Empty.ToPinnedSecure();

        // Act & Assert
        Assert.Throws<ArgumentException>(() =>
        {
            using var _ = SecureBigInteger.FromHexadecimal(emptyHex);
        });
    }

    [Theory]
    [InlineData("-")]
    [InlineData("+")]
    public void FromHexadecimal_SignWithoutDigits_ThrowsFormatException(string signOnly)
    {
        // Arrange
        using var hex = signOnly.ToPinnedSecure();

        // Act & Assert
        Assert.Throws<FormatException>(() =>
        {
            using var _ = SecureBigInteger.FromHexadecimal(hex);
        });
    }

    [Theory]
    // Odd-length input is supported per the API contract — the leading hex
    // character represents the LOW nibble of the most-significant byte.
    [InlineData("F", 0xFL)]
    [InlineData("1FF", 0x1FFL)]
    [InlineData("ABCDE", 0xABCDEL)]
    public void FromHexadecimal_OddLengthInput_ParsesAsLowNibbleOfMsb(string oddHex, long expectedValue)
    {
        // Arrange
        using var hex = oddHex.ToPinnedSecure();

        // Act
        using var num = SecureBigInteger.FromHexadecimal(hex);

        // Assert
        Assert.Equal(expectedValue, (long)num);
    }

    [Theory]
    // Sign acceptance: '+' is allowed for symmetry with '-' and matches the
    // convention of the (now-removed) decimal ctor.
    [InlineData("+5", 5L)]
    [InlineData("+FF", 255L)]
    [InlineData("-5", -5L)]
    [InlineData("-FF", -255L)]
    public void FromHexadecimal_SignedInput_HonoursLeadingSign(string signedHex, long expectedValue)
    {
        // Arrange
        using var hex = signedHex.ToPinnedSecure();

        // Act
        using var num = SecureBigInteger.FromHexadecimal(hex);

        // Assert
        Assert.Equal(expectedValue, (long)num);
    }

    [Theory]
    // 0x / 0X base prefix is optional. The same magnitude must parse
    // identically with or without the prefix and across leading-zero
    // variations. Sign + prefix combinations are also exercised.
    [InlineData("7B2", 0x7B2L)]
    [InlineData("07B2", 0x7B2L)]
    [InlineData("0x7B2", 0x7B2L)]
    [InlineData("0X7B2", 0x7B2L)]
    [InlineData("0x07B2", 0x7B2L)]
    [InlineData("0X07B2", 0x7B2L)]
    [InlineData("-0xFF", -0xFFL)]
    [InlineData("+0xFF", 0xFFL)]
    [InlineData("-0X07B2", -0x7B2L)]
    public void FromHexadecimal_AcceptsOptional0xPrefix(string hexInput, long expectedValue)
    {
        // Arrange
        using var hex = hexInput.ToPinnedSecure();

        // Act
        using var num = SecureBigInteger.FromHexadecimal(hex);

        // Assert
        Assert.Equal(expectedValue, (long)num);
    }

    [Theory]
    // The 0x prefix without trailing digits is rejected, mirroring the
    // sign-without-digits rule.
    [InlineData("0x")]
    [InlineData("0X")]
    [InlineData("-0x")]
    [InlineData("+0X")]
    public void FromHexadecimal_PrefixWithoutDigits_ThrowsFormatException(string input)
    {
        // Arrange
        using var hex = input.ToPinnedSecure();

        // Act & Assert
        Assert.Throws<FormatException>(() =>
        {
            using var _ = SecureBigInteger.FromHexadecimal(hex);
        });
    }

    [Theory]
    // Round-trip: every value ToHexadecimal can emit must be parsed back to
    // the same value by FromHexadecimal. Decimals span sign, single byte,
    // multi-byte, and a Mersenne-shaped value at the M127 boundary.
    [InlineData("0")]
    [InlineData("1")]
    [InlineData("-1")]
    [InlineData("255")]
    [InlineData("-255")]
    [InlineData("65536")]
    [InlineData("123456789012345678901234567890")]
    [InlineData("170141183460469231731687303715884105727")]
    [InlineData("-170141183460469231731687303715884105727")]
    public void FromHexadecimal_RoundTripWithToHexadecimal_PreservesValue(string decimalValue)
    {
        // Arrange
        using var original = BigInteger.Parse(decimalValue).ToSecureBigInteger();

        // Act
        using var hexChars = original.ToHexadecimal();
        using var roundTripped = SecureBigInteger.FromHexadecimal(hexChars);

        // Assert
        Assert.Equal(original, roundTripped);
    }

    [Theory]
    // Cross-check MersenneModulo against the generic Modulo (= Remainder)
    // path for representative Mersenne exponents and operand magnitudes.
    // Operand values: zero, one, p-1 bits set, exact M_p, M_p + 1 (≡ 1),
    // 2*M_p (≡ M_p), and a 2p-bit value (post-multiply scale).
    [InlineData(13, "0")]
    [InlineData(13, "1")]
    [InlineData(13, "8190")]
    [InlineData(13, "8191")]
    [InlineData(13, "8192")]
    [InlineData(13, "16382")]
    [InlineData(13, "67108863")]
    [InlineData(31, "0")]
    [InlineData(31, "2147483647")]
    [InlineData(31, "2147483648")]
    [InlineData(61, "2305843009213693951")]
    [InlineData(127, "0")]
    [InlineData(127, "170141183460469231731687303715884105727")]
    [InlineData(127, "170141183460469231731687303715884105728")]
    [InlineData(127, "340282366920938463463374607431768211454")]
    [InlineData(127, "28948022309329048855892746252171976962977213799489202546401021394546514198529")]
    public void MersenneModulo_MatchesGenericModulo(int exponent, string operandDecimal)
    {
        // Arrange
        BigInteger operandBig = BigInteger.Parse(operandDecimal);
        BigInteger mersennePrimeBig = (BigInteger.One << exponent) - BigInteger.One;
        BigInteger expectedBig = operandBig % mersennePrimeBig;

        using var operand = operandBig.ToSecureBigInteger();
        using var expected = expectedBig.ToSecureBigInteger();

        // Act
        using var actual = operand.MersenneModulo(exponent);

        // Assert
        Assert.Equal(expected, actual);
    }

    [Fact]
    public void MersenneModulo_NonPositiveExponent_ThrowsArgumentOutOfRangeException()
    {
        // Arrange
        using var operand = new SecureBigInteger(42);

        // Act & Assert
        Assert.Throws<ArgumentOutOfRangeException>(() =>
        {
            using var _ = operand.MersenneModulo(0);
        });
        Assert.Throws<ArgumentOutOfRangeException>(() =>
        {
            using var _ = operand.MersenneModulo(-1);
        });
    }

    [Theory]
    // Mathematical-modulo semantics for negative operands: every row's
    // expected value is the canonical non-negative representative in
    // [0, M_p - 1] of the negative input, computed via
    // ((operand % M_p) + M_p) % M_p on the BCL side and cross-checked
    // against the limb-CT path. The all-zero-after-mod corner case
    // (-M_p, -2*M_p, ...) must canonicalise back to 0 and is tested
    // alongside the typical M_p - residue pattern.
    [InlineData(127, "-1")]
    [InlineData(127, "-3000")]
    [InlineData(127, "-170141183460469231731687303715884105727")]
    [InlineData(127, "-170141183460469231731687303715884105728")]
    [InlineData(127, "-340282366920938463463374607431768211454")]
    [InlineData(31, "-2147483647")]
    [InlineData(31, "-2147483648")]
    [InlineData(13, "-8190")]
    [InlineData(13, "-8191")]
    [InlineData(13, "-8192")]
    public void MersenneModulo_NegativeOperand_ReturnsMathematicalModulo(int exponent, string operandDecimal)
    {
        // Arrange
        BigInteger operandBig = BigInteger.Parse(operandDecimal);
        BigInteger mersennePrimeBig = (BigInteger.One << exponent) - BigInteger.One;
        BigInteger expectedBig = ((operandBig % mersennePrimeBig) + mersennePrimeBig) % mersennePrimeBig;

        using var operand = operandBig.ToSecureBigInteger();
        using var expected = expectedBig.ToSecureBigInteger();

        // Act
        using var actual = operand.MersenneModulo(exponent);

        // Assert
        Assert.Equal(expected, actual);
    }
}