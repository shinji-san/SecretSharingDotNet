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

/// <summary>
/// Unit tests for <see cref="SecureBigInteger"/>: pinned-memory, secure-erase big integer
/// covering constructors (byte array, int/long/ulong, copy, two's-complement boundary),
/// arithmetic (+/-/*/Divide/Remainder/Square/Pow/MersenneModulo), equality and comparison
/// surface, conversions (int/long, ToString, ToHexadecimal, ToPinnedCharArray), and full
/// disposed-state guards on every public member.
/// </summary>
public class SecureBigIntegerTests
{
    /// <summary>
    /// Tests that the <see cref="SecureBigInteger(byte[])"/> constructor parses the given
    /// little-endian two's-complement byte array into the expected numeric value, including
    /// positive, zero, and negative cases.
    /// </summary>
    /// <param name="byteArray">Little-endian two's-complement byte representation.</param>
    /// <param name="expected">The expected decoded value.</param>
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

    /// <summary>
    /// Tests that the parameterless <see cref="SecureBigInteger()"/> constructor produces
    /// a canonical zero: <see cref="SecureBigInteger.IsZero"/> is <c>true</c>,
    /// <see cref="SecureBigInteger.Sign"/> is <c>0</c>, and the decimal string is <c>"0"</c>.
    /// </summary>
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

    /// <summary>
    /// Tests that <see cref="SecureBigInteger(int)"/> round-trips through
    /// <see cref="SecureBigInteger.ToPinnedCharArray()"/> as the matching decimal
    /// representation across the full <see cref="int"/> range.
    /// </summary>
    /// <param name="value">The seed <see cref="int"/> value.</param>
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

    /// <summary>
    /// Tests that <see cref="SecureBigInteger(long)"/> round-trips through
    /// <see cref="SecureBigInteger.ToPinnedCharArray()"/> as the matching decimal
    /// representation across the full <see cref="long"/> range.
    /// </summary>
    /// <param name="value">The seed <see cref="long"/> value.</param>
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

    /// <summary>
    /// Tests that <see cref="SecureBigInteger(ulong)"/> round-trips through
    /// <see cref="SecureBigInteger.ToPinnedCharArray()"/> across the full
    /// <see cref="ulong"/> range — including values above <see cref="long.MaxValue"/>
    /// that the <see cref="long"/> ctor cannot represent.
    /// </summary>
    /// <param name="value">The seed <see cref="ulong"/> value.</param>
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

    /// <summary>
    /// Tests that the implicit <see cref="ulong"/> → <see cref="SecureBigInteger"/>
    /// conversion is routed through the <see cref="ulong"/> constructor and produces
    /// the matching decimal representation.
    /// </summary>
    /// <param name="value">The seed <see cref="ulong"/> value.</param>
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

    /// <summary>
    /// Tests that the copy constructor produces a value-equal but reference-distinct
    /// <see cref="SecureBigInteger"/> instance — the copy owns an independent pinned
    /// buffer.
    /// </summary>
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

    /// <summary>
    /// Tests that <see cref="SecureBigInteger.IsZero"/> is <see langword="true"/> for
    /// instances constructed from a zero seed (both <see cref="int"/> and
    /// <see cref="long"/> overloads).
    /// </summary>
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

    /// <summary>
    /// Tests that <see cref="SecureBigInteger.IsZero"/> is <see langword="false"/> for
    /// positive and negative non-zero seed values.
    /// </summary>
    /// <param name="value">A non-zero seed value.</param>
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

    /// <summary>
    /// Tests that <see cref="SecureBigInteger.IsOne"/> is <see langword="true"/> for
    /// instances constructed from a seed of one (both <see cref="int"/> and
    /// <see cref="long"/> overloads).
    /// </summary>
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

    /// <summary>
    /// Tests that <see cref="SecureBigInteger.IsOne"/> is <see langword="false"/> for
    /// values other than <c>1</c>, including <c>0</c>, <c>-1</c>, and larger magnitudes.
    /// </summary>
    /// <param name="value">A non-one seed value.</param>
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

    /// <summary>
    /// Tests that <see cref="SecureBigInteger.IsEven"/> returns the expected parity for
    /// representative values including signed boundaries (<see cref="int.MaxValue"/>,
    /// <see cref="int.MinValue"/>, <see cref="long.MaxValue"/>, <see cref="long.MinValue"/>).
    /// </summary>
    /// <param name="value">The seed value.</param>
    /// <param name="expectedEven">Whether the value is even.</param>
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

    /// <summary>
    /// Tests that reading <see cref="SecureBigInteger.IsEven"/> after
    /// <see cref="IDisposable.Dispose"/> throws <see cref="ObjectDisposedException"/>.
    /// </summary>
    [Fact]
    public void IsEven_AfterDispose_ThrowsObjectDisposedException()
    {
        // Arrange
        var num = new SecureBigInteger(42);
        num.Dispose();

        // Act & Assert
        Assert.Throws<ObjectDisposedException>(() => num.IsEven);
    }

    /// <summary>
    /// Tests that <see cref="SecureBigInteger.Sign"/> returns <c>0</c> for zero,
    /// <c>1</c> for positive values, and <c>-1</c> for negative values.
    /// </summary>
    /// <param name="value">The seed value.</param>
    /// <param name="expectedSign">The expected sign (-1, 0, or 1).</param>
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

    /// <summary>
    /// Tests that <see cref="SecureBigInteger.Add(SecureBigInteger, SecureBigInteger)"/>
    /// computes the correct sum across positive, negative, mixed-sign, and zero cases.
    /// </summary>
    /// <param name="a">The left summand.</param>
    /// <param name="b">The right summand.</param>
    /// <param name="expected">The expected sum.</param>
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

    /// <summary>
    /// Tests that the <c>operator +</c> overload computes the same sum as the static
    /// <see cref="SecureBigInteger.Add(SecureBigInteger, SecureBigInteger)"/> method.
    /// </summary>
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

    /// <summary>
    /// Tests that <see cref="SecureBigInteger.Subtract(SecureBigInteger, SecureBigInteger)"/>
    /// computes the correct difference across positive, negative, mixed-sign, zero, and
    /// boundary-near-<see cref="int.MaxValue"/> cases.
    /// </summary>
    /// <param name="a">The minuend.</param>
    /// <param name="b">The subtrahend.</param>
    /// <param name="expected">The expected difference.</param>
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

    /// <summary>
    /// Tests that the <c>operator -</c> overload computes the same difference as the
    /// static <see cref="SecureBigInteger.Subtract(SecureBigInteger, SecureBigInteger)"/>
    /// method.
    /// </summary>
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

    /// <summary>
    /// H1 regression guard: mixed-sign Add on equal magnitudes used to take a distinct
    /// early-return path. The result must be a canonical <c>+0</c> —
    /// <see cref="SecureBigInteger.IsZero"/>, <see cref="SecureBigInteger.Sign"/>,
    /// <c>Equals</c>, and <c>GetHashCode</c> all agree with a clean zero.
    /// </summary>
    /// <param name="a">A signed operand.</param>
    /// <param name="b">The opposite-sign equal-magnitude operand.</param>
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

    /// <summary>
    /// H1 regression guard: same-sign Subtract on equal magnitudes used to take a
    /// distinct early-return path. The result must be a canonical <c>+0</c> —
    /// <c>IsZero</c>, <c>Sign</c>, <c>Equals</c>, and <c>GetHashCode</c> all agree with a
    /// clean zero.
    /// </summary>
    /// <param name="a">The minuend.</param>
    /// <param name="b">The same-sign equal-magnitude subtrahend.</param>
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

    /// <summary>
    /// Tests that <see cref="SecureBigInteger.Multiply(SecureBigInteger, SecureBigInteger)"/>
    /// computes the correct product across positive, negative, mixed-sign, zero, and
    /// near-<see cref="int.MaxValue"/> squared cases.
    /// </summary>
    /// <param name="a">The left factor.</param>
    /// <param name="b">The right factor.</param>
    /// <param name="expected">The expected product.</param>
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

    /// <summary>
    /// Tests <see cref="SecureBigInteger.Multiply(SecureBigInteger, SecureBigInteger)"/>
    /// across full-32-bit operands, half-and-half magnitudes, and a 20-decimal × 20-decimal
    /// case that exceeds the original test window.
    /// </summary>
    /// <param name="leftFactor">Decimal representation of the left factor.</param>
    /// <param name="rightFactor">Decimal representation of the right factor.</param>
    /// <param name="expectedProduct">Decimal representation of the expected product.</param>
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

    /// <summary>
    /// Tests that the <c>operator *</c> overload computes the same product as the static
    /// <see cref="SecureBigInteger.Multiply(SecureBigInteger, SecureBigInteger)"/> method.
    /// </summary>
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

    /// <summary>
    /// Tests that <see cref="SecureBigInteger.Divide(SecureBigInteger, SecureBigInteger)"/>
    /// computes the correct quotient across positive, negative, mixed-sign, and zero-dividend
    /// cases.
    /// </summary>
    /// <param name="a">The dividend.</param>
    /// <param name="b">The divisor.</param>
    /// <param name="expected">The expected quotient.</param>
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

    /// <summary>
    /// Tests that <see cref="SecureBigInteger.Divide(SecureBigInteger, SecureBigInteger)"/>
    /// throws <see cref="DivideByZeroException"/> when the divisor is zero.
    /// </summary>
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

    /// <summary>
    /// Tests that the <c>operator /</c> overload computes the same quotient as the static
    /// <see cref="SecureBigInteger.Divide(SecureBigInteger, SecureBigInteger)"/> method.
    /// </summary>
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

    /// <summary>
    /// Tests that <see cref="SecureBigInteger.Remainder(SecureBigInteger, SecureBigInteger)"/>
    /// returns the truncated-division remainder across positive, negative, mixed-sign, and
    /// exact-division cases.
    /// </summary>
    /// <param name="a">The dividend.</param>
    /// <param name="b">The divisor.</param>
    /// <param name="expected">The expected remainder.</param>
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

    /// <summary>
    /// Tests that <see cref="SecureBigInteger.Remainder(SecureBigInteger, SecureBigInteger)"/>
    /// throws <see cref="DivideByZeroException"/> when the divisor is zero.
    /// </summary>
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

    /// <summary>
    /// H2 regression guard: after zero-operand short-circuit removal, zero-operand inputs
    /// flow through <c>MultiplyUnsigned</c>/<c>DivideUnsigned</c>. The product must be
    /// numerically correct AND a canonical <c>+0</c>.
    /// </summary>
    /// <param name="a">The left factor.</param>
    /// <param name="b">The right factor.</param>
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

    /// <summary>
    /// Tests that dividing a zero dividend by any non-zero divisor produces a canonical
    /// <c>+0</c> quotient (<c>IsZero</c>, <c>Sign</c>, <c>Equals</c>, <c>GetHashCode</c>
    /// all agree with a clean zero).
    /// </summary>
    /// <param name="a">The zero dividend.</param>
    /// <param name="b">A non-zero divisor (positive or negative).</param>
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

    /// <summary>
    /// Tests that taking the remainder of a zero dividend by any non-zero divisor
    /// produces a canonical <c>+0</c> result.
    /// </summary>
    /// <param name="a">The zero dividend.</param>
    /// <param name="b">A non-zero divisor (positive or negative).</param>
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

    /// <summary>
    /// H4 regression guard: mixed-sign Divide where the dividend magnitude is smaller
    /// than the divisor magnitude produces a zero quotient. Without the H4 fix, the
    /// result carried <c>isNegative=true</c> on a magnitude-0 ("negative zero"), and
    /// <c>Equals</c> against a clean <c>+0</c> returned <see langword="false"/>.
    /// </summary>
    /// <param name="a">The dividend.</param>
    /// <param name="b">The opposite-sign larger-magnitude divisor.</param>
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

    /// <summary>
    /// H4 regression guard: exact divisions with a non-positive dividend produce a
    /// zero remainder. Without the fix, the remainder inherits
    /// <c>dividend.isNegative=true</c> on a magnitude-0 result ("negative zero") and
    /// <c>Equals(rem, +0)</c> returns <see langword="false"/>.
    /// </summary>
    /// <param name="a">The negative dividend.</param>
    /// <param name="b">A positive exact divisor.</param>
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

    /// <summary>
    /// Tests that the <c>operator %</c> overload computes the same remainder as the
    /// static <see cref="SecureBigInteger.Remainder(SecureBigInteger, SecureBigInteger)"/>
    /// method.
    /// </summary>
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

    /// <summary>
    /// Tests that <see cref="SecureBigInteger.Square()"/> computes the value's square
    /// across zero, one, and positive/negative bases — the result is always non-negative.
    /// </summary>
    /// <param name="value">The base value.</param>
    /// <param name="expected">The expected square.</param>
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

    /// <summary>
    /// Tests that <see cref="SecureBigInteger.Abs()"/> returns the absolute value across
    /// zero, positive, and negative inputs.
    /// </summary>
    /// <param name="value">The input value.</param>
    /// <param name="expected">The expected absolute value.</param>
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

    /// <summary>
    /// Tests that <see cref="SecureBigInteger.Negate()"/> flips the sign — including
    /// the fixed-point case <c>Negate(0) == 0</c>.
    /// </summary>
    /// <param name="value">The input value.</param>
    /// <param name="expected">The expected negated value.</param>
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

    /// <summary>
    /// Tests that the unary <c>operator -</c> overload negates the value as expected.
    /// </summary>
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

    /// <summary>
    /// Tests that the unary <c>operator -</c> rejects a <see langword="null"/> operand
    /// with <see cref="ArgumentNullException"/> and reports <c>"value"</c> as the
    /// <see cref="ArgumentException.ParamName"/>.
    /// </summary>
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

    /// <summary>
    /// Tests that <see cref="SecureBigInteger.Pow(int)"/> computes the correct power
    /// across zero, one, large, and negative-base exponents — including the sign rules
    /// for odd vs. even exponents over a negative base.
    /// </summary>
    /// <param name="baseValue">The base.</param>
    /// <param name="exponent">The non-negative exponent.</param>
    /// <param name="expected">The expected power.</param>
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

    /// <summary>
    /// Tests that <see cref="SecureBigInteger.Pow(int)"/> rejects a negative exponent
    /// with <see cref="ArgumentException"/>.
    /// </summary>
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

    /// <summary>
    /// Tests that <see cref="SecureBigInteger.Pow(int)"/> handles a larger exponent
    /// (<c>2^20 = 1048576</c>) correctly, exercising more than one repeated-squaring
    /// iteration than the parameterised cases above.
    /// </summary>
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

    /// <summary>
    /// Tests that <see cref="SecureBigInteger.Equals(SecureBigInteger)"/> returns the
    /// expected result across equal, unequal, zero, and signed-boundary values.
    /// </summary>
    /// <param name="a">The left operand.</param>
    /// <param name="b">The right operand.</param>
    /// <param name="expected">The expected equality result.</param>
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

    /// <summary>
    /// Tests that <c>operator ==</c> returns the same equality result as
    /// <see cref="SecureBigInteger.Equals(SecureBigInteger)"/> for both equal and
    /// unequal operand pairs.
    /// </summary>
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

    /// <summary>
    /// Tests that <c>operator !=</c> returns the negation of
    /// <see cref="SecureBigInteger.Equals(SecureBigInteger)"/> for both equal and
    /// unequal operand pairs.
    /// </summary>
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

    /// <summary>
    /// Tests that <c>operator &lt;</c> returns the expected result across less-than,
    /// greater-than, equal, and negative-vs-positive operand combinations.
    /// </summary>
    /// <param name="a">The left operand.</param>
    /// <param name="b">The right operand.</param>
    /// <param name="expected">The expected comparison result.</param>
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

    /// <summary>
    /// Tests that <c>operator &gt;</c> returns the expected result across greater-than,
    /// less-than, equal, and positive-vs-negative operand combinations.
    /// </summary>
    /// <param name="a">The left operand.</param>
    /// <param name="b">The right operand.</param>
    /// <param name="expected">The expected comparison result.</param>
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

    /// <summary>
    /// Tests that <c>operator &lt;=</c> returns the expected result across less-than,
    /// greater-than, and equal operand combinations.
    /// </summary>
    /// <param name="a">The left operand.</param>
    /// <param name="b">The right operand.</param>
    /// <param name="expected">The expected comparison result.</param>
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

    /// <summary>
    /// Tests that <c>operator &lt;=</c> rejects a <see langword="null"/> left operand
    /// with <see cref="ArgumentNullException"/> (<c>ParamName == "left"</c>).
    /// </summary>
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

    /// <summary>
    /// Tests that <c>operator &lt;=</c> rejects a <see langword="null"/> right operand
    /// with <see cref="ArgumentNullException"/> (<c>ParamName == "right"</c>).
    /// </summary>
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

    /// <summary>
    /// Tests that <c>operator &gt;=</c> rejects a <see langword="null"/> left operand
    /// with <see cref="ArgumentNullException"/> (<c>ParamName == "left"</c>).
    /// </summary>
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

    /// <summary>
    /// Tests that <c>operator &gt;=</c> rejects a <see langword="null"/> right operand
    /// with <see cref="ArgumentNullException"/> (<c>ParamName == "right"</c>).
    /// </summary>
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

    /// <summary>
    /// Tests that <c>operator &gt;=</c> returns the expected result across greater-than,
    /// less-than, and equal operand combinations.
    /// </summary>
    /// <param name="a">The left operand.</param>
    /// <param name="b">The right operand.</param>
    /// <param name="expected">The expected comparison result.</param>
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

    /// <summary>
    /// Tests that <see cref="SecureBigInteger.CompareTo(SecureBigInteger)"/> returns the
    /// expected sign across less-than, greater-than, equal, and mixed-sign cases.
    /// </summary>
    /// <param name="a">The left operand.</param>
    /// <param name="b">The right operand.</param>
    /// <param name="expected">The expected sign of the comparison (-1, 0, or 1).</param>
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

    /// <summary>
    /// Tests that <c>operator ++</c> increases the value by one (pre-increment form).
    /// </summary>
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

    /// <summary>
    /// Tests that <c>operator --</c> decreases the value by one (pre-decrement form).
    /// </summary>
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

    /// <summary>
    /// Tests that the explicit <see cref="SecureBigInteger"/> → <see cref="int"/>
    /// conversion round-trips across the full <see cref="int"/> range.
    /// </summary>
    /// <param name="value">The seed <see cref="int"/> value.</param>
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

    /// <summary>
    /// Tests that the explicit <see cref="SecureBigInteger"/> → <see cref="int"/>
    /// conversion throws <see cref="OverflowException"/> when the value does not fit
    /// in <see cref="int"/>.
    /// </summary>
    [Fact]
    public void ExplicitCastToInt_WithTooLargeValue_ThrowsOverflowException()
    {
        // Arrange
        using var num = new SecureBigInteger(long.MaxValue);

        // Act & Assert
        Assert.Throws<OverflowException>(() => (int)num);
    }

    /// <summary>
    /// Tests that the explicit <see cref="SecureBigInteger"/> → <see cref="long"/>
    /// conversion round-trips across the full <see cref="long"/> range.
    /// </summary>
    /// <param name="value">The seed <see cref="long"/> value.</param>
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

    /// <summary>
    /// Tests that the explicit <see cref="SecureBigInteger"/> → <see cref="long"/>
    /// conversion throws <see cref="OverflowException"/> when the value does not fit
    /// in <see cref="long"/>.
    /// </summary>
    [Fact]
    public void ExplicitCastToLong_WithTooLargeValue_ThrowsOverflowException()
    {
        // Arrange
        using var num = new SecureBigInteger(long.MaxValue);
        using var bigNum = SecureBigInteger.Add(num, num);

        // Act & Assert
        Assert.Throws<OverflowException>(() => (long)bigNum);
    }

    /// <summary>
    /// Tests <see cref="SecureBigInteger.ToString()"/>: in <c>DEBUG</c> builds it returns
    /// the verbatim wrapper form <c>"SecureBigInteger(value)"</c>; in release builds it
    /// returns the redacted sentinel <c>"*** Secured Value ***"</c>.
    /// </summary>
    /// <param name="value">The seed value.</param>
    /// <param name="expected">The expected DEBUG-build representation.</param>
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

        // Act
        string actual = num.ToString();

        // Assert
#if DEBUG
        Assert.Equal(expected, actual);
#else
        Assert.Equal(TestData.SecuredValueSentinel, actual);
        Assert.NotEqual(expected, actual);
#endif
    }
    
    /// <summary>
    /// Tests that <see cref="SecureBigInteger.ToPinnedCharArray()"/> emits the canonical
    /// decimal representation (with sign for negatives, no wrapper) across the full
    /// signed-integer range.
    /// </summary>
    /// <param name="value">The seed value.</param>
    /// <param name="expected">The expected decimal representation.</param>
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

    /// <summary>
    /// Tests that <see cref="SecureBigInteger.ToHexadecimal()"/> emits the canonical
    /// uppercase hex representation with sign prefix for negatives — including the
    /// zero-pad case (<c>0 → "00"</c>) and high-bit boundary (<c>256 → "0100"</c>).
    /// </summary>
    /// <param name="value">The seed value.</param>
    /// <param name="expected">The expected hex representation.</param>
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

    /// <summary>
    /// Tests that <see cref="IDisposable.Dispose"/> is idempotent — calling it twice
    /// does not throw.
    /// </summary>
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

    /// <summary>
    /// Aggregate disposed-state guard: every public surface (properties, unary math,
    /// serialisation, equality, comparison, hashing, including the self-equality
    /// short-circuit per L1 fix) must throw <see cref="ObjectDisposedException"/>
    /// once <see cref="IDisposable.Dispose"/> has been called.
    /// </summary>
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
#pragma warning disable CS1718 // intentional: exercises operator== reflexive path
            var _ = num == num;
#pragma warning restore CS1718
        });
    }

    /// <summary>
    /// Tests that <see cref="SecureBigInteger"/> handles very large decimal values
    /// (50–60 digits, including a Mersenne-shaped value crossing the M127 boundary the
    /// Shamir hot path operates near). Constructed via
    /// <see cref="SecureBigInteger.ToSecureBigInteger(BigInteger)"/>; sign carries through
    /// the BigInteger → hex → SecureBigInteger bridge.
    /// </summary>
    /// <param name="decimalValue">The decimal representation.</param>
    /// <param name="expectedSign">The expected sign (1 or -1).</param>
    [Theory]
    // First row preserves the original 50-decimal-digit test value verbatim.
    // The remaining rows extend the surface to 60 digits (positive), 60
    // digits (negative magnitude — verifies sign carries through the
    // BigInteger → hex → SecureBigInteger bridge), and a Mersenne-shaped
    // value that crosses the M127 boundary the Shamir hot path operates near.
    [InlineData("12345678901234567890123456789012345678901234567890", 1)]
    [InlineData("987654321098765432109876543210987654321098765432109876543210", 1)]
    [InlineData("-987654321098765432109876543210987654321098765432109876543210", -1)]
    [InlineData(TestData.M127Decimal, 1)]
    public void VeryLargeNumber_CanBeCreatedAndUsed(string decimalValue, int expectedSign)
    {
        // Arrange & Act
        using var num = BigInteger.Parse(decimalValue).ToSecureBigInteger();

        // Assert
        Assert.False(num.IsZero);
        Assert.Equal(expectedSign, num.Sign);
    }

    /// <summary>
    /// Smoke-test that chained arithmetic (<c>(a + b) * c</c>) produces the correct
    /// composite result, exercising the operator-overload pipeline end-to-end.
    /// </summary>
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

    /// <summary>
    /// Tests the algebraic identity <c>0 / x == 0</c> for non-zero divisors — the
    /// quotient is <see cref="SecureBigInteger.IsZero"/>.
    /// </summary>
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

    /// <summary>
    /// Tests that subtracting equal positive operands produces a canonical <c>+0</c> —
    /// no observable "negative zero" leaks through (<c>IsZero == true</c>,
    /// <c>Sign == 0</c>).
    /// </summary>
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

    /// <summary>
    /// Tests the <c>Equals</c>/<c>GetHashCode</c> contract: equal values produce equal
    /// hash codes.
    /// </summary>
    [Fact]
    public void GetHashCode_SameValues_ReturnsSameHashCode()
    {
        // Arrange
        using var num1 = new SecureBigInteger(42);
        using var num2 = new SecureBigInteger(42);

        // Act & Assert
        Assert.Equal(num1.GetHashCode(), num2.GetHashCode());
    }

    /// <summary>
    /// Tests the <see cref="IComparable{T}"/> convention that a non-null instance
    /// compared to <see langword="null"/> returns <c>1</c>.
    /// </summary>
    [Fact]
    public void CompareTo_NullOther_ReturnsOne()
    {
        // Arrange
        // IComparable<T> convention: a non-null instance is greater than null.
        using var num = new SecureBigInteger(42);

        // Act & Assert
        Assert.Equal(1, num.CompareTo(null));
    }

    /// <summary>
    /// Tests <see cref="object.Equals(object)"/> with a value-equal
    /// <see cref="SecureBigInteger"/> returns <see langword="true"/>.
    /// </summary>
    [Fact]
    public void EqualsObject_MatchingSecureBigInteger_ReturnsTrue()
    {
        // Arrange
        using var num = new SecureBigInteger(42);
        using var same = new SecureBigInteger(42);

        // Act & Assert
        Assert.True(num.Equals((object)same));
    }

    /// <summary>
    /// Tests <see cref="object.Equals(object)"/> with a value-different
    /// <see cref="SecureBigInteger"/> returns <see langword="false"/>.
    /// </summary>
    [Fact]
    public void EqualsObject_DifferingSecureBigInteger_ReturnsFalse()
    {
        // Arrange
        using var num = new SecureBigInteger(42);
        using var different = new SecureBigInteger(43);

        // Act & Assert
        Assert.False(num.Equals((object)different));
    }

    /// <summary>
    /// Tests that <see cref="object.Equals(object)"/> against
    /// <see langword="null"/> returns <see langword="false"/> (does not throw).
    /// </summary>
    [Fact]
    public void EqualsObject_Null_ReturnsFalse()
    {
        using var num = new SecureBigInteger(42);

        Assert.False(num.Equals((object)null));
    }

    /// <summary>
    /// Tests that <see cref="object.Equals(object)"/> returns <see langword="false"/>
    /// when given an unrelated type (cast to <see cref="object"/> defeats the implicit
    /// <see cref="int"/> → <see cref="SecureBigInteger"/> overload).
    /// </summary>
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

    /// <summary>
    /// Aggregate <see langword="null"/>-operand guard: every static math/comparison/
    /// conversion API rejects a <see langword="null"/> operand with
    /// <see cref="ArgumentNullException"/>. Companion to the dedicated
    /// <c>Add_WithNull*</c>, <c>LessThanOrEqualOperator_Null*</c>,
    /// <c>GreaterThanOrEqualOperator_Null*</c>, and <c>NegateOperator_NullInput</c>
    /// tests — those assert <c>ParamName</c> per case; this one covers the full surface
    /// symmetrically so a regression that drops the guard on any single operation is
    /// caught.
    /// </summary>
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

    /// <summary>
    /// Tests that <see cref="SecureBigInteger.Add(SecureBigInteger, SecureBigInteger)"/>
    /// rejects a <see langword="null"/> left operand with
    /// <see cref="ArgumentNullException"/>.
    /// </summary>
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

    /// <summary>
    /// Tests that <see cref="SecureBigInteger.Add(SecureBigInteger, SecureBigInteger)"/>
    /// rejects a <see langword="null"/> right operand with
    /// <see cref="ArgumentNullException"/>.
    /// </summary>
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

    /// <summary>
    /// Tests that the copy constructor rejects a disposed source with
    /// <see cref="ObjectDisposedException"/> — copying it would either dereference the
    /// freed pool buffer or silently produce a corrupted duplicate, both unacceptable
    /// for a secret container.
    /// </summary>
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

    /// <summary>
    /// Tests that all constructor overloads accepting a reference operand reject
    /// <see langword="null"/> with <see cref="ArgumentNullException"/> — the
    /// copy ctor, the copy-with-flag ctor, and the byte-array ctor.
    /// </summary>
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

    /// <summary>
    /// Tests that a <see cref="SecureBigInteger"/> built from an <see cref="int"/> seed,
    /// serialised through <see cref="SecureBigInteger.ToByteArray()"/>, and rebuilt via
    /// the byte-array+length ctor round-trips to the same value across the full
    /// <see cref="int"/> range.
    /// </summary>
    /// <param name="value">The seed <see cref="int"/> value.</param>
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

    /// <summary>
    /// Tests that a <see cref="SecureBigInteger"/> built from a <see cref="long"/> seed,
    /// serialised through <see cref="SecureBigInteger.ToByteArray()"/>, and rebuilt via
    /// the byte-array+length ctor round-trips to the same value across the full
    /// <see cref="long"/> range.
    /// </summary>
    /// <param name="value">The seed <see cref="long"/> value.</param>
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

    /// <summary>
    /// Tests that <see cref="SecureBigInteger.ToByteArray()"/> on a positive value
    /// appends a <c>0x00</c> sentinel when the high bit of the most-significant byte is
    /// set, so consumers that read the bytes as two's-complement interpret the value as
    /// positive. Mirror of
    /// <see cref="Constructor_TwosComplement_PositiveBoundary_PreservesValue"/>.
    /// </summary>
    /// <param name="value">The seed positive value.</param>
    /// <param name="expected">The expected two's-complement little-endian bytes.</param>
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

    /// <summary>
    /// Tests that the <see cref="SecureBigInteger(byte[])"/> ctor preserves positive
    /// boundary values across two's-complement encodings — including the high-bit
    /// boundaries (128, 256, 32768) that require a trailing <c>0x00</c> sentinel.
    /// </summary>
    /// <param name="data">The two's-complement little-endian bytes.</param>
    /// <param name="expected">The expected decoded value.</param>
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

    /// <summary>
    /// Tests that the <see cref="SecureBigInteger(byte[])"/> ctor preserves negative
    /// boundary values across two's-complement encodings — including <c>-1</c> from a
    /// single <c>0xFF</c> byte and from a sign-extended multi-byte run.
    /// </summary>
    /// <param name="data">The two's-complement little-endian bytes.</param>
    /// <param name="expected">The expected decoded negative value.</param>
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

    /// <summary>
    /// Tests that the <see cref="SecureBigInteger(byte[])"/> ctor decodes any all-zero
    /// byte sequence to a canonical zero (<c>IsZero == true</c>, <c>Sign == 0</c>),
    /// regardless of byte-count padding.
    /// </summary>
    /// <param name="data">An all-zero byte sequence.</param>
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

    /// <summary>
    /// Tests that the <see cref="SecureBigInteger(byte[])"/> ctor trims sign-extending
    /// <c>0xFF</c> bytes from a negative value to its canonical magnitude length,
    /// reflected in <see cref="SecureBigInteger.ByteCount"/>.
    /// </summary>
    /// <param name="data">The two's-complement little-endian bytes with sign extension.</param>
    /// <param name="expected">The expected decoded negative value.</param>
    /// <param name="expectedByteCount">The expected canonical byte count after trimming.</param>
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

    /// <summary>
    /// Tests that a multi-byte sign-extended <c>-1</c> (<c>0xFF 0xFF 0xFF</c>) decodes
    /// correctly: it does not report <see cref="SecureBigInteger.IsOne"/>, but its
    /// <see cref="SecureBigInteger.Abs()"/> does.
    /// </summary>
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

    /// <summary>
    /// Tests that <see cref="SecureBigInteger.SerializedByteCount"/> equals
    /// <c>ToByteArray().Length</c> across representative signed values — the contract
    /// the <see cref="SecureBigIntCalculator.ByteCount"/> delegation relies on. The
    /// sentinel rule (append <c>0x00</c> when the magnitude's high-byte MSB is set on
    /// a positive value) is exercised on both single-byte and multi-byte magnitudes.
    /// </summary>
    /// <param name="value">A representative signed value.</param>
    [Theory]
    [InlineData(0L)]
    [InlineData(127L)]
    [InlineData(128L)]
    [InlineData(255L)]
    [InlineData(256L)]
    [InlineData(32767L)]
    [InlineData(32768L)]
    [InlineData(-1L)]
    [InlineData(-128L)]
    [InlineData(-129L)]
    [InlineData(long.MaxValue)]
    [InlineData(long.MinValue)]
    public void SerializedByteCount_MatchesToByteArrayLength(long value)
    {
        // Arrange
        using var num = new SecureBigInteger(value);
        using var bytes = num.ToByteArray();

        // Act & Assert
        Assert.Equal(bytes.Length, num.SerializedByteCount);
    }

    /// <summary>
    /// Tests that reading <see cref="SecureBigInteger.SerializedByteCount"/> after
    /// <see cref="IDisposable.Dispose"/> throws <see cref="ObjectDisposedException"/>.
    /// </summary>
    [Fact]
    public void SerializedByteCount_AfterDispose_ThrowsObjectDisposedException()
    {
        // Arrange
        var num = new SecureBigInteger(42);
        num.Dispose();

        // Act & Assert
        Assert.Throws<ObjectDisposedException>(() => num.SerializedByteCount);
    }

    /// <summary>
    /// Tests that the <see cref="SecureBigInteger(byte[], int, bool)"/> ctor rejects a
    /// negative <c>length</c> with <see cref="ArgumentOutOfRangeException"/> whose
    /// <c>ParamName</c> is <c>"length"</c>.
    /// </summary>
    /// <param name="length">A negative length value.</param>
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

    /// <summary>
    /// Tests that the <see cref="SecureBigInteger(byte[], int)"/> ctor rejects a
    /// negative <c>length</c> with <see cref="ArgumentOutOfRangeException"/> whose
    /// <c>ParamName</c> is <c>"length"</c>.
    /// </summary>
    /// <param name="length">A negative length value.</param>
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

    /// <summary>
    /// Tests that the <see cref="SecureBigInteger(byte[], int, bool)"/> ctor rejects a
    /// <c>length</c> exceeding the underlying array with
    /// <see cref="ArgumentOutOfRangeException"/> (<c>ParamName == "length"</c>).
    /// </summary>
    /// <param name="length">A length exceeding the array size.</param>
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

    /// <summary>
    /// Tests that the <see cref="SecureBigInteger(byte[], int)"/> ctor rejects a
    /// <c>length</c> exceeding the underlying array with
    /// <see cref="ArgumentOutOfRangeException"/> (<c>ParamName == "length"</c>).
    /// </summary>
    /// <param name="length">A length exceeding the array size.</param>
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

    /// <summary>
    /// Tests that the <see cref="SecureBigInteger(byte[], int, bool)"/> ctor with
    /// <c>length == 0</c> and <c>isNegative == false</c> produces a canonical zero.
    /// </summary>
    [Fact]
    public void Constructor_FromByteArrayLengthSign_ZeroLength_IsZero()
    {
        // Arrange
        using var num = new SecureBigInteger(new byte[] { 0xFF, 0xFF }, 0, false);

        // Act & Assert
        Assert.True(num.IsZero);
        Assert.Equal(0, num.Sign);
    }

    /// <summary>
    /// Tests that the <see cref="SecureBigInteger(byte[], int, bool)"/> ctor with
    /// <c>length == 0</c> and <c>isNegative == true</c> still normalises to a canonical
    /// <c>+0</c> — the negative-sign flag is ignored for a magnitude-0 result.
    /// </summary>
    [Fact]
    public void Constructor_FromByteArrayLengthSign_ZeroLengthAndIsNegative_IsZeroWithoutSign()
    {
        // Arrange
        using var num = new SecureBigInteger(new byte[] { 0xFF, 0xFF }, 0, true);

        // Act & Assert
        Assert.True(num.IsZero);
        Assert.Equal(0, num.Sign);
    }

    /// <summary>
    /// Tests that the <see cref="SecureBigInteger(byte[], int)"/> ctor with
    /// <c>length == 0</c> produces a canonical zero.
    /// </summary>
    [Fact]
    public void Constructor_FromByteArrayLength_ZeroLength_IsZero()
    {
        // Arrange
        using var num = new SecureBigInteger(new byte[] { 0xFF, 0xFF }, 0);

        // Act & Assert
        Assert.True(num.IsZero);
        Assert.Equal(0, num.Sign);
    }

    /// <summary>
    /// Regression guard against pinned-buffer leaks on the failure path of
    /// <see cref="SecureBigInteger.FromHexadecimal(PinnedPoolArray{char})"/>: invokes
    /// the parser 100× per invalid input. A regression that drops the
    /// <c>SecureClear</c> on throw shows up as a memory leak in the test harness.
    /// </summary>
    /// <param name="invalidHex">A hex string that must be rejected.</param>
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

    /// <summary>
    /// Tests that <see cref="SecureBigInteger.FromHexadecimal(PinnedPoolArray{char})"/>
    /// accepts mixed-case hex literals — companion to the invalid-char test, preserved
    /// as a regression guard against future tightening that might re-reject mixed-case.
    /// </summary>
    /// <param name="hexValue">A mixed-case hex literal.</param>
    /// <param name="expectedValue">The expected decoded value.</param>
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

    /// <summary>
    /// Regression guard that <see cref="SecureBigInteger.ToPinnedCharArray()"/> returns
    /// a consistent decimal representation across repeated calls — no internal state
    /// is corrupted by a previous emit.
    /// </summary>
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

    /// <summary>
    /// Tests that <see cref="SecureBigInteger.FromHexadecimal(PinnedPoolArray{char})"/>
    /// rejects a <see langword="null"/> input with <see cref="ArgumentNullException"/>.
    /// </summary>
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

    /// <summary>
    /// Tests that <see cref="SecureBigInteger.FromHexadecimal(PinnedPoolArray{char})"/>
    /// rejects an empty pinned buffer with <see cref="ArgumentException"/>.
    /// </summary>
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

    /// <summary>
    /// Tests that <see cref="SecureBigInteger.FromHexadecimal(PinnedPoolArray{char})"/>
    /// rejects a sign-only input (<c>"-"</c>, <c>"+"</c>) with
    /// <see cref="FormatException"/> — at least one hex digit is required.
    /// </summary>
    /// <param name="signOnly">A sign character with no trailing digits.</param>
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

    /// <summary>
    /// Tests that <see cref="SecureBigInteger.FromHexadecimal(PinnedPoolArray{char})"/>
    /// supports odd-length input per the API contract: the leading hex character
    /// represents the low nibble of the most-significant byte.
    /// </summary>
    /// <param name="oddHex">An odd-length hex literal.</param>
    /// <param name="expectedValue">The expected decoded value.</param>
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

    /// <summary>
    /// Tests that <see cref="SecureBigInteger.FromHexadecimal(PinnedPoolArray{char})"/>
    /// honours a leading <c>+</c> or <c>-</c> sign — <c>+</c> is accepted for symmetry
    /// with <c>-</c> per the convention of the (now-removed) decimal ctor.
    /// </summary>
    /// <param name="signedHex">A signed hex literal.</param>
    /// <param name="expectedValue">The expected decoded value.</param>
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

    /// <summary>
    /// Tests that <see cref="SecureBigInteger.FromHexadecimal(PinnedPoolArray{char})"/>
    /// accepts an optional <c>0x</c> / <c>0X</c> base prefix — the same magnitude must
    /// parse identically with or without the prefix and across leading-zero variations.
    /// Sign + prefix combinations are also exercised.
    /// </summary>
    /// <param name="hexInput">A hex literal with or without prefix and sign.</param>
    /// <param name="expectedValue">The expected decoded value.</param>
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

    /// <summary>
    /// Tests that <see cref="SecureBigInteger.FromHexadecimal(PinnedPoolArray{char})"/>
    /// rejects the <c>0x</c> / <c>0X</c> prefix without trailing digits with
    /// <see cref="FormatException"/> — mirroring the sign-without-digits rule.
    /// </summary>
    /// <param name="input">A prefix-only hex literal.</param>
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

    /// <summary>
    /// Round-trip test: every value <see cref="SecureBigInteger.ToHexadecimal()"/> can
    /// emit must be parsed back to the same value by
    /// <see cref="SecureBigInteger.FromHexadecimal(PinnedPoolArray{char})"/>. Values
    /// span sign, single-byte, multi-byte, and a Mersenne-shaped value at the M127
    /// boundary.
    /// </summary>
    /// <param name="decimalValue">The decimal representation of the seed value.</param>
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
    [InlineData(TestData.M127Decimal)]
    [InlineData(TestData.M127NegDecimal)]
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

    /// <summary>
    /// Cross-checks <see cref="SecureBigInteger.MersenneModulo(int)"/> against the
    /// generic Modulo (= <c>Remainder</c>) path for representative Mersenne exponents
    /// and operand magnitudes. Operand values exercised: zero, one, p−1 bits set,
    /// exact <c>M_p</c>, <c>M_p + 1</c> (≡ 1), <c>2·M_p</c> (≡ <c>M_p</c>), and a
    /// 2p-bit value (post-multiply scale).
    /// </summary>
    /// <param name="exponent">The Mersenne prime exponent.</param>
    /// <param name="operandDecimal">Decimal representation of the operand.</param>
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
    [InlineData(127, TestData.M127Decimal)]
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

    /// <summary>
    /// Tests that <see cref="SecureBigInteger.MersenneModulo(int)"/> rejects a
    /// non-positive exponent (<c>0</c> or negative) with
    /// <see cref="ArgumentOutOfRangeException"/>.
    /// </summary>
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

    /// <summary>
    /// Tests <see cref="SecureBigInteger.MersenneModulo(int)"/> with negative operands:
    /// the result is the canonical non-negative representative in <c>[0, M_p − 1]</c>,
    /// computed via <c>((operand % M_p) + M_p) % M_p</c> on the BCL side and
    /// cross-checked against the limb-CT path. The all-zero-after-mod corner case
    /// (<c>-M_p</c>, <c>-2·M_p</c>, ...) must canonicalise back to <c>0</c> and is
    /// tested alongside the typical <c>M_p − residue</c> pattern.
    /// </summary>
    /// <param name="exponent">The Mersenne prime exponent.</param>
    /// <param name="operandDecimal">Decimal representation of the negative operand.</param>
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
    [InlineData(127, TestData.M127NegDecimal)]
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