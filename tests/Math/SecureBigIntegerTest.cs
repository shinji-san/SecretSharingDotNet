// ----------------------------------------------------------------------------
// <copyright file="SecureBigInteger.cs" company="Private">
// Copyright (c) 2024 All Rights Reserved
// </copyright>
// <author>Sebastian Walther</author>
// <date>04/01/2024 07:34:00 PM</date>
// ----------------------------------------------------------------------------

#region License

// ----------------------------------------------------------------------------
// Copyright 2024 Sebastian Walther
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

#if NET6_0_OR_GREATER
namespace SecretSharingDotNetTest.Math;

using SecretSharingDotNet.Helper;
using SecretSharingDotNet.Math;
using System;
using System.Globalization;
using System.Numerics;
using System.Runtime.InteropServices;
using Xunit;

public sealed class SecureBigIntegerTest : IDisposable
{
    private readonly Scope scope;
    private bool disposed;

    public SecureBigIntegerTest()
    {
        this.scope = new Scope();
        var compositeDisposable = this.scope.GetScopedSingleton<CompositeDisposable>();
        CompositeDisposableContext.SetCurrent(compositeDisposable);
    }
    
    ~SecureBigIntegerTest()
    {
        this.Dispose(false);
    }
    
    public void Dispose()
    {
        this.Dispose(true);
        GC.SuppressFinalize(this);
    }
    
    private void Dispose(bool disposing)
    {
        if (this.disposed)
        {
            return;
        }
        
        if (disposing)
        {
            this.scope?.Dispose();
        }
        
        this.disposed = true;
    }
    
    [Fact]
    public void Dispose_SetsIsDisposedToTrue()
    {
        // Arrange
        var secureBigInteger = new SecureBigInteger(42);

        // Act
        secureBigInteger.Dispose();

        // Assert
        Assert.True(secureBigInteger.IsDisposed);
    }

    [Fact]
    public void Dispose_MultipleCallsToDispose_DoesNotThrowException()
    {
        // Arrange
        var secureBigInteger = new SecureBigInteger(42);

        // Act
        secureBigInteger.Dispose();
        secureBigInteger.Dispose();
        secureBigInteger.Dispose();
    }

    [Fact]
    public void Constructor_WithByteArrayOrSpan_CreatesInstance()
    {
        // Arrange
        byte[] value = BitConverter.GetBytes(42);

        // Act
        using var secureBigInteger = new SecureBigInteger(value);

        // Assert
        Assert.Equal(42.ToString(), secureBigInteger.ToString());
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(7)]
    [InlineData(ulong.MaxValue)]
    [InlineData(long.MaxValue)]
    [InlineData(long.MinValue)]
    [InlineData(500000000000122)]
    [InlineData(-500000000000122)]
    public void Constructor_WithBigInteger_CreatesInstance(BigInteger value)
    {
        // Arrange & Act
        using var secureBigInteger = new SecureBigInteger(value);

        // Assert
        Assert.Equal(value.ToString(), secureBigInteger.ToString());
    }

    [Theory]
    [InlineData(uint.MinValue)]
    [InlineData(1)]
    [InlineData(7)]
    [InlineData(uint.MaxValue)]
    public void Constructor_WithUInt_CreatesInstance(uint value)
    {
        // Arrange & Act
        using var secureBigInteger = new SecureBigInteger(value);

        // Assert
        Assert.Equal(value.ToString(), secureBigInteger.ToString());
    }

    [Theory]
    [InlineData(ulong.MinValue)]
    [InlineData(1)]
    [InlineData(7)]
    [InlineData(ulong.MaxValue)]
    public void Constructor_WithULong_CreatesInstance(ulong value)
    {
        // Arrange & Act
        using var secureBigInteger = new SecureBigInteger(value);

        // Assert
        Assert.Equal(value.ToString(), secureBigInteger.ToString());
    }

    [Theory]
    [InlineData(0)]
    [InlineData(42)]
    [InlineData(-42)]
    [InlineData(int.MinValue)]
    [InlineData(int.MaxValue)]
    public void Constructor_WithInt_CreatesInstance(int value)
    {
        // Arrange & Act
        using var secureBigInteger = new SecureBigInteger(value);

        // Assert
        Assert.Equal(value.ToString(), secureBigInteger.ToString());
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(7)]
    [InlineData(long.MaxValue)]
    [InlineData(long.MinValue + 1)]
    public void Constructor_WithLong_CreatesInstance(long value)
    {
        // Arrange & Act
        using var secureBigInteger = new SecureBigInteger(value);

        // Assert
        Assert.Equal(value.ToString(), secureBigInteger.ToString());
    }

    [Theory]
    [InlineData(0, "0")]
    [InlineData(1, "1")]
    [InlineData(7, "7")]
    [InlineData(42, "42")]
    [InlineData(long.MaxValue, "9223372036854775807")]
    [InlineData(long.MinValue + 1 , "-9223372036854775807")]
    public void ToString_ReturnsStringRepresentationOfSecureBigInteger(long value, string expected)
    {
        // Arrange
        using var secureBigInteger = new SecureBigInteger(value);

        // Act
        string result = secureBigInteger.ToString();

        // Assert
        Assert.Equal(expected, result);
    }

    [Fact]
    public void IsZero_ReturnsTrue_IfBigIntegerIsZero()
    {
        // Arrange
        using var secureBigInteger = new SecureBigInteger(0);

        // Act & Assert
        Assert.True(secureBigInteger.IsZero);
    }

    [Fact]
    public void IsZero_ReturnsFalse_IfBigIntegerIsNotZero()
    {
        // Arrange
        using var secureBigInteger = new SecureBigInteger(1);

        // Act & Assert
        Assert.False(secureBigInteger.IsZero);
    }

    [Fact]
    public void IsOne_ReturnsTrue_IfBigIntegerIsOne()
    {
        // Arrange
        using var secureBigInteger = new SecureBigInteger(1);

        // Act & Assert
        Assert.True(secureBigInteger.IsOne);
    }

    [Fact]
    public void IsEven_ReturnsTrue_IfBigIntegerIsEven()
    {
        // Arrange
        using var secureBigInteger = new SecureBigInteger(2);

        // Act & Assert
        Assert.True(secureBigInteger.IsEven);
    }

    [Fact]
    public void IsEven_ReturnsFalse_IfBigIntegerIsNotEven()
    {
        // Arrange
        using var secureBigInteger = new SecureBigInteger(3);

        // Act & Assert
        Assert.False(secureBigInteger.IsEven);
    }

    [Fact]
    public void IsOdd_ReturnsTrue_IfBigIntegerIsOdd()
    {
        using var secureBigInteger = new SecureBigInteger(3);
        Assert.True(secureBigInteger.IsOdd);
    }

    [Fact]
    public void IsOdd_ReturnsFalse_IfBigIntegerIsNotOdd()
    {
        // Arrange
        using var secureBigInteger = new SecureBigInteger(2);

        // Act & Assert
        Assert.False(secureBigInteger.IsOdd);
    }

    [Theory]
    [InlineData(int.MinValue, int.MaxValue, -1)]
    [InlineData(-1, 1, 0)]
    [InlineData(0, 0, 0)]
    [InlineData(1, 2, 3)]
    [InlineData(2, 3, 5)]
    [InlineData(3, 4, 7)]
    [InlineData(500, -200, 300)]
    [InlineData(-500, -200, -700)]
    [InlineData(-500, 200, -300)]
    [InlineData(int.MaxValue, int.MaxValue, 4294967294)]
    public void Add_WithIntegers(int a, int b, object expected)
    {
        // Arrange
        using var secureBigInteger1 = new SecureBigInteger(a);
        using var secureBigInteger2 = new SecureBigInteger(b);

        // Act
        using var result = secureBigInteger1 + secureBigInteger2;

        // Assert
        Assert.Equal(expected.ToString(), result.ToString());
    }

    [Theory]
    [InlineData(1, 2, 3)]
    [InlineData(2, 3, 5)]
    [InlineData(3, 4, 7)]
    [InlineData(uint.MaxValue, uint.MaxValue, "8589934590")]
    public void Add_WithUnsignedIntegers(uint a, uint b, object expected)
    {
        // Arrange
        using var secureBigInteger1 = new SecureBigInteger(a);
        using var secureBigInteger2 = new SecureBigInteger(b);

        // Act
        using var result = secureBigInteger1 + secureBigInteger2;

        // Assert
        Assert.Equal(expected.ToString(), result.ToString());
    }

    [Theory]
    [InlineData(ulong.MaxValue, ulong.MaxValue, "36893488147419103230")]
    [InlineData(ulong.MaxValue, 1, "18446744073709551616")]
    public void Add_WithUnsignedLongs(ulong a, ulong b, object expected)
    {
        // Arrange
        using var secureBigInteger1 = new SecureBigInteger(a);
        using var secureBigInteger2 = new SecureBigInteger(b);

        // Act
        using var result = secureBigInteger1 + secureBigInteger2;

        // Assert
        Assert.Equal(expected.ToString(), result.ToString());
    }

    [Theory]
    [InlineData(ulong.MaxValue, ulong.MaxValue, "0")]
    [InlineData(ulong.MaxValue, long.MaxValue, "9223372036854775808")]
    [InlineData(ulong.MaxValue, 1, "18446744073709551614")]
    public void Subtract_WithUnsignedLongs(ulong a, ulong b, object expected)
    {
        // Arrange
        using var secureBigInteger1 = new SecureBigInteger(a);
        using var secureBigInteger2 = new SecureBigInteger(b);

        // Act
        using var result = secureBigInteger1 - secureBigInteger2;

        // Assert
        Assert.Equal(expected.ToString(), result.ToString());
    }

    [Theory]
    [InlineData(2, 1, 1)]
    [InlineData(3, 2, 1)]
    [InlineData(4, 3, 1)]
    [InlineData(int.MaxValue, int.MaxValue, 0)]
    [InlineData(int.MaxValue, 1, 2147483646)]
    [InlineData(int.MaxValue, int.MinValue, 4294967295)]
    [InlineData(500, 200, 300)]
    [InlineData(500, -200, 700)]
    [InlineData(-500, -200, -300)]
    public void Subtract_WithIntegers(int a, int b, object expected)
    {
        // Arrange
        using var secureBigInteger1 = new SecureBigInteger(a);
        using var secureBigInteger2 = new SecureBigInteger(b);

        // Act
        using var result = secureBigInteger1 - secureBigInteger2;

        // Assert
        Assert.Equal(expected.ToString(), result.ToString());
    }

    [Theory]
    [InlineData(255, 1, 254)]
    [InlineData(uint.MaxValue, uint.MaxValue, 0)]
    [InlineData(uint.MaxValue, int.MaxValue, 2147483648)]
    public void Subtract_WithUnsignedIntegers(uint a, uint b, object expected)
    {
        // Arrange
        using var secureBigInteger1 = new SecureBigInteger(a);
        using var secureBigInteger2 = new SecureBigInteger(b);

        // Act
        using var result = secureBigInteger1 - secureBigInteger2;

        // Assert
        Assert.Equal(expected.ToString(), result.ToString());
    }

    [Theory]
    [InlineData(long.MaxValue, long.MaxValue, 0)]
    [InlineData(long.MaxValue, 1, 9223372036854775806)]
    public void Subtract_WithLongs(long a, long b, object expected)
    {
        // Arrange
        using var secureBigInteger1 = new SecureBigInteger(a);
        using var secureBigInteger2 = new SecureBigInteger(b);

        // Act
        using var result = secureBigInteger1 - secureBigInteger2;

        // Assert
        Assert.Equal(expected.ToString(), result.ToString());
    }

    [Theory]
    [InlineData(2, 3, 6)]
    [InlineData(3, 4, 12)]
    [InlineData(4, 5, 20)]
    [InlineData(int.MaxValue, int.MaxValue, 4611686014132420609)]
    [InlineData(int.MaxValue, 1, 2147483647)]
    [InlineData(int.MaxValue, int.MinValue, -4611686016279904256)]
    public void Multiply_WithIntegers(int a, int b, object expected)
    {
        // Arrange
        using var secureBigInteger1 = new SecureBigInteger(a);
        using var secureBigInteger2 = new SecureBigInteger(b);

        // Act
        using var result = secureBigInteger1 * secureBigInteger2;

        // Assert
        Assert.Equal(expected.ToString(), result.ToString());
    }

    [Theory]
    [InlineData(2, 3, 6)]
    [InlineData(3, 4, 12)]
    [InlineData(4, 5, 20)]
    [InlineData(uint.MaxValue, uint.MaxValue, "18446744065119617025")]
    public void Multiply_WithUnsignedIntegers(uint a, uint b, object expected)
    {
        // Arrange
        using var secureBigInteger1 = new SecureBigInteger(a);
        using var secureBigInteger2 = new SecureBigInteger(b);

        // Act
        using var result = secureBigInteger1 * secureBigInteger2;

        // Assert
        Assert.Equal(expected.ToString(), result.ToString());
    }

    [Theory]
    [InlineData(2, 3, 6)]
    [InlineData(3, 4, 12)]
    [InlineData(4, 5, 20)]
    [InlineData(long.MaxValue, long.MaxValue, "85070591730234615847396907784232501249")]
    [InlineData(long.MaxValue, 1, "9223372036854775807")]
    [InlineData(long.MaxValue, -1, "-9223372036854775807")]
    [InlineData(long.MaxValue, long.MinValue + 1, "-85070591730234615847396907784232501249")]
    public void Multiply_WithLongs(long a, long b, object expected)
    {
        // Arrange
        using var secureBigInteger1 = new SecureBigInteger(a);
        using var secureBigInteger2 = new SecureBigInteger(b);

        // Act
        using var result = secureBigInteger1 * secureBigInteger2;

        // Assert
        Assert.Equal(expected.ToString(), result.ToString());
    }

    [Theory]
    [InlineData(2, 3, 6)]
    [InlineData(3, 4, 12)]
    [InlineData(4, 5, 20)]
    [InlineData(ulong.MaxValue, ulong.MaxValue, "340282366920938463426481119284349108225")]
    [InlineData(ulong.MaxValue, 1, "18446744073709551615")]
    public void Multiply_WithUnsignedLongs(ulong a, ulong b, object expected)
    {
        // Arrange
        using var secureBigInteger1 = new SecureBigInteger(a);
        using var secureBigInteger2 = new SecureBigInteger(b);

        // Act
        using var result = secureBigInteger1 * secureBigInteger2;

        // Assert
        Assert.Equal(expected.ToString(), result.ToString());
    }

    [Theory]
    [InlineData(2, 3, 0)]
    [InlineData(3, 4, 0)]
    [InlineData(4, 5, 0)]
    [InlineData(4, 3, 1)]
    [InlineData(4, -2, -2)]
    [InlineData(int.MaxValue, int.MaxValue, 1)]
    [InlineData(int.MaxValue, 1, 2147483647)]
    [InlineData(int.MaxValue, -1, -2147483647)]
    [InlineData(int.MaxValue, int.MinValue, 0)]
    [InlineData(500, 200, 2)]
    [InlineData(500, -200, -2)]
    [InlineData(-1200, -400, 3)]
    [InlineData(644, 7, 92)]
    public void Divide_WithIntegers(int a, int b, object expected)
    {
        // Arrange
        using var secureBigInteger1 = new SecureBigInteger(a);
        using var secureBigInteger2 = new SecureBigInteger(b);

        // Act
        using var result = secureBigInteger1 / secureBigInteger2;

        // Assert
        Assert.Equal(expected.ToString(), result.ToString());
    }

    [Theory]
    [InlineData(2, 3, 0)]
    [InlineData(3, 4, 0)]
    [InlineData(4, 5, 0)]
    [InlineData(4, 3, 1)]
    [InlineData(4, 2, 2)]
    [InlineData(uint.MaxValue, uint.MaxValue, 1)]
    [InlineData(uint.MaxValue, 1, 4294967295)]
    public void Divide_WithUnsignedIntegers(uint a, uint b, object expected)
    {
        // Arrange
        using var secureBigInteger1 = new SecureBigInteger(a);
        using var secureBigInteger2 = new SecureBigInteger(b);

        // Act
        using var result = secureBigInteger1 / secureBigInteger2;

        // Assert
        Assert.Equal(expected.ToString(), result.ToString());
    }

    [Theory]
    [InlineData(2, 3, 0)]
    [InlineData(3, 4, 0)]
    [InlineData(4, 5, 0)]
    [InlineData(4, 3, 1)]
    [InlineData(4, 2, 2)]
    [InlineData(long.MaxValue, long.MaxValue, 1)]
    [InlineData(long.MaxValue, 1, 9223372036854775807)]
    [InlineData(long.MaxValue, -1, -9223372036854775807)]
    [InlineData(long.MaxValue, long.MinValue + 1, -1)]
    public void Divide_WithLongs(long a, long b, object expected)
    {
        // Arrange
        using var secureBigInteger1 = new SecureBigInteger(a);
        using var secureBigInteger2 = new SecureBigInteger(b);

        // Act
        using var result = secureBigInteger1 / secureBigInteger2;

        // Assert
        Assert.Equal(expected.ToString(), result.ToString());
    }

    [Theory]
    [InlineData(2, 3, 0)]
    [InlineData(3, 4, 0)]
    [InlineData(4, 5, 0)]
    [InlineData(4, 3, 1)]
    [InlineData(4, 2, 2)]
    [InlineData(ulong.MaxValue, ulong.MaxValue, 1)]
    [InlineData(ulong.MaxValue, 1, 18446744073709551615)]
    [InlineData(ulong.MaxValue, 2, 9223372036854775807)]
    public void Divide_WithUnsignedLongs(ulong a, ulong b, object expected)
    {
        // Arrange
        using var secureBigInteger1 = new SecureBigInteger(a);
        using var secureBigInteger2 = new SecureBigInteger(b);

        // Act
        using var result = secureBigInteger1 / secureBigInteger2;

        // Assert
        Assert.Equal(expected.ToString(), result.ToString());
    }
    
    [Theory]
    [InlineData("-3835255132460882789166558313013993180345974142956602990091834073659135360342051453609559904418337272107499204961198273", "170141183460469231731687303715884105727", "-29190816759278638212969385224164168518")]
    [InlineData("3835255132460882789166558313013993180345974142956602990091834073659135360342051453609559904418337272107499204961198273", "170141183460469231731687303715884105727", "29190816759278638212969385224164168518")]
    public void Modulo_WithString(string a, string b, string expected)
    {
        // Arrange
        using var secureBigInteger1 = SecureBigInteger.Parse(a, CultureInfo.InvariantCulture);
        using var secureBigInteger2 = SecureBigInteger.Parse(b, CultureInfo.InvariantCulture);

        // Act
        using var result = secureBigInteger1 % secureBigInteger2;

        // Assert
        Assert.Equal(expected, result.ToString());
    }

    [Theory]
    [InlineData(2, 3, 2)]
    [InlineData(3, 4, 3)]
    [InlineData(4, 5, 4)]
    [InlineData(4, 3, 1)]
    [InlineData(4, 2, 0)]
    [InlineData(4, -2, 0)]
    [InlineData(5, 3, 2)]
    [InlineData(5, -3, 2)]
    [InlineData(6, 3, 0)]
    [InlineData(6, -3, 0)]
    [InlineData(int.MaxValue, int.MaxValue, 0)]
    [InlineData(int.MaxValue, 1, 0)]
    [InlineData(int.MaxValue, -1, 0)]
    [InlineData(int.MaxValue, int.MinValue, 2147483647)]
    public void Modulus_WithIntegers(int a, int b, object expected)
    {
        // Arrange
        using var secureBigInteger1 = new SecureBigInteger(a);
        using var secureBigInteger2 = new SecureBigInteger(b);

        // Act
        using var result = secureBigInteger1 % secureBigInteger2;

        // Assert
        Assert.Equal(expected.ToString(), result.ToString());
    }

    [Theory]
    [InlineData(2, 3, 2)]
    [InlineData(3, 4, 3)]
    [InlineData(4, 5, 4)]
    [InlineData(4, 3, 1)]
    [InlineData(4, 2, 0)]
    [InlineData(5, 3, 2)]
    [InlineData(6, 3, 0)]
    [InlineData(uint.MaxValue, uint.MaxValue, 0)]
    [InlineData(uint.MaxValue, 1, 0)]
    public void Modulus_WithUnsignedIntegers(uint a, uint b, object expected)
    {
        // Arrange
        using var secureBigInteger1 = new SecureBigInteger(a);
        using var secureBigInteger2 = new SecureBigInteger(b);

        // Act
        using var result = secureBigInteger1 % secureBigInteger2;

        // Assert
        Assert.Equal(expected.ToString(), result.ToString());
    }

    [Theory]
    [InlineData(2, 3, 2)]
    [InlineData(3, 4, 3)]
    [InlineData(4, 5, 4)]
    [InlineData(4, 3, 1)]
    [InlineData(4, 2, 0)]
    [InlineData(5, 3, 2)]
    [InlineData(6, 3, 0)]
    [InlineData(long.MaxValue, long.MaxValue, 0)]
    [InlineData(long.MaxValue, 1, 0)]
    [InlineData(long.MaxValue, -1, 0)]
    [InlineData(long.MaxValue, long.MinValue + 1, 0)]
    [InlineData(long.MinValue + 1, long.MinValue + 1, 0)]
    public void Modulus_WithLongs(long a, long b, object expected)
    {
        // Arrange
        using var secureBigInteger1 = new SecureBigInteger(a);
        using var secureBigInteger2 = new SecureBigInteger(b);

        // Act
        using var result = secureBigInteger1 % secureBigInteger2;

        // Assert
        Assert.Equal(expected.ToString(), result.ToString());
    }

    [Theory]
    [InlineData(ulong.MaxValue, 20, 15)]
    [InlineData(ulong.MaxValue, 1, 0)]
    [InlineData(ulong.MaxValue, 2, 1)]
    [InlineData(ulong.MaxValue, 3, 0)]
    public void Modulus_WithUnsignedLongs(ulong a, ulong b, object expected)
    {
        // Arrange
        using var secureBigInteger1 = new SecureBigInteger(a);
        using var secureBigInteger2 = new SecureBigInteger(b);

        // Act
        using var result = secureBigInteger1 % secureBigInteger2;

        // Assert
        Assert.Equal(expected.ToString(), result.ToString());
    }

    [Theory]
    [InlineData(2, 3, 8)]
    [InlineData(3, 4, 81)]
    public void Pow_WithIntegers(int value, int exponent, object expected)
    {
        // Arrange
        using var secureBigInteger1 = new SecureBigInteger(value);

        // Act
        using var result = secureBigInteger1.Pow(exponent);

        // Assert
        Assert.Equal(expected.ToString(), result.ToString());
    }

    [Theory]
    [InlineData(4, 2, "16")]
    [InlineData(9, 3, "729")]
    public void Pow_WithUnsignedIntegers(uint value, int exponent, object expected)
    {
        // Arrange
        using var secureBigInteger1 = new SecureBigInteger(value);

        // Act
        using var result = secureBigInteger1.Pow(exponent);

        // Assert
        Assert.Equal(expected.ToString(), result.ToString());
    }

    [Theory]
    [InlineData(4, 2, "16")]
    [InlineData(9, 3, "729")]
    [InlineData(-3, 3, "-27")]
    public void Pow_WithLongs(long value, int exponent, object expected)
    {
        // Arrange
        using var secureBigInteger1 = new SecureBigInteger(value);

        // Act
        using var result = secureBigInteger1.Pow(exponent);

        // Assert
        Assert.Equal(expected.ToString(), result.ToString());
    }

    [Theory]
    [InlineData(ulong.MaxValue, 20,
        "20815864389328798141281875261654240038739993424404242425506079834368643384699815883993519000403222895708748681674793449344690890447908431885920079592739573615444805397570578729330039130716069497833623971831833817007046404500291336909466015568610844462737800901333746167215795959142314612138881715678958017183473735270054778324841160160808023792415691149633568863714992256259918212890625")]
    [InlineData(ulong.MaxValue, 1, ulong.MaxValue)]
    [InlineData(2, 10, 1024)]
    [InlineData(2, 20, 1048576)]
    [InlineData(ulong.MaxValue, 2, "340282366920938463426481119284349108225")]
    [InlineData(ulong.MaxValue, 3, "6277101735386680762814942322444851025767571854389858533375")]
    public void Pow_WithUnsignedLongs(ulong value, int exponent, object expected)
    {
        // Arrange
        using var secureBigInteger1 = new SecureBigInteger(value);

        // Act
        using var result = secureBigInteger1.Pow(exponent);

        // Assert
        Assert.Equal(expected.ToString(), result.ToString());
    }

    [Theory]
    [InlineData(4, 2)]
    [InlineData(9, 3)]
    [InlineData(16, 4)]
    [InlineData(25, 5)]
    [InlineData(36, 6)]
    [InlineData(int.MaxValue, 46340)]
    public void SquareRoot_WithUnsignedIntegers(uint value, object expected)
    {
        // Arrange
        using var secureBigInteger1 = new SecureBigInteger(value);

        // Act
        using var result = secureBigInteger1.SquareRoot();

        // Assert
        var x = (ulong)Math.Sqrt(int.MaxValue);
        Assert.Equal(expected.ToString(), result.ToString());
    }

    [Theory]
    [InlineData(4, 2)]
    [InlineData(9, 3)]
    [InlineData(16, 4)]
    [InlineData(25, 5)]
    [InlineData(36, 6)]
    [InlineData(long.MaxValue, "3037000499")]
    public void SquareRoot_WithLongs(long value, object expected)
    {
        // Arrange
        using var secureBigInteger1 = new SecureBigInteger(value);

        // Act
        using var result = secureBigInteger1.SquareRoot();

        // Assert
        Assert.Equal(expected.ToString(), result.ToString());
    }

    [Theory]
    [InlineData(ulong.MaxValue, "4294967295")]
    public void SquareRoot_WithUnsignedLongs(ulong value, object expected)
    {
        // Arrange
        using var secureBigInteger1 = new SecureBigInteger(value);

        // Act
        using var result = secureBigInteger1.SquareRoot();

        // Assert
        Assert.Equal(expected.ToString(), result.ToString());
    }

    [Fact]
    public void ToByteSpan_ReturnsByteSpan()
    {
        // Arrange
        using var secureBigInteger = new SecureBigInteger(2);

        // Act
        var result = secureBigInteger.ToByteSpan();
        using var resultBigInteger = new SecureBigInteger(result);

        // Assert
        Assert.Equal(2.ToString(), resultBigInteger.ToString());
    }

    [Theory]
    [InlineData(2, 3)]
    [InlineData(3, 4)]
    [InlineData(4, 5)]
    [InlineData(int.MaxValue, (long)int.MaxValue + 1)]
    [InlineData(-5, -4)]
    public void Increment_WithIntegers(int value, object expected)
    {
        SecureBigInteger secureBigInteger = null;
        try
        {
            // Arrange
            secureBigInteger = new SecureBigInteger(value);

            // Act
            secureBigInteger++;

            // Assert
            Assert.Equal(expected.ToString(), secureBigInteger.ToString());
        }
        finally
        {
            secureBigInteger?.Dispose();
        }
    }

    [Theory]
    [InlineData(2, 1)]
    [InlineData(3, 2)]
    [InlineData(4, 3)]
    [InlineData(-4, -5)]
    [InlineData(int.MinValue, (long)int.MinValue - 1)]
    public void Decrement_WithIntegers(int value, object expected)
    {
        SecureBigInteger secureBigInteger = null;
        try
        {
            // Arrange
            secureBigInteger = new SecureBigInteger(value);

            // Act
            secureBigInteger--;

            // Assert
            Assert.Equal(expected.ToString(), secureBigInteger.ToString());
        }
        finally
        {
            secureBigInteger?.Dispose();
        }
    }

    [Theory]
    [InlineData(3, 2)]
    [InlineData(4, 3)]
    [InlineData(5, 4)]
    [InlineData(0, long.MinValue + 1)]
    [InlineData(-1, long.MinValue + 1)]
    [InlineData(9223372036854775807, 9223372034707292160)]
    public void GreaterThan_WithLongs(long a, long b)
    {
        // Arrange
        using var secureBigInteger1 = new SecureBigInteger(a);
        using var secureBigInteger2 = new SecureBigInteger(b);

        // Act & Assert
        Assert.True(secureBigInteger1 > secureBigInteger2);
    }

    [Theory]
    [InlineData(2, 3)]
    [InlineData(3, 4)]
    [InlineData(4, 5)]
    [InlineData(long.MaxValue - 1, long.MaxValue)]
    [InlineData(long.MinValue + 1, long.MaxValue)]
    [InlineData(long.MinValue + 1, -1)]
    [InlineData(9223372034707292160, 9223372036854775807)]
    public void LessThan(long a, long b)
    {
        // Arrange
        using var secureBigInteger1 = new SecureBigInteger(a);
        using var secureBigInteger2 = new SecureBigInteger(b);

        // Act & Assert
        Assert.True(secureBigInteger1 < secureBigInteger2);
    }

    [Theory]
    [InlineData(3, 2)]
    [InlineData(4, 3)]
    [InlineData(5, 4)]
    [InlineData(0, long.MinValue + 1)]
    [InlineData(-1, long.MinValue + 1)]
    [InlineData(9223372036854775807, 9223372034707292160)]
    [InlineData(0, 0)]
    [InlineData(5, 5)]
    [InlineData(-4, -4)]
    public void GreaterThanOrEqual_WithLongs(long a, long b)
    {
        // Arrange
        using var secureBigInteger1 = new SecureBigInteger(a);
        using var secureBigInteger2 = new SecureBigInteger(b);

        // Act & Assert
        Assert.True(secureBigInteger1 >= secureBigInteger2);
    }

    [Theory]
    [InlineData(2, 3)]
    [InlineData(3, 4)]
    [InlineData(4, 5)]
    [InlineData(long.MaxValue - 1, long.MaxValue)]
    [InlineData(long.MinValue + 1, long.MaxValue)]
    [InlineData(long.MinValue + 1, -1)]
    [InlineData(9223372034707292160, 9223372036854775807)]
    [InlineData(0, 0)]
    [InlineData(5, 5)]
    [InlineData(-4, -4)]
    public void LessThanOrEqual_WithLongs(long a, long b)
    {
        // Arrange
        using var secureBigInteger1 = new SecureBigInteger(a);
        using var secureBigInteger2 = new SecureBigInteger(b);

        // Act & Assert
        Assert.True(secureBigInteger1 <= secureBigInteger2);
    }

    [Theory]
    [InlineData(2, 2)]
    [InlineData(3, 3)]
    [InlineData(4, 4)]
    [InlineData(long.MaxValue, long.MaxValue)]
    [InlineData(long.MinValue + 1, long.MinValue + 1)]
    [InlineData(0, 0)]
    [InlineData(-4, -4)]
    public void Equals_WithLongs_ReturnsTrue(long a, long b)
    {
        // Arrange
        using var secureBigInteger1 = new SecureBigInteger(a);
        using var secureBigInteger2 = new SecureBigInteger(b);

        // Act & Assert
        Assert.True(secureBigInteger1 == secureBigInteger2);
    }
    
    [Theory]
    [InlineData(2, 1)]
    [InlineData(2, 3)]
    [InlineData(3, 2)]
    [InlineData(3, 4)]
    [InlineData(4, 3)]
    [InlineData(4, 5)]
    [InlineData(long.MaxValue, long.MaxValue - 1)]
    [InlineData(long.MinValue + 1, long.MinValue + 2)]
    [InlineData(0, -1)]
    [InlineData(0, 1)]
    [InlineData(-4, -3)]
    [InlineData(-4, -5)]
    [InlineData(-4, 4)]
    public void Equals_WithLongs_ReturnsFalse(long a, long b)
    {
        // Arrange
        using var secureBigInteger1 = new SecureBigInteger(a);
        using var secureBigInteger2 = new SecureBigInteger(b);

        // Act & Assert
        Assert.False(secureBigInteger1 == secureBigInteger2);
    }

    [Theory]
    [InlineData(-5)]
    [InlineData(22223)]
    [InlineData(-22223)]
    [InlineData(long.MinValue + 1)]
    public void Parse_WithLongs(long value)
    {
        // Arrange
        string valueString = value.ToString(CultureInfo.InvariantCulture);

        // Act
        using var secureBigInteger = SecureBigInteger.Parse(valueString, CultureInfo.InvariantCulture);

        // Assert
        Assert.Equal(valueString, secureBigInteger.ToString());
    }
}
#endif