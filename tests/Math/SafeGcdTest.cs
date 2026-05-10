// ----------------------------------------------------------------------------
// <copyright file="SafeGcdTest.cs" company="Private">
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

namespace SecretSharingDotNetTest.Math;

using System;
using SecretSharingDotNet.Math;
using SecretSharingDotNet.Math.Numerics;
using Xunit;

// `BigInteger` and `SecureBigInteger` are sub-namespaces of
// SecretSharingDotNetTest.Math (parallel-test hierarchy convention), so an
// unqualified `BigInteger` would resolve to the namespace, not the BCL type.
// Aliases here pin the BCL type explicitly.
using BclBigInteger = System.Numerics.BigInteger;
using BclSecureBigInteger = SecretSharingDotNet.Math.Numerics.SecureBigInteger;

public class SafeGcdTest
{
    [Theory]
    // Small inputs verifying the divstep algorithm reaches the correct gcd.
    [InlineData("7", "5", "1", 3)]
    [InlineData("7", "14", "7", 3)]
    [InlineData("7", "0", "7", 3)]
    [InlineData("31", "10", "1", 5)]
    [InlineData("127", "100", "1", 7)]
    [InlineData("127", "0", "127", 7)]
    // Inputs with a non-trivial shared factor (f need not be prime).
    [InlineData("15", "10", "5", 4)]
    [InlineData("15", "9", "3", 4)]
    [InlineData("21", "14", "7", 5)]
    // Mersenne-prime moduli — the modular-inverse use case. Mersenne primes
    // are coprime to every value in [1, M_p − 1].
    [InlineData("8191", "12345", "1", 13)]
    [InlineData("8191", "0", "8191", 13)]
    [InlineData("2147483647", "2", "1", 31)]
    [InlineData("2147483647", "999999937", "1", 31)]
    [InlineData("170141183460469231731687303715884105727", "1", "1", 127)]
    [InlineData("170141183460469231731687303715884105727", "3000", "1", 127)]
    [InlineData("170141183460469231731687303715884105727", "0", "170141183460469231731687303715884105727", 127)]
    public void Gcd_MatchesBclBigInteger(string fDec, string gDec, string expectedGcdDec, int bitLengthBound)
    {
        // Arrange
        using var f = BclBigInteger.Parse(fDec).ToSecureBigInteger();
        using var g = BclBigInteger.Parse(gDec).ToSecureBigInteger();
        using var expected = BclBigInteger.Parse(expectedGcdDec).ToSecureBigInteger();

        // Act
        using var actual = SafeGcd.Gcd(f, g, bitLengthBound);

        // Assert
        Assert.Equal(expected, actual);
    }

    [Fact]
    public void Gcd_FInputNull_ThrowsArgumentNullException()
    {
        // Arrange
        using var g = new BclSecureBigInteger(5);

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() =>
        {
            using var _ = SafeGcd.Gcd(null!, g, 8);
        });
    }

    [Fact]
    public void Gcd_GInputNull_ThrowsArgumentNullException()
    {
        // Arrange
        using var f = new BclSecureBigInteger(7);

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() =>
        {
            using var _ = SafeGcd.Gcd(f, null!, 8);
        });
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    public void Gcd_NonPositiveBitLengthBound_ThrowsArgumentOutOfRangeException(int bitLengthBound)
    {
        // Arrange
        using var f = new BclSecureBigInteger(7);
        using var g = new BclSecureBigInteger(5);

        // Act & Assert
        Assert.Throws<ArgumentOutOfRangeException>(() =>
        {
            using var _ = SafeGcd.Gcd(f, g, bitLengthBound);
        });
    }

    [Theory]
    // f must be positive and odd: zero, negative, and even values are rejected.
    [InlineData(0)]
    [InlineData(-7)]
    [InlineData(8)]
    public void Gcd_InvalidF_ThrowsArgumentException(int fValue)
    {
        // Arrange
        using var f = new BclSecureBigInteger(fValue);
        using var g = new BclSecureBigInteger(5);

        // Act
        var ex = Assert.Throws<ArgumentException>(() =>
        {
            using var _ = SafeGcd.Gcd(f, g, 8);
        });

        // Assert
        Assert.Equal("fInput", ex.ParamName);
    }

    [Fact]
    public void Gcd_NegativeG_ThrowsArgumentException()
    {
        // Arrange
        using var f = new BclSecureBigInteger(7);
        using var g = new BclSecureBigInteger(-1);

        // Act
        var ex = Assert.Throws<ArgumentException>(() =>
        {
            using var _ = SafeGcd.Gcd(f, g, 8);
        });

        // Assert
        Assert.Equal("gInput", ex.ParamName);
    }

    [Theory]
    // Verifies the integer-form Bezout identity:
    //   alpha * fInput + beta * gInput = 2^iterationCount * gcd
    // for representative inputs across small primes, common-factor pairs,
    // and Mersenne-prime moduli (M_3, M_5, M_13, M_31).
    [InlineData("7", "5", 3)]
    [InlineData("7", "0", 3)]
    [InlineData("31", "10", 5)]
    [InlineData("31", "30", 5)]
    [InlineData("127", "100", 7)]
    [InlineData("127", "1", 7)]
    [InlineData("15", "10", 4)]
    [InlineData("15", "9", 4)]
    [InlineData("21", "14", 5)]
    // Note: bitLengthBound must upper-bound BOTH inputs. Below, 12345 has 14 bits,
    // larger than M_13 = 8191 (13 bits), so the bound is 14 not 13.
    [InlineData("8191", "12345", 14)]
    [InlineData("8191", "0", 13)]
    [InlineData("2147483647", "1", 31)]
    [InlineData("2147483647", "999999937", 31)]
    public void ExtendedGcd_AlphaTimesFPlusBetaTimesG_Equals2ToTheNTimesGcd(string fDec, string gDec, int bitLengthBound)
    {
        // Arrange
        BclBigInteger fBig = BclBigInteger.Parse(fDec);
        BclBigInteger gBig = BclBigInteger.Parse(gDec);
        BclBigInteger expectedGcd = BclBigInteger.GreatestCommonDivisor(fBig, gBig);
        using var f = fBig.ToSecureBigInteger();
        using var g = gBig.ToSecureBigInteger();

        // Act
        var (gcd, alpha, beta, iterations) = SafeGcd.ExtendedGcd(f, g, bitLengthBound);

        try
        {
            BclBigInteger gcdActual = gcd.ToBigInteger();
            BclBigInteger alphaActual = alpha.ToBigInteger();
            BclBigInteger betaActual = beta.ToBigInteger();
            BclBigInteger expectedRhs = (BclBigInteger.One << iterations) * expectedGcd;
            BclBigInteger actualLhs = (alphaActual * fBig) + (betaActual * gBig);

            // Assert
            Assert.Equal(expectedGcd, gcdActual);
            Assert.Equal(expectedRhs, actualLhs);
        }
        finally
        {
            gcd.Dispose();
            alpha.Dispose();
            beta.Dispose();
        }
    }

    [Fact]
    public void ExtendedGcd_FInputNull_ThrowsArgumentNullException()
    {
        // Arrange
        using var g = new BclSecureBigInteger(5);

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => SafeGcd.ExtendedGcd(null!, g, 8));
    }

    [Fact]
    public void ExtendedGcd_GInputNull_ThrowsArgumentNullException()
    {
        // Arrange
        using var f = new BclSecureBigInteger(7);

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => SafeGcd.ExtendedGcd(f, null!, 8));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    public void ExtendedGcd_NonPositiveBitLengthBound_ThrowsArgumentOutOfRangeException(int bitLengthBound)
    {
        // Arrange
        using var f = new BclSecureBigInteger(7);
        using var g = new BclSecureBigInteger(5);

        // Act & Assert
        Assert.Throws<ArgumentOutOfRangeException>(() => SafeGcd.ExtendedGcd(f, g, bitLengthBound));
    }
}