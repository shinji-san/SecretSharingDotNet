// ----------------------------------------------------------------------------
// <copyright file="PolynomialTest.cs" company="Private">
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

namespace SecretSharingDotNetTest.Math.BigInteger;

using SecretSharingDotNet.Math;
using SecretSharingDotNet.Math.Numerics;
using System;
using System.Numerics;
using Xunit;

public class PolynomialTest
{
    [Fact]
    public void EvaluateAt_ConstantPolynomial_ReturnsConstantModMersennePrime()
    {
        // Arrange — p(x) = 7 evaluated at x=100 with M_5 = 31 → 7 mod 31 = 7.
        // No reduction occurs (constant < modulus); preserves the original
        // "7 mod 13 = 7" no-reduction character.
        using var xCalc = new BigIntCalculator(100);
        using var constant = new BigIntCalculator(7);
        var coeffs = new Calculator<BigInteger>[] { constant };

        // Act
        using var result = Polynomial.EvaluateAt(xCalc, coeffs, mersenneExponent: 5);

        // Assert
        using var expected = new BigIntCalculator(7);
        Assert.Equal(expected, result);
    }

    [Fact]
    public void EvaluateAt_LinearPolynomial_ComputesCorrectly()
    {
        // Arrange — p(x) = 3 + 5x evaluated at x=4 with M_3 = 7 →
        // 23 mod 7 = 2. Modulus chosen below the polynomial result so the
        // reduction step is genuinely exercised (preserves the original
        // "23 mod 17 = 6" reduction-tested character).
        using var xCalc = new BigIntCalculator(4);
        var coeffs = new Calculator<BigInteger>[]
        {
            new BigIntCalculator(3),
            new BigIntCalculator(5),
        };

        try
        {
            // Act
            using var result = Polynomial.EvaluateAt(xCalc, coeffs, mersenneExponent: 3);

            // Assert
            using var expected = new BigIntCalculator(2);
            Assert.Equal(expected, result);
        }
        finally
        {
            foreach (var c in coeffs)
            {
                c.Dispose();
            }
        }
    }

    [Fact]
    public void EvaluateAt_QuadraticPolynomial_ComputesCorrectly()
    {
        // Arrange — p(x) = 2 + 3x + x² evaluated at x=5 with M_5 = 31 →
        // 42 mod 31 = 11. Modulus chosen below the polynomial result so the
        // reduction step is genuinely exercised (preserves the original
        // "42 mod 23 = 19" reduction-tested character).
        using var xCalc = new BigIntCalculator(5);
        var coeffs = new Calculator<BigInteger>[]
        {
            new BigIntCalculator(2),
            new BigIntCalculator(3),
            new BigIntCalculator(1),
        };

        try
        {
            // Act
            using var result = Polynomial.EvaluateAt(xCalc, coeffs, mersenneExponent: 5);

            // Assert
            using var expected = new BigIntCalculator(11);
            Assert.Equal(expected, result);
        }
        finally
        {
            foreach (var c in coeffs)
            {
                c.Dispose();
            }
        }
    }

    [Fact]
    public void EvaluateAt_NullX_ThrowsArgumentNullException()
    {
        // Arrange
        var coeffs = new Calculator<BigInteger>[] { new BigIntCalculator(1) };

        try
        {
            // Act & Assert
            Assert.Throws<ArgumentNullException>(() => Polynomial.EvaluateAt(null, coeffs, mersenneExponent: 5));
        }
        finally
        {
            coeffs[0].Dispose();
        }
    }

    [Fact]
    public void EvaluateAt_NullCoefficients_ThrowsArgumentNullException()
    {
        // Arrange
        using var xCalc = new BigIntCalculator(1);

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => Polynomial.EvaluateAt<BigInteger>(xCalc, null, mersenneExponent: 5));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    public void EvaluateAt_NonPositiveExponent_ThrowsArgumentOutOfRangeException(int mersenneExponent)
    {
        // Arrange
        using var xCalc = new BigIntCalculator(1);
        var coeffs = new Calculator<BigInteger>[] { new BigIntCalculator(1) };

        try
        {
            // Act
            var ex = Assert.Throws<ArgumentOutOfRangeException>(
                () => Polynomial.EvaluateAt(xCalc, coeffs, mersenneExponent));

            // Assert
            Assert.Equal("mersenneExponent", ex.ParamName);
        }
        finally
        {
            coeffs[0].Dispose();
        }
    }
}