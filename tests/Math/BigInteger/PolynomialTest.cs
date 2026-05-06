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
    public void EvaluateAt_ConstantPolynomial_ReturnsConstantModPrime()
    {
        // Arrange
        // p(x) = 7 evaluated at x=100 with prime=13 → 7 mod 13 = 7
        using var xCalc = new BigIntCalculator(100);
        using var primeCalc = new BigIntCalculator(13);
        using var constant = new BigIntCalculator(7);
        var coeffs = new Calculator<BigInteger>[] { constant };

        // Act
        using var result = Polynomial.EvaluateAt(xCalc, coeffs, primeCalc);

        // Assert
        Assert.Equal(new BigIntCalculator(7), result);
    }

    [Fact]
    public void EvaluateAt_LinearPolynomial_ComputesCorrectly()
    {
        // Arrange
        // p(x) = 3 + 5x evaluated at x=4 with prime=17 → 23 mod 17 = 6
        using var xCalc = new BigIntCalculator(4);
        using var primeCalc = new BigIntCalculator(17);
        var coeffs = new Calculator<BigInteger>[]
        {
            new BigIntCalculator(3),
            new BigIntCalculator(5),
        };

        try
        {
            // Act
            using var result = Polynomial.EvaluateAt(xCalc, coeffs, primeCalc);

            // Assert
            Assert.Equal(new BigIntCalculator(6), result);
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
        // Arrange
        // p(x) = 2 + 3x + x² evaluated at x=5 with prime=23 → 42 mod 23 = 19
        using var xCalc = new BigIntCalculator(5);
        using var primeCalc = new BigIntCalculator(23);
        var coeffs = new Calculator<BigInteger>[]
        {
            new BigIntCalculator(2),
            new BigIntCalculator(3),
            new BigIntCalculator(1),
        };

        try
        {
            // Act
            using var result = Polynomial.EvaluateAt(xCalc, coeffs, primeCalc);

            // Assert
            Assert.Equal(new BigIntCalculator(19), result);
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
        using var primeCalc = new BigIntCalculator(17);
        var coeffs = new Calculator<BigInteger>[] { new BigIntCalculator(1) };

        try
        {
            // Act & Assert
            Assert.Throws<ArgumentNullException>(() => Polynomial.EvaluateAt(null, coeffs, primeCalc));
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
        using var primeCalc = new BigIntCalculator(17);

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => Polynomial.EvaluateAt(xCalc, null, primeCalc));
    }

    [Fact]
    public void EvaluateAt_NullPrime_ThrowsArgumentNullException()
    {
        // Arrange
        using var xCalc = new BigIntCalculator(1);
        var coeffs = new Calculator<BigInteger>[] { new BigIntCalculator(1) };

        try
        {
            // Act & Assert
            Assert.Throws<ArgumentNullException>(() => Polynomial.EvaluateAt(xCalc, coeffs, null));
        }
        finally
        {
            coeffs[0].Dispose();
        }
    }
}
