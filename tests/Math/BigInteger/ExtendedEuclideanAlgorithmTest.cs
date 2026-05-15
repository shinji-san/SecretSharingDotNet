// ----------------------------------------------------------------------------
// <copyright file="ExtendedEuclideanAlgorithmTest.cs" company="Private">
// Copyright (c) 2019 All Rights Reserved
// </copyright>
// <author>Sebastian Walther</author>
// <date>04/20/2019 10:52:28 PM</date>
// ----------------------------------------------------------------------------

#region License
// ----------------------------------------------------------------------------
// Copyright 2019 Sebastian Walther
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
using System.Globalization;
using System.Numerics;
using Xunit;

/// <summary>
/// Tests for <see cref="ExtendedEuclideanAlgorithm{TNumber}"/> on the
/// <see cref="BigInteger"/> backend — Euclidean GCD plus the Bezout coefficients used
/// downstream for modular inversion during share reconstruction.
/// </summary>
public class ExtendedEuclideanAlgorithmTest
{
    private readonly ExtendedEuclideanAlgorithm<BigInteger> gcd = new ExtendedEuclideanAlgorithm<BigInteger>();

    /// <summary>
    /// Tests that <see cref="ExtendedEuclideanAlgorithm{TNumber}.Compute"/> returns
    /// <c>gcd(6, 9) = 3</c> for two small composites. Sanity check for the basic
    /// Euclidean recurrence on the <see cref="BigInteger"/> backend.
    /// </summary>
    [Fact]
    public void Compute_SmallComposites_ReturnsGreatestCommonDivisor()
    {
        // Arrange
        using Calculator<BigInteger> expected = (BigInteger)3;

        // Act
        using var gcdResult = this.gcd.Compute(BigInteger.Parse("6", CultureInfo.InvariantCulture), BigInteger.Parse("9", CultureInfo.InvariantCulture));

        // Assert
        Assert.Equal(expected, gcdResult.GreatestCommonDivisor);
    }

    /// <summary>
    /// Tests that <see cref="ExtendedEuclideanAlgorithm{TNumber}.Compute"/> produces the
    /// expected Bezout coefficients for <c>(2, M127)</c> — two positive operands where the
    /// second is the Mersenne prime <c>2^127 − 1</c>.
    /// </summary>
    [Fact]
    public void Compute_TwoPositiveOperands_ReturnsExpectedBezoutCoefficients()
    {
        // Act
        using var result = this.gcd.Compute(BigInteger.Parse("2", CultureInfo.InvariantCulture), BigInteger.Parse("170141183460469231731687303715884105727", CultureInfo.InvariantCulture));

        // Assert
        Assert.Equal(BigInteger.Parse("-85070591730234615865843651857942052863", CultureInfo.InvariantCulture), result.BezoutCoefficients[0].Value);
        Assert.Equal(BigInteger.One, result.BezoutCoefficients[1].Value);
    }

    /// <summary>
    /// Tests that <see cref="ExtendedEuclideanAlgorithm{TNumber}.Compute"/> produces the
    /// expected Bezout coefficients for <c>(-1, M127)</c> — negative first operand of
    /// magnitude one against the Mersenne prime.
    /// </summary>
    [Fact]
    public void Compute_NegativeOneAndMersennePrime_ReturnsExpectedBezoutCoefficients()
    {
        // Act
        using var result = this.gcd.Compute(BigInteger.Parse("-1", CultureInfo.InvariantCulture), BigInteger.Parse("170141183460469231731687303715884105727", CultureInfo.InvariantCulture));

        // Assert
        Assert.Equal(BigInteger.One, result.BezoutCoefficients[0].Value);
        Assert.Equal(BigInteger.Zero, result.BezoutCoefficients[1].Value);
    }

    /// <summary>
    /// Tests that <see cref="ExtendedEuclideanAlgorithm{TNumber}.Compute"/> produces the
    /// expected Bezout coefficients for <c>(-4, M127)</c> — negative first operand of
    /// magnitude four against the Mersenne prime.
    /// </summary>
    [Fact]
    public void Compute_NegativeFourAndMersennePrime_ReturnsExpectedBezoutCoefficients()
    {
        // Act
        using var result = this.gcd.Compute(BigInteger.Parse("-4", CultureInfo.InvariantCulture), BigInteger.Parse("170141183460469231731687303715884105727", CultureInfo.InvariantCulture));

        // Assert
        Assert.Equal(BigInteger.Parse("42535295865117307932921825928971026432", CultureInfo.InvariantCulture), result.BezoutCoefficients[0].Value);
        Assert.Equal(BigInteger.One, result.BezoutCoefficients[1].Value);
    }

    /// <summary>
    /// Tests that <see cref="ExtendedEuclideanAlgorithm{TNumber}.Compute"/> produces the
    /// expected Bezout coefficients for <c>(M127, -1)</c> — mirror of the
    /// negative-first-operand case with the Mersenne prime in the first slot instead.
    /// </summary>
    [Fact]
    public void Compute_MersennePrimeAndNegativeOne_ReturnsExpectedBezoutCoefficients()
    {
        // Act
        using var result = this.gcd.Compute(BigInteger.Parse("170141183460469231731687303715884105727", CultureInfo.InvariantCulture), BigInteger.Parse("-1", CultureInfo.InvariantCulture));

        // Assert
        Assert.Equal(BigInteger.Zero, result.BezoutCoefficients[0].Value);
        Assert.Equal(BigInteger.One, result.BezoutCoefficients[1].Value);
    }

    /// <summary>
    /// Tests that <see cref="ExtendedEuclideanAlgorithm{TNumber}.Compute"/> produces the
    /// expected Bezout coefficients for <c>(M127, -4)</c> — mirror of the
    /// negative-four-first-operand case with the Mersenne prime in the first slot instead.
    /// </summary>
    [Fact]
    public void Compute_MersennePrimeAndNegativeFour_ReturnsExpectedBezoutCoefficients()
    {
        // Act
        using var result = this.gcd.Compute(BigInteger.Parse("170141183460469231731687303715884105727", CultureInfo.InvariantCulture), BigInteger.Parse("-4", CultureInfo.InvariantCulture));

        // Assert
        Assert.Equal(BigInteger.One, result.BezoutCoefficients[0].Value);
        Assert.Equal(BigInteger.Parse("42535295865117307932921825928971026432", CultureInfo.InvariantCulture), result.BezoutCoefficients[1].Value);
    }
}