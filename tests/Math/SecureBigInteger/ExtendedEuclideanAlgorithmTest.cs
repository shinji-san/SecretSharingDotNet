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

namespace SecretSharingDotNetTest.Math.SecureBigInteger;

using System.Numerics;
using SecretSharingDotNet.Math;
using SecretSharingDotNet.Math.Numerics;
using Xunit;

/// <summary>
/// Tests for <see cref="ExtendedEuclideanAlgorithm{TNumber}"/> on the
/// <see cref="SecureBigInteger"/> backend — Euclidean GCD plus the Bezout coefficients used
/// downstream for modular inversion during share reconstruction.
/// </summary>
public class ExtendedEuclideanAlgorithmTest
{
    private readonly ExtendedEuclideanAlgorithm<SecureBigInteger> gcd = new ExtendedEuclideanAlgorithm<SecureBigInteger>();

    /// <summary>
    /// Tests that <see cref="ExtendedEuclideanAlgorithm{TNumber}.Compute"/> returns
    /// <c>gcd(6, 9) = 3</c> for two small composites. Sanity check for the basic
    /// Euclidean recurrence on the <see cref="SecureBigInteger"/> backend.
    /// </summary>
    [Fact]
    public void Compute_SmallComposites_ReturnsGreatestCommonDivisor()
    {
        // Arrange
        using Calculator<SecureBigInteger> expected = (SecureBigInteger)3;
        using Calculator<SecureBigInteger> a = (SecureBigInteger)6; 
        using Calculator<SecureBigInteger> b = (SecureBigInteger)9;

        // Act
        using var gcdResult = this.gcd.Compute(a, b);

        // Assert
        Assert.Equal(expected, gcdResult.GreatestCommonDivisor);
    }

    /// <summary>
    /// Tests that <see cref="ExtendedEuclideanAlgorithm{TNumber}.Compute"/> produces the
    /// expected Bezout coefficients for several operand pairs involving the Mersenne prime
    /// <c>M127</c> and small companions. Negative operands exercise the sign-propagation
    /// path on the <see cref="SecureBigInteger"/> backend.
    /// </summary>
    /// <param name="operandA">First operand as a decimal string (the
    /// <see cref="SecureBigInteger"/>(string) decimal ctor was removed in D3, so test
    /// constants are routed through
    /// <see cref="BigInteger.Parse(string)"/> + <c>ToSecureBigInteger()</c>).</param>
    /// <param name="operandB">Second operand as a decimal string.</param>
    /// <param name="expectedCoefficientForA">Expected Bezout coefficient paired with operand A
    /// (i.e. <c>BezoutCoefficients[0]</c>).</param>
    /// <param name="expectedCoefficientForB">Expected Bezout coefficient paired with operand B
    /// (i.e. <c>BezoutCoefficients[1]</c>).</param>
    [Theory]
    // Originally 5 separate [Fact]s in this class. The InlineData rows preserve
    // every original decimal test value verbatim — large constants are routed
    // through System.Numerics.BigInteger.Parse and BigIntegerExtensions
    // .ToSecureBigInteger() because the SecureBigInteger(string) decimal ctor
    // was removed in D3. The BezoutCoefficients[0] / [1] convention pins
    // expectedCoefficientForA → BezoutCoefficients[0] and
    // expectedCoefficientForB → BezoutCoefficients[1].
    [InlineData("2", "170141183460469231731687303715884105727", "-85070591730234615865843651857942052863", "1")]
    [InlineData("-1", "170141183460469231731687303715884105727", "1", "0")]
    [InlineData("-4", "170141183460469231731687303715884105727", "42535295865117307932921825928971026432", "1")]
    [InlineData("170141183460469231731687303715884105727", "-1", "0", "1")]
    [InlineData("170141183460469231731687303715884105727", "-4", "1", "42535295865117307932921825928971026432")]
    public void Compute_ProducesExpectedBezoutCoefficients(
        string operandA,
        string operandB,
        string expectedCoefficientForA,
        string expectedCoefficientForB)
    {
        // Arrange
        using Calculator<SecureBigInteger> a = BigInteger.Parse(operandA).ToSecureBigInteger();
        using Calculator<SecureBigInteger> b = BigInteger.Parse(operandB).ToSecureBigInteger();
        using Calculator<SecureBigInteger> expectedA = BigInteger.Parse(expectedCoefficientForA).ToSecureBigInteger();
        using Calculator<SecureBigInteger> expectedB = BigInteger.Parse(expectedCoefficientForB).ToSecureBigInteger();

        // Act
        using var result = this.gcd.Compute(a, b);

        // Assert
        Assert.Equal(expectedA, result.BezoutCoefficients[0]);
        Assert.Equal(expectedB, result.BezoutCoefficients[1]);
    }
}