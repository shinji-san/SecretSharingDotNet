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

namespace SecretSharingDotNetTest.Math.SecureBigInteger;

using SecretSharingDotNet.Math;
using SecretSharingDotNet.Math.Numerics;
using System;
using Xunit;

/// <summary>
/// Tests for <see cref="Polynomial"/> on the <see cref="SecureBigInteger"/> backend —
/// Horner-style polynomial evaluation under a Mersenne-prime modulus, the building
/// block for Shamir share generation. Mirror of the BigInteger-side test class plus
/// the additional <c>EvaluateAt_WithZero</c> guard.
/// </summary>
public class PolynomialTest
{
    /// <summary>
    /// Tests that <see cref="Polynomial.EvaluateAt{TNumber}"/> on a constant polynomial
    /// returns the constant itself when it is already less than the Mersenne modulus
    /// (no reduction step engaged).
    /// </summary>
    [Fact]
    public void EvaluateAt_ConstantPolynomial_ReturnsConstantModMersennePrime()
    {
        // Arrange — p(x) = 7 evaluated at x=100 with M_5 = 31 → 7 mod 31 = 7.
        // No reduction occurs (constant < modulus); preserves the original
        // "7 mod 13 = 7" no-reduction character.
        using var xCalc = new SecureBigIntCalculator(100);
        using var constant = new SecureBigIntCalculator(7);
        var coeffs = new Calculator<SecureBigInteger>[] { constant };

        // Act
        using var result = Polynomial.EvaluateAt(xCalc, coeffs, mersenneExponent: 5);

        // Assert
        using var expected = new SecureBigIntCalculator(7);
        Assert.Equal(expected, result);
    }

    /// <summary>
    /// Tests that <see cref="Polynomial.EvaluateAt{TNumber}"/> on a linear polynomial
    /// (<c>p(x) = a₀ + a₁x</c>) computes correctly when the modulus genuinely engages the
    /// reduction step (polynomial result &gt; modulus).
    /// </summary>
    [Fact]
    public void EvaluateAt_LinearPolynomial_ComputesCorrectly()
    {
        // Arrange — p(x) = 3 + 5x evaluated at x=4 with M_3 = 7 →
        // 23 mod 7 = 2. Modulus chosen below the polynomial result so the
        // reduction step is genuinely exercised (preserves the original
        // "23 mod 17 = 6" reduction-tested character).
        using var xCalc = new SecureBigIntCalculator(4);
        var coeffs = new Calculator<SecureBigInteger>[]
        {
            new SecureBigIntCalculator(3),
            new SecureBigIntCalculator(5),
        };

        try
        {
            // Act
            using var result = Polynomial.EvaluateAt(xCalc, coeffs, mersenneExponent: 3);

            // Assert
            using var expected = new SecureBigIntCalculator(2);
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

    /// <summary>
    /// Tests that <see cref="Polynomial.EvaluateAt{TNumber}"/> on a quadratic polynomial
    /// (<c>p(x) = a₀ + a₁x + a₂x²</c>) computes correctly through Horner's scheme, again with
    /// the modulus below the unreduced polynomial result so the reduction step is exercised.
    /// </summary>
    [Fact]
    public void EvaluateAt_QuadraticPolynomial_ComputesCorrectly()
    {
        // Arrange — p(x) = 2 + 3x + x² evaluated at x=5 with M_5 = 31 →
        // 42 mod 31 = 11. Modulus chosen below the polynomial result so the
        // reduction step is genuinely exercised (preserves the original
        // "42 mod 23 = 19" reduction-tested character).
        using var xCalc = new SecureBigIntCalculator(5);
        var coeffs = new Calculator<SecureBigInteger>[]
        {
            new SecureBigIntCalculator(2),
            new SecureBigIntCalculator(3),
            new SecureBigIntCalculator(1),
        };

        try
        {
            // Act
            using var result = Polynomial.EvaluateAt(xCalc, coeffs, mersenneExponent: 5);

            // Assert
            using var expected = new SecureBigIntCalculator(11);
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

    /// <summary>
    /// Tests that <see cref="Polynomial.EvaluateAt{TNumber}"/> throws
    /// <see cref="ArgumentNullException"/> for a <see langword="null"/> <c>x</c>.
    /// </summary>
    [Fact]
    public void EvaluateAt_NullX_ThrowsArgumentNullException()
    {
        // Arrange
        var coeffs = new Calculator<SecureBigInteger>[] { new SecureBigIntCalculator(1) };

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

    /// <summary>
    /// Tests that <see cref="Polynomial.EvaluateAt{TNumber}"/> throws
    /// <see cref="ArgumentNullException"/> for a <see langword="null"/> coefficient array.
    /// </summary>
    [Fact]
    public void EvaluateAt_NullCoefficients_ThrowsArgumentNullException()
    {
        // Arrange
        using var xCalc = new SecureBigIntCalculator(1);

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => Polynomial.EvaluateAt<SecureBigInteger>(xCalc, null, mersenneExponent: 5));
    }

    /// <summary>
    /// Tests that <see cref="Polynomial.EvaluateAt{TNumber}"/> rejects non-positive
    /// Mersenne exponents (0 or negative) with <see cref="ArgumentOutOfRangeException"/>,
    /// catching pre-call misuse before the modular reduction tries to run.
    /// </summary>
    /// <param name="mersenneExponent">A non-positive exponent value to feed to the call.</param>
    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    public void EvaluateAt_NonPositiveExponent_ThrowsArgumentOutOfRangeException(int mersenneExponent)
    {
        // Arrange
        using var xCalc = new SecureBigIntCalculator(1);
        var coeffs = new Calculator<SecureBigInteger>[] { new SecureBigIntCalculator(1) };

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

    /// <summary>
    /// Tests that <see cref="Polynomial.EvaluateAt{TNumber}"/> rejects <c>x = 0</c> with
    /// <see cref="ArgumentOutOfRangeException"/> — evaluating at zero would expose the
    /// constant term (= the secret <c>a₀</c>) directly, defeating the secret-sharing
    /// scheme. Guard is therefore in the public-API surface.
    /// </summary>
    [Fact]
    public void EvaluateAt_WithZero_ThrowsArgumentOutOfRangeException()
    {
        // Arrange — evaluating at x=0 would return the constant term (the secret a₀).
        // M_13 = 8191 mirrors the original test's `prime = 8191` modulus value.
        using var xCalc = new SecureBigIntCalculator(0);
        using var a0 = new SecureBigIntCalculator(42);
        using var a1 = new SecureBigIntCalculator(7);
        var coeffs = new Calculator<SecureBigInteger>[] { a0, a1 };

        // Act
        var ex = Assert.Throws<ArgumentOutOfRangeException>(
            () => Polynomial.EvaluateAt(xCalc, coeffs, mersenneExponent: 13));

        // Assert
        Assert.Equal("x", ex.ParamName);
    }

    /// <summary>
    /// Regression guard for <c>SEC-1</c>: when an exception is raised inside the Horner
    /// loop (here triggered by a pre-disposed coefficient), the in-flight
    /// <c>accumulator</c> Calculator must not leak its pinned-limb buffer. The fix
    /// wraps the loop in a try/catch that disposes <c>accumulator</c> on every
    /// exception path before re-throwing. The test-project's memory-leak instrumentation
    /// catches any regression that re-introduces the leak.
    /// </summary>
    [Fact]
    public void EvaluateAt_DisposedCoefficient_ThrowsWithoutLeakingAccumulator()
    {
        // Arrange — coefficients[1] is disposed before EvaluateAt runs. The Horner loop
        // visits indices in descending order so iteration index 1 (the linear coefficient)
        // is the first arithmetic step, ensuring the throw lands AFTER the accumulator
        // has been allocated by Calculator<SecureBigInteger>.Zero.
        using var xCalc = new SecureBigIntCalculator(2);
        var a0 = new SecureBigIntCalculator(42);
        var a1 = new SecureBigIntCalculator(7);
        a1.Dispose();
        var coeffs = new Calculator<SecureBigInteger>[] { a0, a1 };

        // Act & Assert — exception propagates; the implementation's catch-and-dispose
        // path is exercised. If the accumulator leaks, the test-project's per-test
        // pinned-allocation accounting reports the residual buffer.
        Assert.Throws<ObjectDisposedException>(
            () => Polynomial.EvaluateAt(xCalc, coeffs, mersenneExponent: 13));

        a0.Dispose();
    }
}