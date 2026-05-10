// ----------------------------------------------------------------------------
// <copyright file="MersenneSafeGcdAlgorithmTest.cs" company="Private">
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

using System;
using System.Numerics;
using SecretSharingDotNet.Cryptography.ShamirsSecretSharing;
using SecretSharingDotNet.Math;
using SecretSharingDotNet.Math.Numerics;
using Xunit;

public class MersenneSafeGcdAlgorithmTest
{
    [Fact]
    public void Constructor_NullSecurityLevelManager_ThrowsArgumentNullException()
    {
        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => new MersenneSafeGcdAlgorithm(null!));
    }

    [Theory]
    // (denominator, mersenneExponent). For each row:
    //   gcd       = 1
    //   bezout[0] = denominator^{-1} mod M_p   (cross-checked via Fermat: a^{p-2} mod p)
    [InlineData("1", 13)]
    [InlineData("2", 13)]
    [InlineData("3", 13)]
    [InlineData("8190", 13)]
    [InlineData("12345", 13)]
    [InlineData("1", 31)]
    [InlineData("2", 31)]
    [InlineData("999999937", 31)]
    [InlineData("2147483646", 31)]
    [InlineData("1", 127)]
    [InlineData("2", 127)]
    [InlineData("3000", 127)]
    [InlineData("170141183460469231731687303715884105726", 127)]
    public void Compute_NonZeroDenominator_ReturnsModularInverse(string denominatorDec, int mersenneExponent)
    {
        // Arrange
        using var manager = new SecurityLevelManager<SecureBigInteger> { SecurityLevel = mersenneExponent };
        BigInteger primeBig = (BigInteger.One << mersenneExponent) - BigInteger.One;
        BigInteger denominatorBig = BigInteger.Parse(denominatorDec) % primeBig;
        BigInteger expectedInverse = BigInteger.ModPow(denominatorBig, primeBig - 2, primeBig);

        var algorithm = new MersenneSafeGcdAlgorithm(manager);
        using Calculator<SecureBigInteger> aCalc = new SecureBigIntCalculator(denominatorBig.ToSecureBigInteger());
        Calculator<SecureBigInteger> bCalc = manager.MersennePrime;

        // Act
        using var result = algorithm.Compute(aCalc, bCalc);

        // Assert
        Assert.True(result.GreatestCommonDivisor.IsOne);

        BigInteger inverseActual = ((SecureBigInteger)result.BezoutCoefficients[0]).ToBigInteger();
        Assert.Equal(expectedInverse, inverseActual);

        // Stronger sanity check independent of the cross-implementation: bezout[0] · a ≡ 1 (mod M_p).
        BigInteger product = (inverseActual * denominatorBig) % primeBig;
        Assert.Equal(BigInteger.One, product);
    }

    [Fact]
    public void Compute_ZeroDenominator_GcdEqualsPrime()
    {
        // Arrange
        using var manager = new SecurityLevelManager<SecureBigInteger> { SecurityLevel = 31 };
        BigInteger primeBig = (BigInteger.One << 31) - BigInteger.One;

        var algorithm = new MersenneSafeGcdAlgorithm(manager);
        using Calculator<SecureBigInteger> aCalc = new SecureBigIntCalculator(BigInteger.Zero.ToSecureBigInteger());
        Calculator<SecureBigInteger> bCalc = manager.MersennePrime;

        // Act
        using var result = algorithm.Compute(aCalc, bCalc);

        // Assert: gcd(0, M_p) = M_p.
        BigInteger gcdActual = ((SecureBigInteger)result.GreatestCommonDivisor).ToBigInteger();
        Assert.Equal(primeBig, gcdActual);
    }

    [Fact]
    public void Compute_NullA_ThrowsArgumentNullException()
    {
        // Arrange
        using var manager = new SecurityLevelManager<SecureBigInteger> { SecurityLevel = 31 };
        var algorithm = new MersenneSafeGcdAlgorithm(manager);
        Calculator<SecureBigInteger> bCalc = manager.MersennePrime;

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => algorithm.Compute(null!, bCalc));
    }

    [Fact]
    public void Compute_NullB_ThrowsArgumentNullException()
    {
        // Arrange
        using var manager = new SecurityLevelManager<SecureBigInteger> { SecurityLevel = 31 };
        var algorithm = new MersenneSafeGcdAlgorithm(manager);
        using Calculator<SecureBigInteger> aCalc = new SecureBigIntCalculator(new SecureBigInteger(7));

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => algorithm.Compute(aCalc, null!));
    }

    [Fact]
    public void Compute_BIsNotConfiguredMersennePrime_ThrowsArgumentException()
    {
        // Arrange: configure manager with M_31, but pass M_13 as `b`.
        using var manager = new SecurityLevelManager<SecureBigInteger> { SecurityLevel = 31 };
        var algorithm = new MersenneSafeGcdAlgorithm(manager);
        BigInteger m13 = (BigInteger.One << 13) - BigInteger.One;
        using Calculator<SecureBigInteger> aCalc = new SecureBigIntCalculator(new SecureBigInteger(7));
        using Calculator<SecureBigInteger> bCalc = new SecureBigIntCalculator(m13.ToSecureBigInteger());

        // Act
        var ex = Assert.Throws<ArgumentException>(() => algorithm.Compute(aCalc, bCalc));

        // Assert
        Assert.Equal("b", ex.ParamName);
    }

    [Theory]
    [InlineData("3", 13)]
    [InlineData("999999937", 31)]
    [InlineData("3000", 127)]
    public void Compute_CrossCheckAgainstExtendedEuclideanAlgorithm_ProducesEqualInverseModMersennePrime(
        string denominatorDec, int mersenneExponent)
    {
        // Arrange
        using var manager = new SecurityLevelManager<SecureBigInteger> { SecurityLevel = mersenneExponent };
        BigInteger primeBig = (BigInteger.One << mersenneExponent) - BigInteger.One;
        BigInteger denominatorBig = BigInteger.Parse(denominatorDec) % primeBig;

        var safegcd = new MersenneSafeGcdAlgorithm(manager);
        var euclidean = new ExtendedEuclideanAlgorithm<SecureBigInteger>();

        using Calculator<SecureBigInteger> aCalc = new SecureBigIntCalculator(denominatorBig.ToSecureBigInteger());
        Calculator<SecureBigInteger> bCalc = manager.MersennePrime;

        // Act
        using var safegcdResult = safegcd.Compute(aCalc, bCalc);
        using var euclideanResult = euclidean.Compute(aCalc, bCalc);

        // Assert: both inverses, after reducing into [0, M_p − 1], are identical.
        BigInteger safegcdInverse = ((SecureBigInteger)safegcdResult.BezoutCoefficients[0]).ToBigInteger();
        BigInteger euclideanInverseRaw = ((SecureBigInteger)euclideanResult.BezoutCoefficients[0]).ToBigInteger();
        BigInteger euclideanInverseReduced = ((euclideanInverseRaw % primeBig) + primeBig) % primeBig;

        Assert.Equal(euclideanInverseReduced, safegcdInverse);
    }

    [Fact]
    public void Compute_ResultDispose_IsIdempotent()
    {
        // Arrange
        using var manager = new SecurityLevelManager<SecureBigInteger> { SecurityLevel = 31 };
        var algorithm = new MersenneSafeGcdAlgorithm(manager);
        using Calculator<SecureBigInteger> aCalc = new SecureBigIntCalculator(new SecureBigInteger(42));
        Calculator<SecureBigInteger> bCalc = manager.MersennePrime;

        // Act
        var result = algorithm.Compute(aCalc, bCalc);
        result.Dispose();
        var ex = Record.Exception(() => result.Dispose());

        // Assert
        Assert.Null(ex);
    }

    // -------------------------------------------------------------------------
    // Internal helper tests: MersenneSafeGcdAlgorithm.ExtendedGcd
    //
    // These tests target the internal Bernstein–Yang divsteps helper directly
    // (visible to the test assembly via InternalsVisibleTo) rather than going
    // through Compute(). Compute() requires `b == manager.MersennePrime`, so
    // testing the algorithm against arbitrary non-Mersenne pairs
    // (e.g. 15/10 with shared factor 5) is only possible at the helper level.
    // -------------------------------------------------------------------------

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
    public void ExtendedGcd_MatchesBclBigInteger(string fDec, string gDec, string expectedGcdDec, int bitLengthBound)
    {
        // Arrange
        using var f = BigInteger.Parse(fDec).ToSecureBigInteger();
        using var g = BigInteger.Parse(gDec).ToSecureBigInteger();
        using var expected = BigInteger.Parse(expectedGcdDec).ToSecureBigInteger();

        // Act
        var (gcd, alpha, beta, _) = MersenneSafeGcdAlgorithm.ExtendedGcd(f, g, bitLengthBound);

        try
        {
            // Assert
            Assert.Equal(expected, gcd);
        }
        finally
        {
            gcd.Dispose();
            alpha.Dispose();
            beta.Dispose();
        }
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
        BigInteger fBig = BigInteger.Parse(fDec);
        BigInteger gBig = BigInteger.Parse(gDec);
        BigInteger expectedGcd = BigInteger.GreatestCommonDivisor(fBig, gBig);
        using var f = fBig.ToSecureBigInteger();
        using var g = gBig.ToSecureBigInteger();

        // Act
        var (gcd, alpha, beta, iterations) = MersenneSafeGcdAlgorithm.ExtendedGcd(f, g, bitLengthBound);

        try
        {
            BigInteger gcdActual = gcd.ToBigInteger();
            BigInteger alphaActual = alpha.ToBigInteger();
            BigInteger betaActual = beta.ToBigInteger();
            BigInteger expectedRhs = (BigInteger.One << iterations) * expectedGcd;
            BigInteger actualLhs = (alphaActual * fBig) + (betaActual * gBig);

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
        using var g = new SecureBigInteger(5);

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => MersenneSafeGcdAlgorithm.ExtendedGcd(null!, g, 8));
    }

    [Fact]
    public void ExtendedGcd_GInputNull_ThrowsArgumentNullException()
    {
        // Arrange
        using var f = new SecureBigInteger(7);

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => MersenneSafeGcdAlgorithm.ExtendedGcd(f, null!, 8));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    public void ExtendedGcd_NonPositiveBitLengthBound_ThrowsArgumentOutOfRangeException(int bitLengthBound)
    {
        // Arrange
        using var f = new SecureBigInteger(7);
        using var g = new SecureBigInteger(5);

        // Act & Assert
        Assert.Throws<ArgumentOutOfRangeException>(() => MersenneSafeGcdAlgorithm.ExtendedGcd(f, g, bitLengthBound));
    }
}