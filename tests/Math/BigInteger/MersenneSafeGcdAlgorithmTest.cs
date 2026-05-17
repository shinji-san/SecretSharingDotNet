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

namespace SecretSharingDotNetTest.Math.BigInteger;

using System;
using System.Numerics;
using SecretSharingDotNet.Math;
using SecretSharingDotNet.Math.Numerics;
using Xunit;

/// <summary>
/// Tests for <see cref="MersenneSafeGcdAlgorithm{TNumber}"/> instantiated with
/// <see cref="BigInteger"/> — the variable-time backend mirror of the
/// constant-time <see cref="SecureBigInteger"/>-backed tests. Verifies that the
/// Bernstein–Yang divsteps recurrence produces the same mathematical results
/// regardless of the underlying numeric backend. Note: the BigInteger
/// backend does not provide timing-side-channel resistance — these tests cover
/// algorithmic correctness only.
/// </summary>
public class MersenneSafeGcdAlgorithmTest
{
    /// <summary>
    /// Tests that <see cref="MersenneSafeGcdAlgorithm{TNumber}.Compute"/> returns the
    /// modular inverse of a non-zero denominator under several Mersenne-prime moduli
    /// (M13, M31, M127). Cross-checks against Fermat's little theorem
    /// (<c>a^{p-2} mod p ≡ a^{-1} mod p</c>) computed via BCL <c>BigInteger.ModPow</c>.
    /// </summary>
    /// <param name="denominatorDec">The denominator as a decimal string.</param>
    /// <param name="mersenneExponent">The Mersenne exponent picking the prime field.</param>
    [Theory]
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
        BigInteger primeBig = (BigInteger.One << mersenneExponent) - BigInteger.One;
        BigInteger denominatorBig = BigInteger.Parse(denominatorDec) % primeBig;
        BigInteger expectedInverse = BigInteger.ModPow(denominatorBig, primeBig - 2, primeBig);

        var algorithm = new MersenneSafeGcdAlgorithm<BigInteger>();
        using Calculator<BigInteger> aCalc = new BigIntCalculator(denominatorBig);
        using Calculator<BigInteger> bCalc = new BigIntCalculator(primeBig);

        // Act
        using var result = algorithm.Compute(aCalc, bCalc);

        // Assert
        Assert.True(result.GreatestCommonDivisor.IsOne);

        BigInteger inverseActual = (BigInteger)result.BezoutCoefficients[0];
        Assert.Equal(expectedInverse, inverseActual);

        // Stronger sanity check independent of the cross-implementation: bezout[0] · a ≡ 1 (mod M_p).
        BigInteger product = (inverseActual * denominatorBig) % primeBig;
        Assert.Equal(BigInteger.One, product);
    }

    /// <summary>
    /// Tests that <c>gcd(0, M_p) = M_p</c> — the boundary case where the denominator is
    /// zero. <see cref="MersenneSafeGcdAlgorithm{TNumber}.Compute"/> must surface the
    /// prime itself as the GCD rather than producing an undefined inverse.
    /// </summary>
    [Fact]
    public void Compute_ZeroDenominator_GcdEqualsPrime()
    {
        // Arrange
        BigInteger primeBig = (BigInteger.One << 31) - BigInteger.One;

        var algorithm = new MersenneSafeGcdAlgorithm<BigInteger>();
        using Calculator<BigInteger> aCalc = new BigIntCalculator(BigInteger.Zero);
        using Calculator<BigInteger> bCalc = new BigIntCalculator(primeBig);

        // Act
        using var result = algorithm.Compute(aCalc, bCalc);

        // Assert: gcd(0, M_p) = M_p.
        BigInteger gcdActual = (BigInteger)result.GreatestCommonDivisor;
        Assert.Equal(primeBig, gcdActual);
    }

    /// <summary>
    /// Tests that <see cref="MersenneSafeGcdAlgorithm{TNumber}.Compute"/> rejects a
    /// <see langword="null"/> first operand (<c>a</c>) with
    /// <see cref="ArgumentNullException"/>.
    /// </summary>
    [Fact]
    public void Compute_NullA_ThrowsArgumentNullException()
    {
        // Arrange
        BigInteger primeBig = (BigInteger.One << 31) - BigInteger.One;
        var algorithm = new MersenneSafeGcdAlgorithm<BigInteger>();
        using Calculator<BigInteger> bCalc = new BigIntCalculator(primeBig);

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => algorithm.Compute(null!, bCalc));
    }

    /// <summary>
    /// Tests that <see cref="MersenneSafeGcdAlgorithm{TNumber}.Compute"/> rejects a
    /// <see langword="null"/> second operand (<c>b</c>) with
    /// <see cref="ArgumentNullException"/>.
    /// </summary>
    [Fact]
    public void Compute_NullB_ThrowsArgumentNullException()
    {
        // Arrange
        var algorithm = new MersenneSafeGcdAlgorithm<BigInteger>();
        using Calculator<BigInteger> aCalc = new BigIntCalculator(new BigInteger(7));

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => algorithm.Compute(aCalc, null!));
    }

    /// <summary>
    /// Tests that <see cref="MersenneSafeGcdAlgorithm{TNumber}.Compute"/> rejects an
    /// even modulus (<c>b</c>) with <see cref="ArgumentException"/>. Mersenne primes
    /// <c>M_p = 2^p − 1</c> are always odd; an even value is guaranteed not to be a
    /// Mersenne prime and would otherwise produce silently-wrong results.
    /// </summary>
    [Fact]
    public void Compute_EvenB_ThrowsArgumentException()
    {
        // Arrange
        var algorithm = new MersenneSafeGcdAlgorithm<BigInteger>();
        using Calculator<BigInteger> aCalc = new BigIntCalculator(new BigInteger(7));
        using Calculator<BigInteger> bCalc = new BigIntCalculator(new BigInteger(42));

        // Act & Assert
        var ex = Assert.Throws<ArgumentException>(() => algorithm.Compute(aCalc, bCalc));
        Assert.Equal("b", ex.ParamName);
    }

    /// <summary>
    /// Cross-checks <see cref="MersenneSafeGcdAlgorithm{TNumber}.Compute"/> against the
    /// <see cref="ExtendedEuclideanAlgorithm{TNumber}.Compute"/>: both algorithms must
    /// produce the same modular inverse modulo <c>M_p</c> after reducing the Euclidean
    /// result into the <c>[0, M_p − 1]</c> range.
    /// </summary>
    /// <param name="denominatorDec">The denominator as a decimal string.</param>
    /// <param name="mersenneExponent">The Mersenne exponent picking the prime field.</param>
    [Theory]
    [InlineData("3", 13)]
    [InlineData("999999937", 31)]
    [InlineData("3000", 127)]
    public void Compute_CrossCheckAgainstExtendedEuclideanAlgorithm_ProducesEqualInverseModMersennePrime(
        string denominatorDec, int mersenneExponent)
    {
        // Arrange
        BigInteger primeBig = (BigInteger.One << mersenneExponent) - BigInteger.One;
        BigInteger denominatorBig = BigInteger.Parse(denominatorDec) % primeBig;

        var safegcd = new MersenneSafeGcdAlgorithm<BigInteger>();
        var euclidean = new ExtendedEuclideanAlgorithm<BigInteger>();

        using Calculator<BigInteger> aCalc = new BigIntCalculator(denominatorBig);
        using Calculator<BigInteger> bCalc = new BigIntCalculator(primeBig);

        // Act
        using var safegcdResult = safegcd.Compute(aCalc, bCalc);
        using var euclideanResult = euclidean.Compute(aCalc, bCalc);

        // Assert: both inverses, after reducing into [0, M_p − 1], are identical.
        BigInteger safegcdInverse = (BigInteger)safegcdResult.BezoutCoefficients[0];
        BigInteger euclideanInverseRaw = (BigInteger)euclideanResult.BezoutCoefficients[0];
        BigInteger euclideanInverseReduced = ((euclideanInverseRaw % primeBig) + primeBig) % primeBig;

        Assert.Equal(euclideanInverseReduced, safegcdInverse);
    }

    /// <summary>
    /// Tests that the <see cref="ExtendedGcdResult{TNumber}"/> returned by
    /// <see cref="MersenneSafeGcdAlgorithm{TNumber}.Compute"/> tolerates repeated
    /// <see cref="IDisposable.Dispose"/> calls without throwing — idempotent disposal.
    /// </summary>
    [Fact]
    public void Compute_ResultDispose_IsIdempotent()
    {
        // Arrange
        BigInteger primeBig = (BigInteger.One << 31) - BigInteger.One;
        var algorithm = new MersenneSafeGcdAlgorithm<BigInteger>();
        using Calculator<BigInteger> aCalc = new BigIntCalculator(new BigInteger(42));
        using Calculator<BigInteger> bCalc = new BigIntCalculator(primeBig);

        // Act
        var result = algorithm.Compute(aCalc, bCalc);
        result.Dispose();
        var ex = Record.Exception(() => result.Dispose());

        // Assert
        Assert.Null(ex);
    }

    // -------------------------------------------------------------------------
    // Internal helper tests: MersenneSafeGcdAlgorithm<BigInteger>.ExtendedGcd
    //
    // These tests target the internal Bernstein–Yang divsteps helper directly
    // (visible to the test assembly via InternalsVisibleTo) rather than going
    // through Compute(). Compute() requires that `b` be a Mersenne prime,
    // so testing the algorithm against arbitrary non-Mersenne pairs
    // (e.g. 15/10 with shared factor 5) is only possible at the helper level.
    // -------------------------------------------------------------------------

    /// <summary>
    /// Tests the internal <c>ExtendedGcd</c> helper directly against the BCL's
    /// <see cref="BigInteger.GreatestCommonDivisor(BigInteger, BigInteger)"/>. Covers
    /// coprime pairs, pairs with non-trivial shared factors (impossible to test via
    /// <c>Compute</c>, which restricts <c>b</c> to a Mersenne prime), and Mersenne
    /// moduli M13/M31/M127.
    /// </summary>
    /// <param name="fDec">First operand as a decimal string.</param>
    /// <param name="gDec">Second operand as a decimal string.</param>
    /// <param name="expectedGcdDec">The expected GCD as a decimal string.</param>
    /// <param name="bitLengthBound">Public upper bound on the bit length of the operands.</param>
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
    [InlineData(TestData.M127Decimal, "1", "1", 127)]
    [InlineData(TestData.M127Decimal, "3000", "1", 127)]
    [InlineData(TestData.M127Decimal, "0", TestData.M127Decimal, 127)]
    public void ExtendedGcd_MatchesBclBigInteger(string fDec, string gDec, string expectedGcdDec, int bitLengthBound)
    {
        // Arrange
        BigInteger fBig = BigInteger.Parse(fDec);
        BigInteger gBig = BigInteger.Parse(gDec);
        BigInteger expectedBig = BigInteger.Parse(expectedGcdDec);
        using Calculator<BigInteger> fCalc = new BigIntCalculator(fBig);
        using Calculator<BigInteger> gCalc = new BigIntCalculator(gBig);

        // Act
        var (gcd, alpha, beta, _) = MersenneSafeGcdAlgorithm<BigInteger>.ExtendedGcd(fCalc, gCalc, bitLengthBound);

        try
        {
            // Assert
            Assert.Equal(expectedBig, (BigInteger)gcd);
        }
        finally
        {
            gcd.Dispose();
            alpha.Dispose();
            beta.Dispose();
        }
    }

    /// <summary>
    /// Tests the integer-form Bezout identity
    /// <c>α · f + β · g = 2^iterationCount · gcd</c> for representative input pairs.
    /// Confirms the divsteps recurrence preserves the algebraic invariant the
    /// modular-inverse derivation rests on.
    /// </summary>
    /// <param name="fDec">First operand as a decimal string.</param>
    /// <param name="gDec">Second operand as a decimal string.</param>
    /// <param name="bitLengthBound">Public upper bound on the bit length of the operands.</param>
    [Theory]
    [InlineData("7", "5", 3)]
    [InlineData("7", "0", 3)]
    [InlineData("31", "10", 5)]
    [InlineData("31", "30", 5)]
    [InlineData("127", "100", 7)]
    [InlineData("127", "1", 7)]
    [InlineData("15", "10", 4)]
    [InlineData("15", "9", 4)]
    [InlineData("21", "14", 5)]
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
        using Calculator<BigInteger> fCalc = new BigIntCalculator(fBig);
        using Calculator<BigInteger> gCalc = new BigIntCalculator(gBig);

        // Act
        var (gcd, alpha, beta, iterations) = MersenneSafeGcdAlgorithm<BigInteger>.ExtendedGcd(fCalc, gCalc, bitLengthBound);

        try
        {
            BigInteger gcdActual = (BigInteger)gcd;
            BigInteger alphaActual = (BigInteger)alpha;
            BigInteger betaActual = (BigInteger)beta;
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

    /// <summary>
    /// Tests that <c>ExtendedGcd</c> rejects a <see langword="null"/> first operand
    /// (<c>fInput</c>) with <see cref="ArgumentNullException"/>.
    /// </summary>
    [Fact]
    public void ExtendedGcd_FInputNull_ThrowsArgumentNullException()
    {
        // Arrange
        using Calculator<BigInteger> gCalc = new BigIntCalculator(new BigInteger(5));

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => MersenneSafeGcdAlgorithm<BigInteger>.ExtendedGcd(null!, gCalc, 8));
    }

    /// <summary>
    /// Tests that <c>ExtendedGcd</c> rejects a <see langword="null"/> second operand
    /// (<c>gInput</c>) with <see cref="ArgumentNullException"/>.
    /// </summary>
    [Fact]
    public void ExtendedGcd_GInputNull_ThrowsArgumentNullException()
    {
        // Arrange
        using Calculator<BigInteger> fCalc = new BigIntCalculator(new BigInteger(7));

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => MersenneSafeGcdAlgorithm<BigInteger>.ExtendedGcd(fCalc, null!, 8));
    }

    /// <summary>
    /// Tests that <c>ExtendedGcd</c> rejects a non-positive <c>bitLengthBound</c>
    /// (0 or negative) with <see cref="ArgumentOutOfRangeException"/> — the bound drives
    /// the constant-time iteration count, so a non-positive value is meaningless.
    /// </summary>
    /// <param name="bitLengthBound">A non-positive bound value.</param>
    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    public void ExtendedGcd_NonPositiveBitLengthBound_ThrowsArgumentOutOfRangeException(int bitLengthBound)
    {
        // Arrange
        using Calculator<BigInteger> fCalc = new BigIntCalculator(new BigInteger(7));
        using Calculator<BigInteger> gCalc = new BigIntCalculator(new BigInteger(5));

        // Act & Assert
        Assert.Throws<ArgumentOutOfRangeException>(() => MersenneSafeGcdAlgorithm<BigInteger>.ExtendedGcd(fCalc, gCalc, bitLengthBound));
    }

    /// <summary>
    /// Tests <c>ComputeIterationCount</c> against the closed-form
    /// <c>ceil((49.39 × bitLengthBound + 80) / 17)</c> formula from §11 of
    /// Bernstein &amp; Yang (2019). Covers (a) small values reached by the existing
    /// <c>ExtendedGcd</c> theories, (b) the int32-overflow boundary at
    /// <c>bitLengthBound ≈ 434,801</c> (where <c>4939 × bitLengthBound</c> first
    /// exceeds <see cref="int.MaxValue"/>), and (c) every Mersenne exponent
    /// above 756,839 in <c>MersennePrimeProvider.KnownMersennePrimeExponents</c>
    /// — the 16 exponents that silently wrapped when the multiplication was
    /// performed in int32.
    /// </summary>
    /// <param name="bitLengthBound">Public upper bound on the bit length of the operands.</param>
    /// <param name="expectedIterations">The expected divsteps iteration count.</param>
    [Theory]
    [InlineData(1, 8)]
    [InlineData(13, 43)]
    [InlineData(31, 95)]
    [InlineData(127, 374)]
    [InlineData(434801, 1263230)]
    [InlineData(434802, 1263233)]
    [InlineData(756839, 2198845)]
    [InlineData(859433, 2496911)]
    [InlineData(1257787, 3654246)]
    [InlineData(1398269, 4062388)]
    [InlineData(2976221, 8646803)]
    [InlineData(3021377, 8777994)]
    [InlineData(6972593, 20257439)]
    [InlineData(13466917, 39125360)]
    [InlineData(20996011, 60999592)]
    [InlineData(24036583, 69833348)]
    [InlineData(25964951, 75435825)]
    [InlineData(30402457, 88328085)]
    [InlineData(32582657, 94662207)]
    [InlineData(37156667, 107951051)]
    [InlineData(42643801, 123892789)]
    [InlineData(43112609, 125254815)]
    public void ComputeIterationCount_MatchesBernsteinYangFormula(int bitLengthBound, int expectedIterations)
    {
        // Act
        int actual = MersenneSafeGcdAlgorithm<BigInteger>.ComputeIterationCount(bitLengthBound);

        // Assert
        Assert.Equal(expectedIterations, actual);
        Assert.True(actual > 0, "iteration count must be strictly positive across the supported bound range");
    }
}