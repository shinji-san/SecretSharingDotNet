// ----------------------------------------------------------------------------
// <copyright file="MersenneSafeGcdAlgorithm.cs" company="Private">
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

namespace SecretSharingDotNet.Math;

using Cryptography.ShamirsSecretSharing;
using Numerics;
using System;

/// <summary>
/// Constant-time extended-GCD algorithm specialised for the
/// <see cref="SecureBigInteger"/> backend, computing modular inverses against
/// the Mersenne prime configured on a supplied
/// <see cref="ISecurityLevelManager{TNumber}"/>. Wraps
/// <see cref="SafeGcd.ExtendedGcd"/> (Bernstein–Yang divsteps with Bezout
/// tracking) and applies the <c>2^{-n}</c> correction needed to convert the
/// algorithm's integer-form Bezout identity into a modular inverse.
/// </summary>
/// <remarks>
/// <para>
/// <b>Contract weakening vs. <see cref="ExtendedEuclideanAlgorithm{TNumber}"/>.</b>
/// The standard extended Euclidean algorithm returns Bezout coefficients
/// <c>(s, t)</c> satisfying <c>a·s + b·t = gcd(a, b)</c> over <c>Z</c>.
/// <see cref="SafeGcd"/> instead returns <c>(α, β)</c> such that
/// <c>α·f + β·g = 2^n · gcd(f, g)</c>, where <c>n</c> is the
/// algorithm's fixed iteration count. The <c>2^n</c> factor cannot be removed
/// over <c>Z</c> in general; it can only be cancelled modulo a chosen modulus.
/// This class therefore returns coefficients that satisfy the Bezout identity
/// <em>modulo the configured Mersenne prime</em>, not over <c>Z</c>.
/// </para>
/// <para>
/// For Mersenne primes <c>M_p = 2^p − 1</c>, <c>2^p ≡ 1 (mod M_p)</c>, so
/// <c>2^{-n} ≡ 2^{(p − n mod p) mod p} (mod M_p)</c>. Multiplying both sides
/// of the integer-form identity by <c>2^{-n}</c> yields, when
/// <c>gcd(a, b) = 1</c>, a true modular inverse of the denominator.
/// </para>
/// <para>
/// <b>Precondition.</b> <see cref="Compute"/>'s <c>b</c> argument must equal
/// the Mersenne prime currently configured on the supplied
/// <see cref="ISecurityLevelManager{TNumber}"/>. Mismatch throws — the
/// <c>2^{-n} mod M_p</c> arithmetic is invalid against any other modulus.
/// </para>
/// <para>
/// <b>Threat model.</b> Inherits the timing-CT properties of
/// <see cref="SafeGcd"/>: the outer iteration count is data-independent, and
/// every per-iteration arithmetic step uses <see cref="SecureBigInteger"/>
/// operations whose timing depends on the public bit-length of the modulus
/// (i.e. the Mersenne exponent), not on the secret operand values. The
/// <c>2^{-n} mod M_p</c> correction is computed via
/// <see cref="SecureBigInteger.Pow"/>, whose iteration count depends only on
/// the public correction exponent.
/// </para>
/// </remarks>
public sealed class MersenneSafeGcdAlgorithm : IExtendedGcdAlgorithm<SecureBigInteger>
{
    private readonly ISecurityLevelManager<SecureBigInteger> securityLevelManager;

    /// <summary>
    /// Initializes a new instance of the <see cref="MersenneSafeGcdAlgorithm"/> class.
    /// </summary>
    /// <param name="securityLevelManager">
    /// The security-level manager whose currently-configured Mersenne prime defines
    /// the modulus used by every <see cref="Compute"/> call. The manager is borrowed
    /// (not owned); ownership and disposal remain with the caller, matching the
    /// pattern of <see cref="SecretReconstructor{TNumber, TExtendedGcdAlgorithm, TExtendedGcdResult}"/>'s
    /// 2-arg constructor.
    /// </param>
    /// <exception cref="ArgumentNullException">
    /// <paramref name="securityLevelManager"/> is <see langword="null"/>.
    /// </exception>
    public MersenneSafeGcdAlgorithm(ISecurityLevelManager<SecureBigInteger> securityLevelManager)
    {
        this.securityLevelManager = securityLevelManager
            ?? throw new ArgumentNullException(nameof(securityLevelManager));
    }

    /// <inheritdoc />
    /// <remarks>
    /// <para>
    /// Computes the modular inverse of <paramref name="a"/> against the Mersenne prime
    /// supplied as <paramref name="b"/>. Internally calls
    /// <see cref="SafeGcd.ExtendedGcd"/> with <c>fInput = b</c> (odd by Mersenne-prime
    /// definition) and <c>gInput = a</c>, then applies the <c>2^{-n} mod M_p</c>
    /// correction.
    /// </para>
    /// <para>
    /// The returned <see cref="ExtendedGcdResult{TNumber}.BezoutCoefficients"/> are
    /// indexed pairwise with the <c>(a, b)</c> input pair: <c>[0]</c> pairs with
    /// <c>a</c> (the modular inverse when <c>gcd = 1</c>), <c>[1]</c> pairs with
    /// <c>b</c>. The Bezout identity <c>s·a + t·b ≡ gcd(a, b) (mod b)</c> holds
    /// modulo the Mersenne prime; both coefficients are reduced into <c>[0, M_p − 1]</c>.
    /// </para>
    /// <para>
    /// <see cref="ExtendedGcdResult{TNumber}.Quotients"/> are populated with zero
    /// placeholders. The Bernstein–Yang divsteps do not produce the trailing
    /// Euclidean-quotient pair returned by
    /// <see cref="ExtendedEuclideanAlgorithm{TNumber}"/>'s
    /// <c>±a/gcd</c> / <c>∓b/gcd</c> identity; consumers that depend on those values
    /// must use the Euclidean implementation instead.
    /// </para>
    /// </remarks>
    /// <exception cref="ArgumentNullException">
    /// <paramref name="a"/> or <paramref name="b"/> is <see langword="null"/>.
    /// </exception>
    /// <exception cref="ArgumentException">
    /// <paramref name="b"/> is not equal to the Mersenne prime currently configured
    /// on the security-level manager.
    /// </exception>
    public ExtendedGcdResult<SecureBigInteger> Compute(
        Calculator<SecureBigInteger> a,
        Calculator<SecureBigInteger> b)
    {
        if (a is null)
        {
            throw new ArgumentNullException(nameof(a));
        }

        if (b is null)
        {
            throw new ArgumentNullException(nameof(b));
        }

        int mersenneExponent = this.securityLevelManager.SecurityLevel;
        SecureBigInteger denominatorVal = a;
        SecureBigInteger primeVal = b;
        SecureBigInteger expectedPrime = this.securityLevelManager.MersennePrime;

        if (!primeVal.Equals(expectedPrime))
        {
            throw new ArgumentException(
                "Modulus must equal the Mersenne prime currently configured on the security-level manager.",
                nameof(b));
        }

        // SafeGcd contract: alpha * primeVal + beta * denominatorVal = 2^iter * gcd.
        // primeVal is odd & positive (Mersenne primes M_p = 2^p − 1 with p ≥ 2),
        // satisfying SafeGcd's fInput-must-be-odd-and-positive precondition.
        var (gcd, alpha, beta, iterations) =
            SafeGcd.ExtendedGcd(primeVal, denominatorVal, mersenneExponent);

        SecureBigInteger inv2n = null;
        SecureBigInteger sVal = null;
        SecureBigInteger tVal = null;
        SecureBigIntCalculator gcdCalc = null;
        SecureBigIntCalculator sCalc = null;
        SecureBigIntCalculator tCalc = null;
        Calculator<SecureBigInteger> qaCalc = null;
        Calculator<SecureBigInteger> qbCalc = null;

        try
        {
            // 2^p ≡ 1 (mod M_p)  ⇒  2^{-n} ≡ 2^{(p − n mod p) mod p} (mod M_p).
            int reducedIterations = iterations % mersenneExponent;
            int correctionExponent = reducedIterations == 0 ? 0 : mersenneExponent - reducedIterations;
            using (var two = new SecureBigInteger(2))
            using (var rawPow = two.Pow(correctionExponent))
            {
                inv2n = rawPow.MersenneModulo(mersenneExponent);
            }

            // Multiply Bezout coefficients by 2^{-n} mod M_p, then reduce.
            // s pairs with a (= denominator) ; when gcd = 1, s = a^{-1} mod M_p.
            // t pairs with b (= prime)        ; t reflects the prime side of the identity.
            using (var sProduct = beta * inv2n)
            {
                sVal = sProduct.MersenneModulo(mersenneExponent);
            }

            using (var tProduct = alpha * inv2n)
            {
                tVal = tProduct.MersenneModulo(mersenneExponent);
            }

            gcdCalc = new SecureBigIntCalculator(gcd);
            gcd = null;
            sCalc = new SecureBigIntCalculator(sVal);
            sVal = null;
            tCalc = new SecureBigIntCalculator(tVal);
            tVal = null;

            // Quotients are zero placeholders: the divsteps recurrence does not
            // expose the trailing Euclidean-quotient pair. See class remarks.
            qaCalc = Calculator<SecureBigInteger>.Zero;
            qbCalc = Calculator<SecureBigInteger>.Zero;

            var coefficients = new Calculator<SecureBigInteger>[] { sCalc, tCalc };
            var quotients = new[] { qaCalc, qbCalc };
            var result = new ExtendedGcdResult<SecureBigInteger>(gcdCalc, coefficients, quotients);

            // Ownership transferred to result; null locals so the catch path below
            // does not double-dispose.
            gcdCalc = null;
            sCalc = null;
            tCalc = null;
            qaCalc = null;
            qbCalc = null;
            return result;
        }
        finally
        {
            gcd?.Dispose();
            alpha.Dispose();
            beta.Dispose();
            inv2n?.Dispose();
            sVal?.Dispose();
            tVal?.Dispose();
            gcdCalc?.Dispose();
            sCalc?.Dispose();
            tCalc?.Dispose();
            qaCalc?.Dispose();
            qbCalc?.Dispose();
        }
    }
}