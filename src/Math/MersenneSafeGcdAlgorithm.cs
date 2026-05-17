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
/// Constant-time-capable extended-GCD algorithm computing modular inverses
/// against the Mersenne prime supplied as the modulus argument to
/// <see cref="Compute"/>. Implements the Bernstein–Yang "safegcd" / divsteps
/// recurrence (with Bezout-coefficient tracking) and applies the
/// <c>2^{-n}</c> correction needed to convert the algorithm's integer-form
/// Bezout identity into a modular inverse.
/// </summary>
/// <typeparam name="TNumber">Numeric data type (an integer type). Use
/// <see cref="SecureBigInteger"/> for the constant-time backend or
/// <see cref="System.Numerics.BigInteger"/> for the variable-time backend —
/// see the threat-model paragraph in the remarks for what the choice
/// implies.</typeparam>
/// <remarks>
/// <para>
/// <b>Algorithm reference.</b> Bernstein, Daniel J., and Bo-Yin Yang. "Fast
/// constant-time gcd computation and modular inversion." IACR Cryptology
/// ePrint Archive, 2019/266. https://gcd.cr.yp.to/safegcd-20190413.pdf
/// </para>
/// <para>
/// The algorithm replaces the Euclidean recurrence — whose iteration count
/// depends on the operand magnitudes — with a fixed-iteration divstep
/// transformation on a triple <c>(δ, f, g)</c>:
/// <code>
///   if δ &gt; 0 and g is odd:   (δ, f, g) → (-δ, g, (g − f) / 2)
///   else if g is odd:          (δ, f, g) → (δ + 1, f, (g + f) / 2)
///   else (g even):             (δ, f, g) → (δ + 1, f, g / 2)
/// </code>
/// After <c>n = ceil((49.39 p + 80) / 17)</c> iterations on inputs of bit
/// length at most <c>p</c>, <c>g</c> is zero and <c>|f|</c> equals the gcd of
/// the original inputs. The fixed iteration count is the central constant-time
/// guarantee — provided the per-iteration arithmetic is itself constant-time
/// (see threat-model paragraph below).
/// </para>
/// <para>
/// <b>Integer-form Bezout tracking.</b> A 2 × 2 transition matrix
/// <c>(u_f, v_f, u_g, v_g)</c> is updated alongside <c>(δ, f, g)</c> so that
/// for each iteration <c>k</c>:
/// <code>
///   2^k * f_k = u_f * fInput + v_f * gInput
///   2^k * g_k = u_g * fInput + v_g * gInput
/// </code>
/// Initial state at <c>k = 0</c>: <c>u_f = 1</c>, <c>v_f = 0</c>,
/// <c>u_g = 0</c>, <c>v_g = 1</c>. Per-divstep matrix updates are pure integer
/// add, subtract, and doubling — no division. After <c>n</c> iterations,
/// <c>2^n * gcd = ±(u_f * fInput + v_f * gInput)</c>; the sign is folded into
/// the returned coefficients so the caller-facing identity is always
/// <c>α · fInput + β · gInput = 2^n · gcd</c> with non-negative gcd.
/// </para>
/// <para>
/// <b>Mersenne-modulus correction.</b> The standard extended Euclidean
/// algorithm returns Bezout coefficients <c>(s, t)</c> satisfying
/// <c>a·s + b·t = gcd(a, b)</c> over <c>Z</c>. The integer-form divsteps
/// identity <c>α · f + β · g = 2^n · gcd(f, g)</c> carries the unwanted
/// <c>2^n</c> factor, which cannot be removed over <c>Z</c> in general — only
/// modulo a chosen modulus. For Mersenne primes <c>M_p = 2^p − 1</c>,
/// <c>2^p ≡ 1 (mod M_p)</c>, so <c>2^{-n} ≡ 2^{(p − n mod p) mod p} (mod M_p)</c>.
/// Multiplying the integer-form identity by <c>2^{-n}</c> yields, when
/// <c>gcd(a, b) = 1</c>, a true modular inverse of the denominator. This
/// class therefore returns Bezout coefficients that satisfy the identity
/// <em>modulo the configured Mersenne prime</em>, not over <c>Z</c>.
/// </para>
/// <para>
/// <b>Precondition.</b> <see cref="Compute"/>'s <c>b</c> argument must be a
/// Mersenne prime <c>M_p = 2^p − 1</c>. The exponent <c>p</c> is derived from
/// <c>b</c>'s bit length at call time; passing a non-Mersenne modulus produces
/// silently-wrong results because the <c>2^{-n} mod M_p</c> correction
/// arithmetic is only valid against a true Mersenne modulus. The single
/// in-product caller (<see cref="SecretReconstructor{TNumber, TExtendedGcdAlgorithm, TExtendedGcdResult}.DivMod"/>)
/// satisfies this precondition by construction.
/// </para>
/// <para>
/// <b>Threat model — backend-conditional.</b> The outer iteration count is
/// fixed at the public Mersenne exponent, independent of operand values.
/// Whether per-iteration work is itself constant-time depends on the
/// <see cref="Calculator{TNumber}"/> backend the type is instantiated with:
/// <list type="bullet">
///   <item>With <c>TNumber = </c><see cref="SecureBigInteger"/>, the
///   divstep loop's per-iter arithmetic flows through that backend's CT
///   primitives. Per-iter wall-clock time is approximately uniform across
///   branches and independent of secret operand values. The
///   <c>2^{-n} mod M_p</c> correction is computed via
///   <see cref="SecureBigInteger.Pow"/>, whose iteration count depends only on
///   the public correction exponent. This is the configuration the
///   threat-model guarantees of this library are written against.</item>
///   <item>With <c>TNumber = </c><see cref="System.Numerics.BigInteger"/>, the
///   algorithm is mathematically equivalent but per-iter wall-clock time is
///   variable on operand magnitude. The fixed iteration count alone does
///   <em>not</em> provide timing-side-channel resistance against a co-located
///   active attacker. Use this configuration only when the threat model
///   excludes timing side channels (e.g. trusted-local computation or
///   testing-/cross-check use cases).</item>
/// </list>
/// Strict branchless mask-select between precomputed alternatives is a
/// future-work optimisation aligned with a limb-level rewrite of the CT
/// primitives.
/// </para>
/// <para>
/// <b>Implementation provenance.</b> Implemented from the Bernstein–Yang
/// paper as the algorithmic reference, not from existing public-source code
/// (BoringSSL <c>bn_safegcd.c</c>, libsodium <c>scalar_invert</c>, etc.). The
/// divstep formula and iteration-count formula are taken from the paper
/// directly; the per-iteration code structure is a straightforward
/// translation into idiomatic C# on top of <see cref="Calculator{TNumber}"/>'s
/// operator surface.
/// </para>
/// </remarks>
public sealed class MersenneSafeGcdAlgorithm<TNumber> : IExtendedGcdAlgorithm<TNumber>
{
    /// <summary>
    /// Initializes a new instance of the <see cref="MersenneSafeGcdAlgorithm{TNumber}"/> class.
    /// </summary>
    /// <remarks>
    /// Stateless: the Mersenne exponent <c>p</c> is derived from the modulus
    /// passed to <see cref="Compute"/> at call time. No security-level manager
    /// is referenced, so the algorithm and the
    /// <see cref="SecretReconstructor{TNumber, TExtendedGcdAlgorithm, TExtendedGcdResult}"/>
    /// that consumes it cannot drift in their view of the configured prime.
    /// </remarks>
    public MersenneSafeGcdAlgorithm() { }

    /// <inheritdoc />
    /// <remarks>
    /// <para>
    /// Computes the modular inverse of <paramref name="a"/> against the Mersenne prime
    /// supplied as <paramref name="b"/>. Internally calls <see cref="ExtendedGcd"/>
    /// with <c>fInput = b</c> (odd by Mersenne-prime definition) and
    /// <c>gInput = a</c>, then applies the <c>2^{-n} mod M_p</c> correction.
    /// </para>
    /// <para>
    /// The Mersenne exponent <c>p</c> is read off <paramref name="b"/>'s bit length
    /// (since <c>M_p = 2^p − 1</c> has exactly <c>p</c> significant bits). Callers
    /// must pass a true Mersenne prime as <paramref name="b"/>; the precondition is
    /// not structurally validated, and a non-Mersenne modulus produces silently
    /// wrong results because the <c>2^{-n} mod M_p</c> correction relies on
    /// <c>2^p ≡ 1 (mod M_p)</c>.
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
    /// <paramref name="b"/> is even. Mersenne primes <c>M_p = 2^p - 1</c> are always
    /// odd; an even modulus is therefore guaranteed not to be a Mersenne prime. This
    /// parity check is a cheap defense-in-depth guard against the most likely misuse
    /// (e.g. passing a composite or an unrelated modulus); it does not prove that
    /// <paramref name="b"/> is a Mersenne prime — odd non-Mersenne values still
    /// produce the silently-wrong results documented above. Branches on the public
    /// modulus only, so CT-safe.
    /// </exception>
    public ExtendedGcdResult<TNumber> Compute(
        Calculator<TNumber> a,
        Calculator<TNumber> b)
    {
        if (a is null)
        {
            throw new ArgumentNullException(nameof(a));
        }

        if (b is null)
        {
            throw new ArgumentNullException(nameof(b));
        }

        if (b.IsEven)
        {
            throw new ArgumentException(ErrorMessages.MersenneModulusMustBeOdd, nameof(b));
        }

        int mersenneExponent = BitLengthOfPublicMersennePrime(b);

        // ExtendedGcd contract: alpha * b + beta * a = 2^iter * gcd.
        // b is the Mersenne prime (odd & positive, satisfying the
        // fInput-must-be-odd-and-positive precondition); a is the denominator.
        var (gcd, alpha, beta, iterations) = ExtendedGcd(b, a, mersenneExponent);

        Calculator<TNumber> inv2n = null;
        Calculator<TNumber> sCalc = null;
        Calculator<TNumber> tCalc = null;
        Calculator<TNumber> qaCalc = null;
        Calculator<TNumber> qbCalc = null;

        try
        {
            // 2^p ≡ 1 (mod M_p)  ⇒  2^{-n} ≡ 2^{(p − n mod p) mod p} (mod M_p).
            int reducedIterations = iterations % mersenneExponent;
            int correctionExponent = reducedIterations == 0 ? 0 : mersenneExponent - reducedIterations;
            using (var two = Calculator<TNumber>.Two)
            using (var rawPow = two.Pow(correctionExponent))
            {
                inv2n = rawPow.MersenneModulo(mersenneExponent);
            }

            // Multiply Bezout coefficients by 2^{-n} mod M_p, then reduce.
            // sCalc pairs with a (= denominator); when gcd = 1, sCalc = a^{-1} mod M_p.
            // tCalc pairs with b (= prime); reflects the prime side of the identity.
            using (var sProduct = beta * inv2n)
            {
                sCalc = sProduct.MersenneModulo(mersenneExponent);
            }

            using (var tProduct = alpha * inv2n)
            {
                tCalc = tProduct.MersenneModulo(mersenneExponent);
            }

            // Quotients are zero placeholders: the divsteps recurrence does not
            // expose the trailing Euclidean-quotient pair. See class remarks.
            qaCalc = Calculator<TNumber>.Zero;
            qbCalc = Calculator<TNumber>.Zero;

            var coefficients = new[] { sCalc, tCalc };
            var quotients = new[] { qaCalc, qbCalc };
            var result = new ExtendedGcdResult<TNumber>(gcd, coefficients, quotients);

            // Ownership of gcd / sCalc / tCalc / qaCalc / qbCalc transferred to
            // result; null locals so the finally below does not double-dispose.
            gcd = null;
            sCalc = null;
            tCalc = null;
            qaCalc = null;
            qbCalc = null;
            return result;
        }
        finally
        {
            // alpha / beta are loop-local owned by us; always dispose.
            // inv2n is a per-call temporary; always dispose.
            // gcd / sCalc / tCalc / qaCalc / qbCalc are nulled on success and
            // non-null on a throw between their allocation and the
            // ownership-transfer line — null-conditional disposal handles both.
            alpha?.Dispose();
            beta?.Dispose();
            inv2n?.Dispose();
            sCalc?.Dispose();
            tCalc?.Dispose();
            qaCalc?.Dispose();
            qbCalc?.Dispose();
            gcd?.Dispose();
        }
    }

    /// <summary>
    /// Computes the gcd of <paramref name="fInput"/> and <paramref name="gInput"/>
    /// together with integer-form Bezout coefficients <c>α</c> and <c>β</c>
    /// satisfying <c>α · fInput + β · gInput = 2^iterationCount · gcd</c> via the
    /// Bernstein–Yang divstep recurrence with 2 × 2 transition-matrix tracking.
    /// </summary>
    /// <param name="fInput">First operand. Must be positive and odd.</param>
    /// <param name="gInput">Second operand. Must be non-negative.</param>
    /// <param name="bitLengthBound">Public upper bound on the bit length
    /// of the operands. Drives the iteration count
    /// <c>ceil((49.39 × bitLengthBound + 80) / 17)</c>. For a modular-inverse
    /// computation modulo the Mersenne prime <c>M_p</c>, pass <c>p</c>.</param>
    /// <returns>A tuple <c>(gcd, alpha, beta, iterationCount)</c> with the
    /// gcd and the integer-form Bezout coefficients. The caller takes
    /// ownership of all three <see cref="Calculator{TNumber}"/> instances and
    /// must dispose them.</returns>
    /// <remarks>
    /// Per-divstep matrix updates (derived directly from the definitions of
    /// <c>f_{k+1}</c>, <c>g_{k+1}</c> in each branch):
    /// <list type="bullet">
    ///   <item>Branch 1 (δ &gt; 0, g_k odd):
    ///   u_f' = 2 u_g, v_f' = 2 v_g, u_g' = u_g − u_f, v_g' = v_g − v_f.</item>
    ///   <item>Branch 2 (δ ≤ 0, g_k odd):
    ///   u_f' = 2 u_f, v_f' = 2 v_f, u_g' = u_g + u_f, v_g' = v_g + v_f.</item>
    ///   <item>Branch 3 (g_k even):
    ///   u_f' = 2 u_f, v_f' = 2 v_f, u_g' = u_g, v_g' = v_g.</item>
    /// </list>
    /// After iteration <c>n</c>, <c>g_n = 0</c> and <c>|f_n| = gcd</c>;
    /// <c>2^n * gcd = ±(u_f * fInput + v_f * gInput)</c>, where the sign
    /// flips if <c>f_n &lt; 0</c>. The returned alpha, beta absorb that
    /// sign so the caller-facing identity is always
    /// <c>alpha * fInput + beta * gInput = 2^iterationCount * gcd</c> with
    /// non-negative gcd.
    /// </remarks>
    /// <exception cref="ArgumentNullException">
    /// <paramref name="fInput"/> or <paramref name="gInput"/> is null.
    /// </exception>
    /// <exception cref="ArgumentOutOfRangeException">
    /// <paramref name="bitLengthBound"/> is not positive.
    /// </exception>
    /// <exception cref="ArgumentException">
    /// <paramref name="fInput"/> is not positive and odd, or
    /// <paramref name="gInput"/> is negative.
    /// </exception>
    internal static (Calculator<TNumber> gcd, Calculator<TNumber> alpha, Calculator<TNumber> beta, int iterationCount)
        ExtendedGcd(Calculator<TNumber> fInput, Calculator<TNumber> gInput, int bitLengthBound)
    {
        if (fInput is null)
        {
            throw new ArgumentNullException(nameof(fInput));
        }

        if (gInput is null)
        {
            throw new ArgumentNullException(nameof(gInput));
        }

        if (bitLengthBound <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(bitLengthBound), bitLengthBound, string.Format(ErrorMessages.ValueLowerThanX, 1));
        }

        if (fInput.Sign <= 0 || fInput.IsEven)
        {
            throw new ArgumentException(ErrorMessages.OperandMustBePositiveAndOdd, nameof(fInput));
        }

        if (gInput.Sign < 0)
        {
            throw new ArgumentException(string.Format(ErrorMessages.ValueLowerThanX, 0), nameof(gInput));
        }

        int iterations = ((4939 * bitLengthBound) + 8000 + 1699) / 1700;

        Calculator<TNumber> f = fInput.Clone();
        Calculator<TNumber> g = gInput.Clone();
        Calculator<TNumber> uF = Calculator<TNumber>.One;
        Calculator<TNumber> vF = Calculator<TNumber>.Zero;
        Calculator<TNumber> uG = Calculator<TNumber>.Zero;
        Calculator<TNumber> vG = Calculator<TNumber>.One;
        Calculator<TNumber> two = Calculator<TNumber>.Two;
        int delta = 1;

        // Tail-allocated outputs declared outside the try-block so the finally
        // can dispose them on exception (e.g. OOM during one of the three
        // allocations below); cleared to null after ownership transfer to the
        // returned tuple so the success path does not double-dispose.
        Calculator<TNumber> gcd = null;
        Calculator<TNumber> alpha = null;
        Calculator<TNumber> beta = null;

        try
        {
            for (int i = 0; i < iterations; i++)
            {
                ApplyExtendedDivstep(two, ref f, ref g, ref delta, ref uF, ref vF, ref uG, ref vG);
            }

            // Sign-correct the Bezout coefficients so the returned identity is
            // alpha * fInput + beta * gInput = 2^iterationCount * |f_n|.
            bool fIsNegative = f.Sign < 0;
            gcd = f.Abs();
            alpha = fIsNegative ? Negate(uF) : uF.Clone();
            beta = fIsNegative ? Negate(vF) : vF.Clone();

            var result = (gcd, alpha, beta, iterations);
            // Ownership transferred to the returned tuple.
            gcd = alpha = beta = null;
            return result;
        }
        finally
        {
            f?.Dispose();
            g?.Dispose();
            uF?.Dispose();
            vF?.Dispose();
            uG?.Dispose();
            vG?.Dispose();
            two?.Dispose();
            // On the success path these are null; on a throw between the
            // tail allocations and the ownership-transfer assignment, the
            // partially-allocated values are released here.
            gcd?.Dispose();
            alpha?.Dispose();
            beta?.Dispose();
        }
    }

    /// <summary>
    /// Returns the additive negation of <paramref name="x"/> as a freshly-owned
    /// <see cref="Calculator{TNumber}"/>, computed via <c>0 − x</c>. The caller
    /// takes ownership and must dispose.
    /// </summary>
    /// <remarks>
    /// <see cref="Calculator{TNumber}"/> does not expose a unary-minus surface,
    /// so the sign-flip path of <see cref="ExtendedGcd"/> routes through this
    /// helper instead. The transient <see cref="Calculator{TNumber}.Zero"/>
    /// instance is local to this helper.
    /// </remarks>
    private static Calculator<TNumber> Negate(Calculator<TNumber> x)
    {
        using var zero = Calculator<TNumber>.Zero;
        return zero - x;
    }

    /// <summary>
    /// Applies one extended divstep transformation, updating the working
    /// values <paramref name="f"/>, <paramref name="g"/>,
    /// <paramref name="delta"/> together with the four matrix entries
    /// <paramref name="uF"/>, <paramref name="vF"/>, <paramref name="uG"/>,
    /// <paramref name="vG"/> in lock-step. All previous instances are
    /// disposed before being replaced. <paramref name="two"/> is the
    /// <see cref="Calculator{TNumber}.Two"/> constant pre-allocated once
    /// per <see cref="ExtendedGcd"/> call, reused across all iterations.
    /// </summary>
    private static void ApplyExtendedDivstep(
        Calculator<TNumber> two,
        ref Calculator<TNumber> f, ref Calculator<TNumber> g, ref int delta,
        ref Calculator<TNumber> uF, ref Calculator<TNumber> vF,
        ref Calculator<TNumber> uG, ref Calculator<TNumber> vG)
    {
        bool gIsOdd = !g.IsEven;
        bool branch1 = delta > 0 && gIsOdd;

        // Each branch performs four to seven fresh allocations. If the n-th
        // allocation throws (OOM), the prior n-1 must be released or they
        // leak — every branch declares its outputs as nullable locals up
        // front and the catch clause releases whatever was allocated before
        // the throw. Past the catch the new state is fully committed; the
        // tail's Dispose-then-swap operates on values that are not expected
        // to throw (Dispose() is robust on both CT and BCL backends).
        Calculator<TNumber> newF = null;
        Calculator<TNumber> newG = null;
        Calculator<TNumber> newUF = null;
        Calculator<TNumber> newVF = null;
        Calculator<TNumber> newUG = null;
        Calculator<TNumber> newVG = null;
        int newDelta;

        try
        {
            if (branch1)
            {
                newF = g.Clone();
                using var diff = g - f;
                newG = diff / two;
                newUF = uG + uG;
                newVF = vG + vG;
                newUG = uG - uF;
                newVG = vG - vF;
                newDelta = -delta;
            }
            else if (gIsOdd)
            {
                newF = f.Clone();
                using var sum = g + f;
                newG = sum / two;
                newUF = uF + uF;
                newVF = vF + vF;
                newUG = uG + uF;
                newVG = vG + vF;
                newDelta = delta + 1;
            }
            else
            {
                newF = f.Clone();
                newG = g / two;
                newUF = uF + uF;
                newVF = vF + vF;
                newUG = uG.Clone();
                newVG = vG.Clone();
                newDelta = delta + 1;
            }
        }
        catch
        {
            newF?.Dispose();
            newG?.Dispose();
            newUF?.Dispose();
            newVF?.Dispose();
            newUG?.Dispose();
            newVG?.Dispose();
            throw;
        }

        f.Dispose();
        g.Dispose();
        uF.Dispose();
        vF.Dispose();
        uG.Dispose();
        vG.Dispose();
        f = newF;
        g = newG;
        uF = newUF;
        vF = newVF;
        uG = newUG;
        vG = newVG;
        delta = newDelta;
    }

    /// <summary>
    /// Returns the bit length of <paramref name="publicValue"/> — i.e. the
    /// position of its highest set bit, 1-indexed (0 for zero). For a Mersenne
    /// prime <c>M_p = 2^p − 1</c>, this is exactly <c>p</c>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Variable-time on operand magnitude.</b> The high-byte location and
    /// its leading-zero count both depend on the operand value. This helper is
    /// deliberately scoped <c>private static</c> on
    /// <see cref="MersenneSafeGcdAlgorithm{TNumber}"/> rather than exposed as a
    /// general accessor, so the only call site is <see cref="Compute"/>'s
    /// exponent-derivation path — where the argument is the public Mersenne-prime
    /// modulus <c>b</c>. Callers cannot reach this method on secret material,
    /// which preserves the constant-time contract of the secret-bearing
    /// arithmetic path for the SecureBigInteger backend.
    /// </para>
    /// <para>
    /// Implementation: scan from the most-significant byte of the magnitude
    /// downward via <see cref="Calculator.ByteRepresentation"/> (inherited
    /// from the non-generic <see cref="Calculator"/> base), find the first
    /// non-zero byte, then count significant bits in it. Two's-
    /// complement sign-extension padding (one trailing <c>0x00</c> byte when the
    /// magnitude's high-byte MSB is set) is transparently absorbed by the
    /// leading-zero scan. For known Mersenne exponents (all odd primes ≥ 2), no
    /// padding occurs in practice.
    /// </para>
    /// </remarks>
    private static int BitLengthOfPublicMersennePrime(Calculator<TNumber> publicValue)
    {
        using var bytes = publicValue.ByteRepresentation;
        int idx = bytes.Length - 1;
        while (idx >= 0 && bytes[idx] == 0)
        {
            idx--;
        }

        if (idx < 0)
        {
            return 0;
        }

        byte highByte = bytes[idx];
        int bitsInHighByte = 0;
        while (highByte != 0)
        {
            bitsInHighByte++;
            highByte >>= 1;
        }

        return (idx * 8) + bitsInHighByte;
    }
}