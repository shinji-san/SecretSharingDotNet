// ----------------------------------------------------------------------------
// <copyright file="SafeGcd.cs" company="Private">
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

using System;
using SecretSharingDotNet.Math.Numerics;

/// <summary>
/// Constant-time greatest-common-divisor computation following the
/// Bernstein–Yang "safegcd" / divsteps algorithm.
/// </summary>
/// <remarks>
/// <para>
/// <b>Reference.</b> Bernstein, Daniel J., and Bo-Yin Yang. "Fast
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
/// length at most <c>p</c>, <c>g</c> is zero and <c>|f|</c> equals the
/// gcd of the original inputs. The fixed iteration count is the central
/// constant-time guarantee.
/// </para>
/// <para>
/// <b>Implementation status (D8-step-1).</b> Operates on the public
/// <see cref="SecureBigInteger"/> arithmetic surface — every divstep
/// allocates two or three intermediate values via the existing CT
/// Add / Subtract / Divide ops from D4–D6. This is allocation-heavy but
/// algorithmically correct. Two follow-up steps are planned:
/// <list type="bullet">
///   <item>D8-step-2: transition-matrix tracking, returning the Bezout
///   coefficients alongside the gcd.</item>
///   <item>D8-step-3: wrap as <see cref="SecretSharingDotNet.Math.IExtendedGcdAlgorithm{TNumber}"/>
///   for the SecureBigInteger backend, replacing the variable-time
///   Euclidean recurrence in <see cref="ExtendedEuclideanAlgorithm{TNumber}"/>.
///   Limb-level allocation removal is a downstream perf optimisation
///   (related to memo R5).</item>
/// </list>
/// </para>
/// <para>
/// <b>CT contract.</b> The outer iteration count is fixed at the public
/// <paramref name="bitLengthBound"/>, independent of operand values.
/// Per-iteration branch selection (the three divstep arms) is
/// data-dependent on <c>δ</c> and <c>g</c>'s low bit; each branch performs
/// the same allocation count and arithmetic-op count, so per-iter
/// wall-clock time is approximately uniform across branches. Strict
/// branchless mask-select between precomputed alternatives is a future-
/// work optimisation aligned with the limb-level rewrite.
/// </para>
/// <para>
/// <b>Implementation provenance.</b> Implemented from the Bernstein–Yang
/// paper as the algorithmic reference, not from existing public-source
/// code (BoringSSL <c>bn_safegcd.c</c>, libsodium <c>scalar_invert</c>,
/// etc.). The divstep formula and iteration-count formula are taken from
/// the paper directly; the per-iteration code structure is a
/// straightforward translation into idiomatic C# on top of the existing
/// CT primitives in <see cref="SecureBigInteger"/>.
/// </para>
/// </remarks>
internal static class SafeGcd
{
    /// <summary>
    /// Computes the greatest common divisor of <paramref name="fInput"/>
    /// and <paramref name="gInput"/> via Bernstein–Yang divsteps.
    /// </summary>
    /// <param name="fInput">First operand. Must be positive and odd.</param>
    /// <param name="gInput">Second operand. Must be non-negative.</param>
    /// <param name="bitLengthBound">
    /// Public upper bound on the bit length of the operands. Drives the
    /// iteration count <c>ceil((49.39 × bitLengthBound + 80) / 17)</c>.
    /// For a modular-inverse computation modulo the Mersenne prime
    /// <c>M_p</c>, pass <c>p</c>.
    /// </param>
    /// <returns>A new <see cref="SecureBigInteger"/> holding the gcd. The
    /// caller takes ownership and must dispose.</returns>
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
    public static SecureBigInteger Gcd(SecureBigInteger fInput, SecureBigInteger gInput, int bitLengthBound)
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
            throw new ArgumentException("fInput must be positive and odd.", nameof(fInput));
        }

        if (gInput.Sign < 0)
        {
            throw new ArgumentException(string.Format(ErrorMessages.ValueLowerThanX, 0), nameof(gInput));
        }

        // Bernstein–Yang iteration count: ceil((49.39 p + 80) / 17). Computed in
        // integer arithmetic as ceil((4939 p + 8000) / 1700) → with the
        // standard "+ divisor − 1, integer-divide" rounding-up trick this is
        // (4939 p + 8000 + 1699) / 1700.
        int iterations = ((4939 * bitLengthBound) + 8000 + 1699) / 1700;

        SecureBigInteger f = new SecureBigInteger(fInput);
        SecureBigInteger g = new SecureBigInteger(gInput);
        int delta = 1;

        try
        {
            for (int i = 0; i < iterations; i++)
            {
                ApplyDivstep(ref f, ref g, ref delta);
            }

            // After n iterations g is zero and |f| equals gcd(fInput, gInput).
            // f may have flipped sign during the algorithm; take the absolute
            // value to return a non-negative representative.
            return f.Abs();
        }
        finally
        {
            f?.Dispose();
            g?.Dispose();
        }
    }

    /// <summary>
    /// Applies one divstep transformation to <paramref name="f"/>,
    /// <paramref name="g"/>, and <paramref name="delta"/> in place.
    /// </summary>
    /// <remarks>
    /// The previous instances of <paramref name="f"/> and
    /// <paramref name="g"/> are disposed before being replaced; the new
    /// instances become owned by the caller's locals via the <c>ref</c>
    /// parameters. Each branch allocates the same number of intermediates
    /// (one new <c>f</c>, one new <c>g</c>, plus at most one <c>using</c>
    /// scratch for the add or subtract), so the per-iter cost is
    /// approximately uniform across branches.
    /// </remarks>
    private static void ApplyDivstep(ref SecureBigInteger f, ref SecureBigInteger g, ref int delta)
    {
        bool gIsOdd = !g.IsEven;
        bool branch1 = delta > 0 && gIsOdd;

        SecureBigInteger newF;
        SecureBigInteger newG;
        int newDelta;

        if (branch1)
        {
            // δ > 0 and g odd: (δ, f, g) → (-δ, g, (g − f) / 2).
            // (g − f) is even because both g and the invariantly-odd f are odd.
            newF = new SecureBigInteger(g);
            using var diff = SecureBigInteger.Subtract(g, f);
            newG = diff / 2;
            newDelta = -delta;
        }
        else if (gIsOdd)
        {
            // δ ≤ 0 and g odd: (δ, f, g) → (δ + 1, f, (g + f) / 2).
            // (g + f) is even for the same parity reason.
            newF = new SecureBigInteger(f);
            using var sum = SecureBigInteger.Add(g, f);
            newG = sum / 2;
            newDelta = delta + 1;
        }
        else
        {
            // g even: (δ, f, g) → (δ + 1, f, g / 2).
            newF = new SecureBigInteger(f);
            newG = g / 2;
            newDelta = delta + 1;
        }

        f.Dispose();
        g.Dispose();
        f = newF;
        g = newG;
        delta = newDelta;
    }
}
