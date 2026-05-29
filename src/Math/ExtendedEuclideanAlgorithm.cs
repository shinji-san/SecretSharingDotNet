// ----------------------------------------------------------------------------
// <copyright file="ExtendedEuclideanAlgorithm.cs" company="Private">
// Copyright (c) 2019 All Rights Reserved
// </copyright>
// <author>Sebastian Walther</author>
// <date>04/20/2019 10:52:28 PM</date>
// ----------------------------------------------------------------------------

#region License
// ----------------------------------------------------------------------------
// Copyright 2022 Sebastian Walther
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

/// <summary>
/// Extended Euclidean algorithm implementation
/// </summary>
/// <typeparam name="TNumber">Numeric data type (An integer type)</typeparam>
public sealed class ExtendedEuclideanAlgorithm<TNumber> : IExtendedGcdAlgorithm<TNumber>
{
    /// <inheritdoc />
    public ExtendedGcdResult<TNumber> Compute(Calculator<TNumber> a, Calculator<TNumber> b)
    {
        if (a is null)
        {
            throw new ArgumentNullException(nameof(a));
        }

        if (b is null)
        {
            throw new ArgumentNullException(nameof(b));
        }

        // Loop state tracks the standard `(r_i, s_i, t_i)` triple of the extended
        // Euclidean algorithm with the invariant a·s_i + b·t_i = r_i. `*Cur`
        // carries the current iteration's value, `*Prev` the previous iteration's.
        Calculator<TNumber> sCur = null;
        Calculator<TNumber> sPrev = null;
        Calculator<TNumber> tCur = null;
        Calculator<TNumber> tPrev = null;
        Calculator<TNumber> rCur = null;
        Calculator<TNumber> rPrev = null;
        try
        {
            sCur = Calculator<TNumber>.Zero;
            sPrev = Calculator<TNumber>.One;
            tCur = Calculator<TNumber>.One;
            tPrev = Calculator<TNumber>.Zero;
            rCur = b.Clone();
            rPrev = a.Clone();

            while (!rCur.IsZero)
            {
                checked
                {
                    using var quotient = rPrev / rCur;
                    using var quotientTimesR = quotient * rCur;
                    using var quotientTimesS = quotient * sCur;
                    using var quotientTimesT = quotient * tCur;

                    var tmpR = rCur;
                    rCur = rPrev - quotientTimesR;
                    rPrev.Dispose();
                    rPrev = tmpR;

                    var tmpS = sCur;
                    sCur = sPrev - quotientTimesS;
                    sPrev.Dispose();
                    sPrev = tmpS;

                    var tmpT = tCur;
                    tCur = tPrev - quotientTimesT;
                    tPrev.Dispose();
                    tPrev = tmpT;
                }
            }

            // rCur is zero at this point, still owned by us, and is not part of the
            // result — release it explicitly to avoid leaking the final iteration's
            // tail value.
            rCur.Dispose();
            rCur = null;

            // Loop invariant at this point:
            //   rPrev          = gcd(a, b)
            //   (sPrev, tPrev) = Bézout pair satisfying a·s + b·t = gcd
            //   (sCur,  tCur ) = trailing pair carried one iteration past gcd
            var coefficients = new[] { sPrev, tPrev };
            var quotients = new[] { sCur, tCur };
            var result = new ExtendedGcdResult<TNumber>(rPrev, coefficients, quotients);

            // Ownership of these calculators is now held by `result`. Null the locals
            // so the finally block below does not double-dispose values the result owns.
            rPrev = sPrev = tPrev = sCur = tCur = null;
            return result;
        }
        finally
        {
            // sCur / sPrev / tCur / tPrev / rCur / rPrev are nulled on the success
            // path above and non-null on a throw between their allocation and the
            // ownership-transfer line — null-conditional disposal handles both.
            // Mirrors the ownership-transfer cleanup pattern in
            // MersenneSafeGcdAlgorithm.Compute.
            sCur?.Dispose();
            sPrev?.Dispose();
            tCur?.Dispose();
            tPrev?.Dispose();
            rCur?.Dispose();
            rPrev?.Dispose();
        }
    }
}
