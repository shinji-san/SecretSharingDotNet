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

        Calculator<TNumber> x = null;
        Calculator<TNumber> lastX = null;
        Calculator<TNumber> y = null;
        Calculator<TNumber> lastY = null;
        Calculator<TNumber> r = null;
        Calculator<TNumber> lastR = null;
        try
        {
            x = Calculator<TNumber>.Zero;
            lastX = Calculator<TNumber>.One;
            y = Calculator<TNumber>.One;
            lastY = Calculator<TNumber>.Zero;
            r = b.Clone();
            lastR = a.Clone();

            while (!r.IsZero)
            {
                checked
                {
                    using var quotient = lastR / r;
                    using var quotientTimesR = quotient * r;
                    using var quotientTimesX = quotient * x;
                    using var quotientTimesY = quotient * y;

                    var tmpR = r;
                    r = lastR - quotientTimesR;
                    lastR.Dispose();
                    lastR = tmpR;

                    var tmpX = x;
                    x = lastX - quotientTimesX;
                    lastX.Dispose();
                    lastX = tmpX;

                    var tmpY = y;
                    y = lastY - quotientTimesY;
                    lastY.Dispose();
                    lastY = tmpY;
                }
            }

            // r is zero at this point, still owned by us, and is not part of the
            // result — release it explicitly to avoid leaking the final iteration's
            // tail value.
            r.Dispose();
            r = null;

            var coefficients = new[] { lastX, lastY };
            var quotients = new[] { x, y };
            var result = new ExtendedGcdResult<TNumber>(lastR, coefficients, quotients);

            // Ownership of these calculators is now held by `result`. Null the locals
            // so the catch block below does not double-dispose values the result owns.
            lastR = lastX = lastY = x = y = null;
            return result;
        }
        catch
        {
            x?.Dispose();
            lastX?.Dispose();
            y?.Dispose();
            lastY?.Dispose();
            r?.Dispose();
            lastR?.Dispose();
            throw;
        }
    }
}
