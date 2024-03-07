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

/// <summary>
/// Extended Euclidean algorithm implementation
/// </summary>
/// <typeparam name="TNumber">Numeric data type (An integer type)</typeparam>
public class ExtendedEuclideanAlgorithm<TNumber> : IExtendedGcdAlgorithm<TNumber>
{
    /// <summary>
    /// Computes, in addition to the greatest common divisor of integers <paramref name="a"/> and <paramref name="b"/>, also the coefficients of Bézout's identity.
    /// </summary>
    /// <param name="a">An integer</param>
    /// <param name="b">An integer</param>
    /// <returns>For details: <see cref="ExtendedGcdResult{TNumber}"/></returns>
    /// <remarks>
    /// https://en.wikipedia.org/wiki/Modular_multiplicative_inverse#Computation 
    /// https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm#Example
    /// </remarks>
    public ExtendedGcdResult<TNumber> Compute(Calculator<TNumber> a, Calculator<TNumber> b)
    {
        var x = Calculator<TNumber>.Zero;
        var lastX = Calculator<TNumber>.One;
        var y = Calculator<TNumber>.One;
        var lastY = Calculator<TNumber>.Zero;
        var r = b;
        var lastR = a;
        while (r != Calculator<TNumber>.Zero)
        {
            checked
            {
                var quotient = lastR / r;
#if NET6_0_OR_GREATER
                (lastR, r) = (r, lastR - quotient * r);
                (lastX, x) = (x, lastX - quotient * x);
                (lastY, y) = (y, lastY - quotient * y);
#else
                var tmpR = r;
                r = lastR - quotient * r;
                lastR = tmpR;

                var tmpX = x;
                x = lastX - quotient * x;
                lastX = tmpX;

                var tmpY = y;
                y = lastY - quotient * y;
                lastY = tmpY;
#endif
            }
        }

        return new ExtendedGcdResult<TNumber>(lastR, [lastX, lastY], [x, y]);
    }
}
