// ----------------------------------------------------------------------------
// <copyright file="Polynomial.cs" company="Private">
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
using System.Collections.Generic;
using System.Linq;

/// <summary>
/// Polynomial operations in a finite field over <see cref="Calculator{TNumber}"/> coefficients.
/// </summary>
internal static class Polynomial
{
    /// <summary>
    /// Evaluates the polynomial with the given <paramref name="coefficients"/> at <paramref name="x"/>
    /// modulo the Mersenne prime <c>M_p = 2^<paramref name="mersenneExponent"/> - 1</c>,
    /// using Horner's scheme.
    /// </summary>
    /// <typeparam name="TNumber">Numeric data type.</typeparam>
    /// <param name="x">The x-coordinate (share index).</param>
    /// <param name="coefficients">Polynomial coefficients ordered from constant term upwards (index 0 = a0).</param>
    /// <param name="mersenneExponent">
    /// Positive Mersenne-prime exponent. The reduction at every Horner step
    /// routes through <see cref="Calculator{TNumber}.MersenneModulo(int)"/>,
    /// which on the SecureBigInteger backend is the constant-time fold-and-
    /// add specialisation introduced in D7.
    /// </param>
    /// <returns>A newly allocated <see cref="Calculator{TNumber}"/> representing <c>p(x) mod M_p</c>. The caller owns and must dispose it.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="x"/> or <paramref name="coefficients"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentOutOfRangeException">
    /// <paramref name="x"/> is zero (evaluating at <c>x = 0</c> would return
    /// the constant term <c>a₀</c> — i.e. the secret — and is disallowed); or
    /// <paramref name="mersenneExponent"/> is not positive.
    /// </exception>
    public static Calculator<TNumber> EvaluateAt<TNumber>(
        Calculator<TNumber> x,
        IEnumerable<Calculator<TNumber>> coefficients,
        int mersenneExponent)
    {
        if (x is null)
        {
            throw new ArgumentNullException(nameof(x));
        }

        if (coefficients is null)
        {
            throw new ArgumentNullException(nameof(coefficients));
        }

        if (mersenneExponent <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(mersenneExponent), mersenneExponent, string.Format(ErrorMessages.ValueLowerThanX, 1));
        }

        if (x.IsZero)
        {
            throw new ArgumentOutOfRangeException(nameof(x), ErrorMessages.ShareIndexMustBePositive);
        }

        var coefficientArray = coefficients as Calculator<TNumber>[] ?? coefficients.ToArray();

        // accumulator is allocated below and owned by us until ownership is transferred
        // to the caller on the return path. Declared outside the try-block so the catch
        // can dispose it on any exception thrown by the Horner-loop arithmetic
        // (operand-disposed, OOM, etc.) — without this guard the partially-built
        // accumulator would leak its pinned-limb buffer on the SecureBigInteger backend.
        Calculator<TNumber> accumulator = null;
        try
        {
            accumulator = Calculator<TNumber>.Zero;
            for (int index = coefficientArray.Length - 1; index >= 0; index--)
            {
                using var intermediateResult = accumulator * x;
                using var y = intermediateResult + coefficientArray[index];
                var accumulatorTemp = accumulator;
                accumulator = y.MersenneModulo(mersenneExponent);
                accumulatorTemp.Dispose();
            }

            var result = accumulator;
            // Ownership transferred to the caller. Null the local so the catch path
            // does not dispose a value the caller now owns.
            accumulator = null;
            return result;
        }
        catch
        {
            accumulator?.Dispose();
            throw;
        }
    }
}