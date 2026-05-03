// ----------------------------------------------------------------------------
// <copyright file="IExtendedGcdResult`1.cs" company="Private">
// Copyright (c) 2022 All Rights Reserved
// </copyright>
// <author>Sebastian Walther</author>
// <date>08/20/2022 01:20:59 AM</date>
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
using System.Collections.ObjectModel;

/// <summary>
/// Represents the result of the extended greatest common divisor computation.
/// </summary>
/// <typeparam name="TNumber">Numeric data type</typeparam>
/// <remarks>
/// Owns the <see cref="Calculator{TNumber}"/> instances exposed via
/// <see cref="GreatestCommonDivisor"/>, <see cref="BezoutCoefficients"/>, and
/// <see cref="Quotients"/>. The caller takes ownership of the result returned by
/// <see cref="IExtendedGcdAlgorithm{TNumber, TExtendedGcdResult}.Compute"/> and must
/// dispose it; the contained calculators are released as part of disposal.
/// </remarks>
public interface IExtendedGcdResult<TNumber> : IDisposable
{
    /// <summary>
    /// Gets the greatest common divisor
    /// </summary>
    Calculator<TNumber> GreatestCommonDivisor { get; }

    /// <summary>
    /// Gets the Bézout coefficients <c>(s, t)</c> for the input pair <c>(a, b)</c>, satisfying
    /// <c>a·s + b·t = gcd(a, b)</c>.
    /// </summary>
    /// <remarks>
    /// Two-element collection: <c>BezoutCoefficients[0] = s</c> (paired with the first input
    /// <c>a</c>), <c>BezoutCoefficients[1] = t</c> (paired with the second input <c>b</c>).
    /// The pairing matches <see cref="Quotients"/>.
    /// </remarks>
    ReadOnlyCollection<Calculator<TNumber>> BezoutCoefficients { get; }

    /// <summary>
    /// Gets the trailing Bézout-coefficient pair — i.e. the running <c>(s, t)</c> pair carried
    /// past the final iteration of the extended Euclidean algorithm, when the residual reached
    /// zero.
    /// </summary>
    /// <remarks>
    /// Indexed pairwise with <see cref="BezoutCoefficients"/>: <c>Quotients[0]</c> corresponds
    /// to <c>BezoutCoefficients[0]</c> and likewise for <c>[1]</c>. For positive inputs the
    /// relationship <c>Quotients[0] = ±b/gcd(a, b)</c> and <c>Quotients[1] = ∓a/gcd(a, b)</c>
    /// holds (sign chosen by the iteration count's parity), which lets callers recover
    /// <c>a/gcd</c> and <c>b/gcd</c> without rerunning the algorithm.
    /// </remarks>
    ReadOnlyCollection<Calculator<TNumber>> Quotients { get; }
}