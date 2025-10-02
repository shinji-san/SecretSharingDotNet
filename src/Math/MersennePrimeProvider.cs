// ----------------------------------------------------------------------------
// <copyright file="MersennePrimeProvider.cs" company="Private">
// Copyright (c) 2025 All Rights Reserved
// </copyright>
// <author>Sebastian Walther</author>
// <date>10/03/2025 01:07:01 AM</date>
// ----------------------------------------------------------------------------

#region License
// ----------------------------------------------------------------------------
// Copyright 2025 Sebastian Walther
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
using System.Threading;

/// <summary>
/// Provides a standard implementation of the <see cref="IMersennePrimeProvider"/> interface for working with
/// Mersenne prime exponents. This implementation contains a predefined array of known Mersenne prime exponents
/// and includes methods for validating and retrieving exponents within this predefined range.
/// </summary>
/// <remarks>
/// Mersenne primes are primes of the form 2^p - 1, where p is itself a prime number. This class offers
/// capabilities to check if a given exponent is a valid Mersenne prime exponent and to retrieve the next
/// available Mersenne prime exponent given a minimum value.
/// </remarks>
public sealed class MersennePrimeProvider : IMersennePrimeProvider
{
    /// <summary>
    /// Represents a collection of known prime exponents for generating Mersenne primes.
    /// Each value in this array corresponds to an exponent p such that 2^p - 1
    /// is Mersenne prime.
    /// </summary>
    private static readonly int[] KnownMersennePrimeExponents =
    [
        13, 17, 19, 31, 61, 89, 107, 127, 521, 607, 1279, 2203, 2281, 3217, 4253, 4423, 9689, 9941, 11213,
        19937, 21701, 23209, 44497, 86243, 110503, 132049, 216091, 756839, 859433, 1257787, 1398269, 2976221,
        3021377, 6972593, 13466917, 20996011, 24036583, 25964951, 30402457, 32582657, 37156667, 42643801, 43112609
    ];

    private MersennePrimeProvider()
    {
    }

    /// <inheritdoc />
    public bool IsValidMersennePrimeExponent(int exponent) => Array.BinarySearch(KnownMersennePrimeExponents, exponent) >= 0;

    /// <inheritdoc />
    public int MinMersennePrimeExponent => KnownMersennePrimeExponents[0];

    /// <inheritdoc />
    public int MaxMersennePrimeExponent => KnownMersennePrimeExponents[KnownMersennePrimeExponents.Length - 1];

    /// <summary>
    /// Provides a singleton instance of the <see cref="MersennePrimeProvider"/>.
    /// This instance is lazily initialized to ensure thread-safe and efficient access to
    /// methods for working with Mersenne prime exponents.
    /// </summary>
    public static readonly MersennePrimeProvider Instance = new Lazy<MersennePrimeProvider>(()=> new MersennePrimeProvider(), LazyThreadSafetyMode.ExecutionAndPublication).Value;

    /// <inheritdoc />
    public int GetNextMersennePrimeExponent(int minValue)
    {
        int index = Array.BinarySearch(KnownMersennePrimeExponents, minValue);

        if (index >= 0)
        {
            return KnownMersennePrimeExponents[index];
        }

        index = ~index;
        if (index >= KnownMersennePrimeExponents.Length)
        {
            throw new ArgumentOutOfRangeException(nameof(minValue), minValue,
                string.Format(ErrorMessages.NoValidMersennePrimeExponentAvailable, minValue));
        }

        return KnownMersennePrimeExponents[index];
    }

    /// <inheritdoc />
    public int GetIndexOfMersennePrimeExponent(int mersenneExponent) => Array.IndexOf(KnownMersennePrimeExponents, mersenneExponent);

    /// <inheritdoc />
    public int GetMersennePrimeExponentByIndex(int index) => KnownMersennePrimeExponents[index];
}
