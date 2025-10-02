// ----------------------------------------------------------------------------
// <copyright file="IMersennePrimeProvider.cs" company="Private">
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

/// <summary>
/// Represents a provider for standard Mersenne primes, offering methods and properties
/// to validate and retrieve Mersenne prime exponents within a specific range.
/// </summary>
public interface IMersennePrimeProvider
{
    /// <summary>
    /// Gets the smallest known Mersenne prime exponent in the set of predefined
    /// Mersenne prime exponents.
    /// </summary>
    int MinMersennePrimeExponent { get; }

    /// <summary>
    /// Gets the largest known Mersenne prime exponent in the set of predefined
    /// Mersenne prime exponents.
    /// </summary>
    int MaxMersennePrimeExponent { get; }

    /// <summary>
    /// Determines whether the specified exponent corresponds to a valid Mersenne prime exponent.
    /// </summary>
    /// <param name="exponent">The exponent to check.</param>
    /// <returns><see langword="true"/> if the given exponent is a valid Mersenne prime exponent;
    /// otherwise, <see langword="false"/>.</returns>
    bool IsValidMersennePrimeExponent(int exponent);

    /// <summary>
    /// Retrieves the smallest Mersenne prime exponent that is greater than or equal to the specified minimum value.
    /// </summary>
    /// <param name="minValue">The minimum value to use when searching for the next Mersenne prime exponent.</param>
    /// <returns>The next Mersenne prime exponent that is greater than or equal to the specified minimum value.</returns>
    int GetNextMersennePrimeExponent(int minValue);

    /// <summary>
    /// Retrieves the index of the specified Mersenne prime exponent within a predefined list of known Mersenne prime exponents.
    /// </summary>
    /// <param name="mersenneExponent">The Mersenne prime exponent whose index is to be located.</param>
    /// <returns>The zero-based index of the given Mersenne prime exponent if it exists in the list; otherwise, -1.</returns>
    int GetIndexOfMersennePrimeExponent(int mersenneExponent);

    /// <summary>
    /// Retrieves the Mersenne prime exponent at the specified index from the list of known Mersenne prime exponents.
    /// </summary>
    /// <param name="index">The zero-based index of the desired Mersenne prime exponent.</param>
    /// <returns>The Mersenne prime exponent at the specified index.</returns>
    int GetMersennePrimeExponentByIndex(int index);
}