// ----------------------------------------------------------------------------
// <copyright file="ISecurityLevelManager.cs" company="Private">
// Copyright (c) 2025 All Rights Reserved
// </copyright>
// <author>Sebastian Walther</author>
// <date>10/03/2025 01:07:09 AM</date>
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

namespace SecretSharingDotNet.Cryptography.ShamirsSecretSharing;

using Math;

/// <summary>
/// Manages security level configuration and provides the corresponding Mersenne prime.
/// </summary>
/// <typeparam name="TNumber">Numeric data type</typeparam>
public interface ISecurityLevelManager<TNumber>
{
    /// <summary>
    /// Gets or sets the security level (in bits).
    /// </summary>
    /// <exception cref="T:System.ArgumentOutOfRangeException">
    /// The value is outside the valid range of Mersenne prime exponents.
    /// </exception>
    int SecurityLevel { get; set; }

    /// <summary>
    /// Gets the Mersenne prime corresponding to the current security level.
    /// </summary>
    Calculator<TNumber> MersennePrime { get; }

    /// <summary>
    /// Adjusts the security level based on the provided maximum Y value.
    /// </summary>
    /// <param name="maximumY">The maximum Y value used to determine the security level.</param>
    /// <remarks>Use this method for reconstruction</remarks>
    void AdjustSecurityLevel(Calculator<TNumber> maximumY);
}
