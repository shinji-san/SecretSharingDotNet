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
using System;

/// <summary>
/// Manages security level configuration and provides the corresponding Mersenne prime.
/// </summary>
/// <typeparam name="TNumber">Numeric data type</typeparam>
public interface ISecurityLevelManager<TNumber> : IDisposable
{
    /// <summary>
    /// Gets or sets the security level (in bits), expressed as a Mersenne prime exponent.
    /// </summary>
    /// <remarks>
    /// The setter rounds non-Mersenne values up to the next valid Mersenne prime exponent
    /// (e.g. setting <c>20</c> stores <c>31</c>, the next exponent in the predefined list).
    /// A subsequent get therefore can return a value that differs from what was assigned.
    /// Reading the setter back is the reliable way to discover the level the manager
    /// actually ended up using.
    /// </remarks>
    /// <exception cref="T:System.ArgumentOutOfRangeException">
    /// The value is outside the valid range of Mersenne prime exponents.
    /// </exception>
    /// <exception cref="ObjectDisposedException">The implementation has been disposed.</exception>
    int SecurityLevel { get; set; }

    /// <summary>
    /// Gets the Mersenne prime corresponding to the current security level.
    /// </summary>
    /// <remarks>
    /// The returned <see cref="Calculator{TNumber}"/> is owned by this manager and must not
    /// be disposed by the caller. The reference becomes invalid after the next assignment
    /// to <see cref="SecurityLevel"/> (which disposes the previous prime) and after
    /// <see cref="IDisposable.Dispose"/>.
    /// </remarks>
    /// <exception cref="ObjectDisposedException">The implementation has been disposed.</exception>
    Calculator<TNumber> MersennePrime { get; }

    /// <summary>
    /// Fits <see cref="SecurityLevel"/> to the smallest Mersenne prime exponent for which
    /// <paramref name="maximumY"/> still reduces to itself modulo the corresponding prime —
    /// i.e. the smallest finite field that can hold <paramref name="maximumY"/>.
    /// </summary>
    /// <param name="maximumY">The largest y-coordinate among the shares about to be processed.</param>
    /// <remarks>
    /// Use during reconstruction: callers pass the maximum share value, and the manager picks
    /// the tightest Mersenne prime that still admits all share values. The level may be raised
    /// or lowered relative to the current one. Implementations should mutate
    /// <see cref="SecurityLevel"/> at most once so concurrent readers do not observe transient
    /// intermediate values.
    /// </remarks>
    /// <exception cref="ArgumentNullException"><paramref name="maximumY"/> is <see langword="null"/>.</exception>
    /// <exception cref="ObjectDisposedException">The implementation has been disposed.</exception>
    void AdjustSecurityLevel(Calculator<TNumber> maximumY);
}
