// ----------------------------------------------------------------------------
// <copyright file="IInspectableSecurityLevelManager.cs" company="Private">
// Copyright (c) 2025 All Rights Reserved
// </copyright>
// <author>Sebastian Walther</author>
// <date>09/14/2026 10:00:00 PM</date>
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
/// Optional capability on top of <see cref="ISecurityLevelManager{TNumber}"/>: answers questions
/// about security levels <b>without moving the manager's state</b>.
/// </summary>
/// <typeparam name="TNumber">Numeric data type</typeparam>
/// <remarks>
/// <para>
/// Separate from <see cref="ISecurityLevelManager{TNumber}"/> on purpose. Adding these members
/// there would break every external implementation, and a default interface member is not
/// available on <c>netstandard2.0</c> or the <c>net4x</c> targets. A manager that does not
/// implement this interface stays fully supported: consumers of the capability fall back to
/// driving the manager through its own <see cref="ISecurityLevelManager{TNumber}.SecurityLevel"/>
/// setter and reading the value back. <b>Lacking this capability is not by itself an error.</b>
/// </para>
/// <para>
/// The two members answer different questions and neither substitutes for the other.
/// <see cref="IsValidSecurityLevel"/> asks "is exponent 18 admissible?" — no.
/// <see cref="DetermineSecurityLevel"/> asks "which field fits these values?" — possibly 19.
/// </para>
/// </remarks>
public interface IInspectableSecurityLevelManager<TNumber> : ISecurityLevelManager<TNumber>
{
    /// <summary>
    /// Reports whether <paramref name="securityLevel"/> is a Mersenne prime exponent this manager
    /// supports, <b>exactly</b> — without rounding up and without changing any state.
    /// </summary>
    /// <param name="securityLevel">The exponent to test.</param>
    /// <returns>
    /// <see langword="true"/> when the exponent is supported as given; otherwise
    /// <see langword="false"/>.
    /// </returns>
    /// <remarks>
    /// Deliberately unlike the <see cref="ISecurityLevelManager{TNumber}.SecurityLevel"/> setter,
    /// which normalises a non-Mersenne value upward. That normalisation is load-bearing for
    /// splitting, where the level is derived from the secret's byte size; it is wrong for a level
    /// supplied by a caller or read off a share, where silently using a different field than the
    /// one named is the defect this exists to prevent.
    /// </remarks>
    /// <exception cref="ObjectDisposedException">The implementation has been disposed.</exception>
    bool IsValidSecurityLevel(int securityLevel);

    /// <summary>
    /// Returns the smallest supported Mersenne prime exponent whose field still admits
    /// <paramref name="maximumY"/>, <b>without</b> changing
    /// <see cref="ISecurityLevelManager{TNumber}.SecurityLevel"/>.
    /// </summary>
    /// <param name="maximumY">The largest y-coordinate among the shares about to be processed.</param>
    /// <returns>The exponent <see cref="ISecurityLevelManager{TNumber}.AdjustSecurityLevel"/> would select.</returns>
    /// <remarks>
    /// The selection this performs is the same one
    /// <see cref="ISecurityLevelManager{TNumber}.AdjustSecurityLevel"/> performs; the difference is
    /// that the answer is returned instead of committed. That is what lets a caller validate its
    /// inputs against the resulting field before anything moves.
    /// </remarks>
    /// <exception cref="ArgumentNullException"><paramref name="maximumY"/> is <see langword="null"/>.</exception>
    /// <exception cref="ObjectDisposedException">The implementation has been disposed.</exception>
    int DetermineSecurityLevel(Calculator<TNumber> maximumY);
}
