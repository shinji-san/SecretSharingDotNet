// ----------------------------------------------------------------------------
// <copyright file="ShamirsSecretSharingPropertyTest.cs" company="Private">
// Copyright (c) 2026 All Rights Reserved
// </copyright>
// <author>Sebastian Walther</author>
// <date>07/11/2026 00:00:00 AM</date>
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

#if NET8_0_OR_GREATER

namespace SecretSharingDotNetTest.Cryptography.ShamirsSecretSharing.BigInteger;

using CsCheck;
using SecretSharingDotNet.Cryptography;
using SecretSharingDotNet.Cryptography.ShamirsSecretSharing;
using SecretSharingDotNet.Math;
using System.Linq;
using System.Numerics;
using Xunit;

/// <summary>
/// Property-based round-trip tests for Shamir's Secret Sharing over the <see cref="BigInteger"/>
/// backend. They assert the core Shamir invariant — any <c>threshold</c>-sized subset of the
/// generated shares reconstructs the original secret — across randomly generated secrets and
/// <c>(threshold, numberOfShares)</c> configurations, complementing the hand-authored InlineData suites.
/// </summary>
public class ShamirsSecretSharingPropertyTest
{
    /// <summary>
    /// Inclusive upper bound for the generated secret length in bytes.
    /// </summary>
    private const int MaxSecretLength = 32;

    /// <summary>
    /// Inclusive upper bound for the generated number of shares.
    /// </summary>
    private const int MaxShares = 7;

    /// <summary>
    /// Number of generated cases per property. Executed with <c>threads: 1</c> to honour the
    /// project-wide requirement that security-sensitive tests never run in parallel.
    /// </summary>
    private const int Iterations = 250;

    /// <summary>
    /// Any qualifying subset — exactly <c>threshold</c> of the <c>numberOfShares</c> generated shares —
    /// reconstructs the original secret.
    /// </summary>
    [Fact]
    public void Reconstruction_FromAnyThresholdSubset_RecoversSecret()
    {
        // Arrange
        var generator = ShamirsSecretSharingGenerators.SubsetReconstruction(MaxSecretLength, MaxShares);

        // Act & Assert
        generator.Sample((secretBytes, threshold, numberOfShares, subsetOffset) =>
        {
            using var secret = new Secret<BigInteger>(secretBytes);
            using var secretSplitter = new SecretSplitter<BigInteger>();
            using var secretReconstructor = new SecretReconstructor<BigInteger>(new ExtendedEuclideanAlgorithm<BigInteger>());
            using var shares = secretSplitter.MakeShares(threshold, numberOfShares, secret);

            // A wrap-around window of length threshold over the (index-sorted) shares is an
            // arbitrary qualifying subset; length ≤ numberOfShares guarantees distinct shares.
            var subset = shares.Concat(shares).Skip(subsetOffset).Take(threshold).ToArray();
            using var recovered = secretReconstructor.Reconstruction(subset);

            Assert.Equal(secret, recovered);
        }, iter: Iterations, threads: 1);
    }

    /// <summary>
    /// Reconstruction from the complete, over-determined share set (all <c>numberOfShares</c> shares,
    /// which is more than <c>threshold</c>) also recovers the original secret — extra shares beyond the
    /// threshold must not break recovery.
    /// </summary>
    [Fact]
    public void Reconstruction_FromFullShareSet_RecoversSecret()
    {
        // Arrange
        var generator = ShamirsSecretSharingGenerators.FullSetReconstruction(MaxSecretLength, MaxShares);

        // Act & Assert
        generator.Sample((secretBytes, threshold, numberOfShares) =>
        {
            using var secret = new Secret<BigInteger>(secretBytes);
            using var secretSplitter = new SecretSplitter<BigInteger>();
            using var secretReconstructor = new SecretReconstructor<BigInteger>(new ExtendedEuclideanAlgorithm<BigInteger>());
            using var shares = secretSplitter.MakeShares(threshold, numberOfShares, secret);

            using var recovered = secretReconstructor.Reconstruction(shares);

            Assert.Equal(secret, recovered);
        }, iter: Iterations, threads: 1);
    }
}

#endif
