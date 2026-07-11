// ----------------------------------------------------------------------------
// <copyright file="ShamirsSecretSharingConcurrencyTest.cs" company="Private">
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

namespace SecretSharingDotNetTest.Cryptography.ShamirsSecretSharing.SecureBigInteger;

using SecretSharingDotNet.Cryptography;
using SecretSharingDotNet.Cryptography.ShamirsSecretSharing;
using SecretSharingDotNet.Math;
using SecretSharingDotNet.Math.Numerics;
using System.Linq;
using System.Threading.Tasks;
using Xunit;

/// <summary>
/// Concurrency stress tests for Shamir's Secret Sharing over the <see cref="SecureBigInteger"/>
/// backend. They exercise the supported concurrency contract: many threads, each using their own
/// <see cref="SecretSplitter{TNumber}"/> and <see cref="SecretReconstructor{TNumber}"/> instances
/// (the latter over the constant-time <see cref="MersenneSafeGcdAlgorithm{TNumber}"/>), split and
/// reconstruct in parallel, and every round-trip must recover its own secret.
/// </summary>
/// <remarks>
/// A shared splitter/reconstructor is deliberately NOT exercised: it mutates its security level and
/// is documented as not thread-safe (architecture review item A7). The workload is smaller than the
/// <c>BigInteger</c> suite because <see cref="SecureBigInteger"/> arithmetic is considerably slower.
/// Opt-in via the <c>Category=Stress</c> trait; gated to net8.0+ (see <see cref="StressTraits"/>).
/// </remarks>
public class ShamirsSecretSharingConcurrencyTest
{
    /// <summary>
    /// Independent splitter/reconstructor instances used concurrently each recover their own secret.
    /// </summary>
    [Fact]
    [Trait(StressTraits.CategoryKey, StressTraits.CategoryValue)]
    public void ParallelRoundTrip_WithIndependentInstances_EachRecoversItsSecret()
    {
        // Arrange
        const int degreeOfParallelism = 8;
        const int roundTripsPerWorker = 5;

        // Act & Assert
        Parallel.For(0, degreeOfParallelism, worker =>
        {
            for (int iteration = 0; iteration < roundTripsPerWorker; iteration++)
            {
                using var secret = new Secret<SecureBigInteger>(BuildSecret(worker, iteration));
                using var secretSplitter = new SecretSplitter<SecureBigInteger>();
                using var secretReconstructor = new SecretReconstructor<SecureBigInteger>(new MersenneSafeGcdAlgorithm<SecureBigInteger>());
                using var shares = secretSplitter.MakeShares(3, 5, secret);

                var subset = shares.Take(3).ToArray();
                using var recovered = secretReconstructor.Reconstruction(subset);

                Assert.Equal(secret, recovered);
            }
        });
    }

    /// <summary>
    /// Builds a distinct, non-empty secret for the given worker/iteration so concurrent round-trips
    /// operate on varied inputs (and varied security levels via varied length).
    /// </summary>
    /// <param name="worker">The parallel worker index.</param>
    /// <param name="iteration">The per-worker iteration index.</param>
    /// <returns>A deterministic, distinct secret byte array of length 1..6.</returns>
    private static byte[] BuildSecret(int worker, int iteration)
    {
        int length = 1 + ((worker + iteration) % 6);
        var secretBytes = new byte[length];
        for (int j = 0; j < length; j++)
        {
            secretBytes[j] = (byte)((worker * 31) + (iteration * 7) + j + 1);
        }

        return secretBytes;
    }
}

#endif
