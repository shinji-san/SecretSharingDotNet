// ----------------------------------------------------------------------------
// <copyright file="ShamirsSecretSharingGenerators.cs" company="Private">
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

namespace SecretSharingDotNetTest.Cryptography.ShamirsSecretSharing;

using CsCheck;

/// <summary>
/// Shared CsCheck generators for the Shamir's Secret Sharing property tests. Backend-agnostic:
/// they yield raw secret bytes together with a valid share configuration, which both the
/// <c>BigInteger</c> and <c>SecureBigInteger</c> property suites feed into their respective
/// <see cref="SecretSharingDotNet.Cryptography.ShamirsSecretSharing.SecretSplitter{TNumber}"/>.
/// </summary>
/// <remarks>
/// The generated configurations always satisfy the Shamir constraint <c>2 ≤ threshold ≤ numberOfShares</c>.
/// Secret length and share count are bounded by the caller so the (slow) <c>SecureBigInteger</c>
/// backend can request a smaller space than the <c>BigInteger</c> backend.
/// </remarks>
internal static class ShamirsSecretSharingGenerators
{
    /// <summary>
    /// Generates a random secret, a valid <c>(threshold, numberOfShares)</c> configuration and a
    /// <c>subsetOffset</c> in <c>[0, numberOfShares - 1]</c>. The offset selects a wrap-around window
    /// of exactly <c>threshold</c> shares, i.e. an arbitrary qualifying subset.
    /// </summary>
    /// <param name="maxSecretLength">Inclusive upper bound for the generated secret length in bytes.</param>
    /// <param name="maxShares">Inclusive upper bound for the generated number of shares.</param>
    /// <returns>A generator of <c>(Secret, Threshold, NumberOfShares, SubsetOffset)</c> tuples.</returns>
    public static Gen<(byte[] Secret, int Threshold, int NumberOfShares, int SubsetOffset)> SubsetReconstruction(
        int maxSecretLength, int maxShares) =>
        Gen.Byte.Array[1, maxSecretLength].SelectMany(secret =>
            Gen.Int[2, maxShares].SelectMany(numberOfShares =>
                Gen.Int[2, numberOfShares].SelectMany(threshold =>
                    Gen.Int[0, numberOfShares - 1].Select(subsetOffset =>
                        (secret, threshold, numberOfShares, subsetOffset)))));

    /// <summary>
    /// Generates a random secret and a valid <c>(threshold, numberOfShares)</c> configuration, used to
    /// reconstruct from the complete (possibly over-determined) share set.
    /// </summary>
    /// <param name="maxSecretLength">Inclusive upper bound for the generated secret length in bytes.</param>
    /// <param name="maxShares">Inclusive upper bound for the generated number of shares.</param>
    /// <returns>A generator of <c>(Secret, Threshold, NumberOfShares)</c> tuples.</returns>
    public static Gen<(byte[] Secret, int Threshold, int NumberOfShares)> FullSetReconstruction(
        int maxSecretLength, int maxShares) =>
        Gen.Byte.Array[1, maxSecretLength].SelectMany(secret =>
            Gen.Int[2, maxShares].SelectMany(numberOfShares =>
                Gen.Int[2, numberOfShares].Select(threshold =>
                    (secret, threshold, numberOfShares))));
}

#endif
