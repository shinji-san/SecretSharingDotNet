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
    /// <c>subsetRank</c> in <c>[0, C(numberOfShares, threshold) - 1]</c>. The rank names one of the
    /// qualifying subsets through <see cref="Combination"/>, so <em>every</em> k-element subset is
    /// reachable.
    /// </summary>
    /// <param name="maxSecretLength">Inclusive upper bound for the generated secret length in bytes.</param>
    /// <param name="maxShares">Inclusive upper bound for the generated number of shares.</param>
    /// <returns>A generator of <c>(Secret, Threshold, NumberOfShares, SubsetRank)</c> tuples.</returns>
    /// <remarks>
    /// This replaced a <c>subsetOffset</c> in <c>[0, numberOfShares - 1]</c> that selected a
    /// wrap-around window over the index-sorted shares. A window is a qualifying subset, but only
    /// <c>n</c> of the <c>C(n, k)</c> of them, and the ones it names are exactly the contiguous
    /// runs — so no combination with an interior gap was ever tried. `Gen.Shuffle` was measured as
    /// an alternative and rejected: over 500 draws of <c>C(5, 3)</c> it reached 6 of the 10
    /// subsets, where the rank reaches all 10.
    /// </remarks>
    public static Gen<(byte[] Secret, int Threshold, int NumberOfShares, int SubsetRank)> SubsetReconstruction(
        int maxSecretLength, int maxShares) =>
        Gen.Byte.Array[1, maxSecretLength].SelectMany(secret =>
            Gen.Int[2, maxShares].SelectMany(numberOfShares =>
                Gen.Int[2, numberOfShares].SelectMany(threshold =>
                    Gen.Int[0, Binomial(numberOfShares, threshold) - 1].Select(subsetRank =>
                        (secret, threshold, numberOfShares, subsetRank)))));

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

    /// <summary>
    /// The binomial coefficient <c>C(n, k)</c>, i.e. how many k-element subsets a set of n elements
    /// has.
    /// </summary>
    /// <param name="n">The size of the set. Expected to be small; see the remarks.</param>
    /// <param name="k">The size of the subsets to count.</param>
    /// <returns><c>C(n, k)</c>, or zero when <paramref name="k"/> lies outside <c>[0, n]</c>.</returns>
    /// <remarks>
    /// The multiply-then-divide order is what keeps this exact: after <c>i</c> steps the running
    /// product is <c>C(n - k + i, i)</c>, an integer, so the division never truncates. It would
    /// overflow for large operands, which does not arise here — the property suites cap the share
    /// count at seven, where the largest value is <c>C(7, 3) = 35</c>.
    /// </remarks>
    public static int Binomial(int n, int k)
    {
        if (k < 0 || k > n)
        {
            return 0;
        }

        int result = 1;
        for (int i = 1; i <= k; i++)
        {
            result = result * (n - k + i) / i;
        }

        return result;
    }

    /// <summary>
    /// Maps a rank in <c>[0, C(n, k) - 1]</c> to the k-element subset of <c>{0, …, n - 1}</c> that
    /// sits at that position in lexicographic order.
    /// </summary>
    /// <param name="n">The size of the set to choose from.</param>
    /// <param name="k">The size of the subset to return.</param>
    /// <param name="rank">The zero-based position of the subset in lexicographic order.</param>
    /// <returns>The chosen positions, ascending and distinct.</returns>
    /// <remarks>
    /// The mapping is a bijection, which is the whole point: it turns one generated integer into an
    /// arbitrary qualifying subset without rejection sampling, and every subset has exactly one
    /// rank. Rank zero is <c>{0, …, k - 1}</c>, so a shrinking counterexample walks toward the
    /// first k shares rather than toward some arbitrary combination.
    /// </remarks>
    public static int[] Combination(int n, int k, int rank)
    {
        var positions = new int[k];
        int candidate = 0;
        for (int i = 0; i < k; i++)
        {
            // Skip the blocks of subsets that start with a smaller candidate: there are
            // C(n - candidate - 1, k - i - 1) subsets beginning with this candidate.
            while (true)
            {
                int block = Binomial(n - candidate - 1, k - i - 1);
                if (rank < block)
                {
                    break;
                }

                rank -= block;
                candidate++;
            }

            positions[i] = candidate;
            candidate++;
        }

        return positions;
    }
}

#endif
