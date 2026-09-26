// ----------------------------------------------------------------------------
// <copyright file="ShamirsSecretSharingGeneratorsTest.cs" company="Private">
// Copyright (c) 2026 All Rights Reserved
// </copyright>
// <author>Sebastian Walther</author>
// <date>09/17/2026 00:00:00 AM</date>
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

using System.Collections.Generic;
using System.Linq;
using Xunit;

/// <summary>
/// Tests for the subset selection behind the property suites. The property tests claim to draw an
/// <em>arbitrary</em> qualifying subset; that claim rests entirely on
/// <see cref="ShamirsSecretSharingGenerators.Combination"/> being a bijection onto the
/// <c>C(n, k)</c> subsets, so it is checked here rather than assumed. The suites are backend-
/// agnostic, and so is this class — there is no mirrored counterpart.
/// </summary>
public class ShamirsSecretSharingGeneratorsTest
{
    /// <summary>
    /// Over the whole parameter space the property suites use, the ranks <c>[0, C(n, k) - 1]</c>
    /// map onto the k-element subsets of <c>{0, …, n - 1}</c> exactly once each: every result has
    /// the right size, holds distinct positions inside the set, and no two ranks collide. Counting
    /// the distinct results against <c>C(n, k)</c> closes the argument in both directions — an
    /// injective map onto a set of the same finite size is onto it as well.
    /// </summary>
    [Fact]
    public void Combination_OverTheGeneratedParameterSpace_IsABijectionOntoTheSubsets()
    {
        // Arrange — seven is the largest share count any property suite requests.
        const int maxShares = 7;

        // Act & Assert
        for (int numberOfShares = 2; numberOfShares <= maxShares; numberOfShares++)
        {
            for (int threshold = 2; threshold <= numberOfShares; threshold++)
            {
                int subsetCount = ShamirsSecretSharingGenerators.Binomial(numberOfShares, threshold);
                var distinct = new HashSet<string>();
                for (int rank = 0; rank < subsetCount; rank++)
                {
                    var positions = ShamirsSecretSharingGenerators.Combination(numberOfShares, threshold, rank);

                    Assert.Equal(threshold, positions.Length);
                    Assert.Equal(threshold, positions.Distinct().Count());
                    Assert.All(positions, position => Assert.InRange(position, 0, numberOfShares - 1));
                    distinct.Add(string.Join(",", positions));
                }

                Assert.Equal(subsetCount, distinct.Count);
            }
        }
    }

    /// <summary>
    /// The counting the generator bounds itself by. Pascal's rule and the symmetry are the two
    /// properties a wrong multiply/divide order would break, and the out-of-range cases have to
    /// answer zero rather than throw, because <see cref="ShamirsSecretSharingGenerators.Combination"/>
    /// reaches them on its last step.
    /// </summary>
    [Fact]
    public void Binomial_MatchesPascalsRuleAndTheKnownEdges()
    {
        // Act & Assert
        Assert.Equal(1, ShamirsSecretSharingGenerators.Binomial(0, 0));
        Assert.Equal(0, ShamirsSecretSharingGenerators.Binomial(3, -1));
        Assert.Equal(0, ShamirsSecretSharingGenerators.Binomial(3, 4));
        Assert.Equal(35, ShamirsSecretSharingGenerators.Binomial(7, 3));

        for (int n = 1; n <= 12; n++)
        {
            Assert.Equal(1, ShamirsSecretSharingGenerators.Binomial(n, 0));
            Assert.Equal(n, ShamirsSecretSharingGenerators.Binomial(n, 1));
            Assert.Equal(1, ShamirsSecretSharingGenerators.Binomial(n, n));
            for (int k = 0; k <= n; k++)
            {
                Assert.Equal(
                    ShamirsSecretSharingGenerators.Binomial(n, k),
                    ShamirsSecretSharingGenerators.Binomial(n, n - k));
                Assert.Equal(
                    ShamirsSecretSharingGenerators.Binomial(n, k),
                    ShamirsSecretSharingGenerators.Binomial(n - 1, k - 1) + ShamirsSecretSharingGenerators.Binomial(n - 1, k));
            }
        }
    }
}

#endif
