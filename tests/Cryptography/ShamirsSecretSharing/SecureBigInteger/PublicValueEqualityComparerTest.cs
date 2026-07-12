// ----------------------------------------------------------------------------
// <copyright file="PublicValueEqualityComparerTest.cs" company="Private">
// Copyright (c) 2026 All Rights Reserved
// </copyright>
// <author>Sebastian Walther</author>
// <date>07/12/2026 12:00:00 PM</date>
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

namespace SecretSharingDotNetTest.Cryptography.ShamirsSecretSharing.SecureBigInteger;

using SecretSharingDotNet.Cryptography.ShamirsSecretSharing;
using SecretSharingDotNet.Math;
using SecretSharingDotNet.Math.Numerics;
using System.Collections.Generic;
using Xunit;

/// <summary>
/// Tests for <see cref="PublicValueEqualityComparer{TNumber}"/> over the <see cref="SecureBigInteger"/>
/// backend — the comparer used to de-duplicate the public share indices in reconstruction. Guards the
/// O(n) distinctness check against the coarse metadata hash returned by
/// <see cref="SecureBigInteger.GetHashCode"/> (sign + limb count), which would otherwise collapse all
/// small positive one-limb indices into a single bucket.
/// </summary>
public class PublicValueEqualityComparerTest
{
    /// <summary>
    /// Distinct public indices must produce distinct hash codes, so the reconstruction distinctness
    /// <see cref="HashSet{T}"/> stays O(n) rather than collapsing into one bucket. With the raw
    /// <see cref="SecureBigInteger.GetHashCode"/> the resulting set would have a single entry.
    /// </summary>
    [Fact]
    public void GetHashCode_DistinctPublicIndices_ProducesDistinctHashes()
    {
        // Arrange — indices 1..count, exactly as the reconstruction distinctness check sees them.
        const int count = 64;
        var comparer = PublicValueEqualityComparer<SecureBigInteger>.Instance;
        var indices = new Calculator<SecureBigInteger>[count];
        try
        {
            for (int i = 0; i < count; i++)
            {
                indices[i] = new SecureBigInteger(i + 1);
            }

            // Act
            var hashes = new HashSet<int>();
            foreach (var index in indices)
            {
                hashes.Add(comparer.GetHashCode(index));
            }

            // Assert — no collapse to a shared bucket (the raw metadata hash would give Count == 1).
            Assert.Equal(count, hashes.Count);
        }
        finally
        {
            foreach (var index in indices)
            {
                index?.Dispose();
            }
        }
    }

    /// <summary>
    /// The comparer treats equal public values as equal (with equal hashes) and distinct values as
    /// distinct, matching <see cref="Calculator{TNumber}.Equals(Calculator{TNumber})"/>.
    /// </summary>
    [Fact]
    public void Equals_MatchesValueEquality()
    {
        // Arrange
        var comparer = PublicValueEqualityComparer<SecureBigInteger>.Instance;
        using Calculator<SecureBigInteger> five = new SecureBigInteger(5);
        using Calculator<SecureBigInteger> alsoFive = new SecureBigInteger(5);
        using Calculator<SecureBigInteger> seven = new SecureBigInteger(7);

        // Act & Assert
        Assert.True(comparer.Equals(five, alsoFive));
        Assert.Equal(comparer.GetHashCode(five), comparer.GetHashCode(alsoFive));
        Assert.False(comparer.Equals(five, seven));
    }
}
