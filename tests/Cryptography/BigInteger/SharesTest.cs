// ----------------------------------------------------------------------------
// <copyright file="SharesTest.cs" company="Private">
// Copyright (c) 2019 All Rights Reserved
// </copyright>
// <author>Sebastian Walther</author>
// <date>04/20/2019 10:52:28 PM</date>
// ----------------------------------------------------------------------------

#region License
// ----------------------------------------------------------------------------
// Copyright 2019 Sebastian Walther
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

namespace SecretSharingDotNetTest.Cryptography.BigInteger;

using SecretSharingDotNet.Cryptography;
using SecretSharingDotNet.Cryptography.SecureArray;
using SecretSharingDotNet.Cryptography.SecureInput;
using SecretSharingDotNet.Extension;
using SecretSharingDotNet.Math.Numerics;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using Xunit;

/// <summary>
/// Unit test of the <see cref="Shares{TNumber}"/> class.
/// </summary>
public class SharesTest
{
    /// <summary>
    /// Tests the Contains method of the <see cref="Shares{TNumber}"/> class
    /// to verify that it returns true when a specified share exists
    /// within the collection.
    /// </summary>
    /// <param name="index">The index of the share in the predefined shares collection to validate its presence in the collection.</param>
    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    public void Contains_ShareExists_ReturnsTrue(int index)
    {
        // Arrange
        using var lines = TestData.GetPredefinedShares().ToPinnedSecureShareLines();
        using var sharesCollection = Shares<BigInteger>.FromTextLines(lines);
        using var sharePinned = TestData.GetPredefinedShares()[index].ToPinnedSecure();
        using var expectedShare = new Share<BigInteger>(sharePinned);

        // Act & Assert
        Assert.Contains(expectedShare, sharesCollection);
    }

    /// <summary>
    /// Tests the Contains method of the <see cref="Shares{TNumber}"/> class
    /// to verify that it returns false when a specified share does not exist
    /// within the collection.
    /// </summary>
    [Fact]
    public void Contains_ShareDoesNotExist_ReturnsFalse()
    {
        // Arrange
        using var lines = TestData.GetPredefinedShares().ToPinnedSecureShareLines();
        using var sharesCollection = Shares<BigInteger>.FromTextLines(lines);
        using var nonExistingPinned = "4-9999999999999999999999".ToPinnedSecure();
        using var nonExistingShare = new Share<BigInteger>(nonExistingPinned);

        // Act & Assert
        Assert.DoesNotContain(nonExistingShare, sharesCollection);
    }

    /// <summary>
    /// Verifies that the <see cref="Shares{TNumber}.ToString"/> method returns a string representation
    /// that accurately reflects the expected format and content of the shares.
    /// </summary>
    [Fact]
    public void ToString_ReturnsExpectedString()
    {
        // Arrange
        var text = string.Join(Environment.NewLine, TestData.GetPredefinedShares()) + Environment.NewLine;
        using var blob = text.ToPinnedSecure();
        using var shares = Shares<BigInteger>.FromText(blob);

        // Act & Assert
#if DEBUG
        Assert.Equal(text, shares.ToString());
#else
        Assert.Equal(TestData.SecuredValueSentinel, shares.ToString());
#endif
    }

    /// <summary>
    /// Verifies that the <see cref="Shares{TNumber}"/> class implements the
    /// <see cref="IEnumerable"/> interface correctly and returns an enumerator
    /// that iterates through the collection as expected.
    /// </summary>
    [Fact]
    public void GetEnumerator_ReturnsExpectedEnumerator()
    {
        // Arrange
        using var lines = TestData.GetPredefinedShares().ToPinnedSecureShareLines();
        using var shares = Shares<BigInteger>.FromTextLines(lines);
        var testDataArray = TestData.GetPredefinedShares()
            .Select(entry =>
            {
                using var p = entry.ToPinnedSecure();
                return new Share<BigInteger>(p);
            })
            .ToArray();

        try
        {
            // Act
            var actual = ((IEnumerable)shares).GetEnumerator();
            using var disposable = actual as IDisposable;
            var expected = testDataArray.GetEnumerator();

            // Assert
            for (var i = 0; i < testDataArray.Length; i++)
            {
                Assert.Equal(expected.MoveNext(), actual.MoveNext());
                Assert.Equal(expected.Current, actual.Current);
            }

            Assert.True(shares.SequenceEqual(testDataArray));
        }
        finally
        {
            testDataArray.DisposeAll();
        }
    }

    /// <summary>
    /// Tests that <see cref="Shares{TNumber}.Count"/> reports the number of shares parsed
    /// from the pre-defined predefined-shares fixture.
    /// </summary>
    [Fact]
    public void Count_ReturnsExpectedCount()
    {
        // Arrange
        using var lines = TestData.GetPredefinedShares().ToPinnedSecureShareLines();
        using var shares = Shares<BigInteger>.FromTextLines(lines);
        var expectedCount = TestData.GetPredefinedShares().Length;

        // Act
        var actualCount = shares.Count;

        // Assert
        Assert.Equal(expectedCount, actualCount);
    }

    /// <summary>
    /// Tests that the <see cref="Shares{TNumber}"/> indexer returns the share at each
    /// expected position — verified by independently parsing each predefined share line
    /// and comparing against <c>shares[i]</c>.
    /// </summary>
    [Fact]
    public void Indexer_ReturnsExpectedShare()
    {
        // Arrange
        using var lines = TestData.GetPredefinedShares().ToPinnedSecureShareLines();
        using var shares = Shares<BigInteger>.FromTextLines(lines);
        var entries = TestData.GetPredefinedShares();

        // Act & Assert
        Assert.All(Enumerable.Range(0, entries.Length), i =>
        {
            using var p = entries[i].ToPinnedSecure();
            using var expected = new Share<BigInteger>(p);
            Assert.Equal(expected, shares[i]);
        });
    }

    /// <summary>
    /// Tests that <see cref="Shares{TNumber}.CopyTo"/> with offset 0 fills the destination
    /// array with the same shares in the same order as the source collection.
    /// </summary>
    [Fact]
    public void CopyTo_CopiesSharesToArray()
    {
        // Arrange
        using var lines = TestData.GetPredefinedShares().ToPinnedSecureShareLines();
        using var shares = Shares<BigInteger>.FromTextLines(lines);
        var sharesArray = new Share<BigInteger>[shares.Count];

        // Act
        shares.CopyTo(sharesArray, 0);

        // Assert
        Assert.Equal(shares, sharesArray);
    }

    /// <summary>
    /// Tests <see cref="Shares{TNumber}.CopyTo"/> with a non-zero <c>arrayIndex</c> that
    /// just fits the destination — slots before the offset remain at their default
    /// (<see langword="null"/>) and the shares fill the tail exactly.
    /// </summary>
    [Fact]
    public void CopyTo_ExactFitWithOffset_Succeeds()
    {
        // Arrange — array is sized Count + 2 with 2-slot prefix padding.
        using var lines = TestData.GetPredefinedShares().ToPinnedSecureShareLines();
        using var shares = Shares<BigInteger>.FromTextLines(lines);
        var target = new Share<BigInteger>[shares.Count + 2];

        // Act — fills target[2 .. Count+1] exactly.
        shares.CopyTo(target, arrayIndex: 2);

        // Assert
        Assert.Null(target[0]);
        Assert.Null(target[1]);
        Assert.Equal(shares, target.Skip(2));
    }

    /// <summary>
    /// Tests that <see cref="Shares{TNumber}.CopyTo"/> throws <see cref="ArgumentException"/>
    /// when <c>arrayIndex</c> is high enough that the destination cannot accommodate the
    /// full source. Regression for an off-by-one that previously let this case slip past
    /// the guard and fail with <see cref="IndexOutOfRangeException"/> deeper in the copy.
    /// </summary>
    [Fact]
    public void CopyTo_OffsetLeavesTooFewSlots_ThrowsArgumentException()
    {
        // Arrange — target has Count+2 slots, but offset leaves only Count-1 remaining.
        using var lines = TestData.GetPredefinedShares().ToPinnedSecureShareLines();
        using var shares = Shares<BigInteger>.FromTextLines(lines);
        var target = new Share<BigInteger>[shares.Count + 2];
        var offset = target.Length - shares.Count + 1;

        // Act & Assert — previously hidden behind an off-by-one that let this pass the guard
        // and crash at array[i + arrayIndex] with IndexOutOfRangeException.
        Assert.Throws<ArgumentException>(() => shares.CopyTo(target, offset));
    }

    /// <summary>
    /// Tests that <see cref="Shares{TNumber}.CopyTo"/> rejects a negative
    /// <c>arrayIndex</c> with <see cref="ArgumentOutOfRangeException"/>.
    /// </summary>
    [Fact]
    public void CopyTo_NegativeArrayIndex_ThrowsArgumentOutOfRangeException()
    {
        // Arrange
        using var lines = TestData.GetPredefinedShares().ToPinnedSecureShareLines();
        using var shares = Shares<BigInteger>.FromTextLines(lines);
        var target = new Share<BigInteger>[shares.Count];

        // Act & Assert
        Assert.Throws<ArgumentOutOfRangeException>(() => shares.CopyTo(target, -1));
    }

    /// <summary>
    /// Tests that <see cref="Shares{TNumber}.IsReadOnly"/> returns <see langword="true"/> —
    /// once parsed, the collection cannot be mutated.
    /// </summary>
    [Fact]
    public void IsReadOnly_ReturnsTrue()
    {
        // Arrange
        using var lines = TestData.GetPredefinedShares().ToPinnedSecureShareLines();
        using var shares = Shares<BigInteger>.FromTextLines(lines);

        // Act
        var isReadOnly = shares.IsReadOnly;

        // Assert
        Assert.True(isReadOnly);
    }

    /// <summary>
    /// Tests that <see cref="Shares{TNumber}.FromTextLines"/> populates the collection with
    /// one share per source line, comparing each parsed share against an independent
    /// per-line parse.
    /// </summary>
    [Fact]
    public void Constructor_WithPinnedBuffer_InitializesShares()
    {
        // Arrange
        var stringArray = TestData.GetPredefinedShares();
        using var lines = stringArray.ToPinnedSecureShareLines();

        // Act
        using var shares = Shares<BigInteger>.FromTextLines(lines);

        // Assert
        Assert.Equal(stringArray.Length, shares.Count);
        Assert.All(Enumerable.Range(0, stringArray.Length), i =>
        {
            using var p = stringArray[i].ToPinnedSecure();
            using var expected = new Share<BigInteger>(p);
            Assert.Equal(expected, shares[i]);
        });
    }

    /// <summary>
    /// Tests that <see cref="Shares{TNumber}.FromTextLines"/> sorts the parsed shares by
    /// x-coordinate ascending even if the input lines are out of order — a Shamir
    /// reconstruction requires the ordering to be canonical.
    /// </summary>
    [Fact]
    public void AscendingOrder_WithPinnedLines_SortsSharesByIndex()
    {
        // Arrange
        var stringArray = new[]
        {
            "3-300",
            "1-100",
            "2-200"
        };
        using var lines = stringArray.ToPinnedSecureShareLines();

        // Act
        using var sortedShares = Shares<BigInteger>.FromTextLines(lines);

        // Assert
        using var p1 = "1-100".ToPinnedSecure();
        using var p2 = "2-200".ToPinnedSecure();
        using var p3 = "3-300".ToPinnedSecure();
        using var s1 = new Share<BigInteger>(p1);
        using var s2 = new Share<BigInteger>(p2);
        using var s3 = new Share<BigInteger>(p3);
        Assert.Equal(s1, sortedShares[0]);
        Assert.Equal(s2, sortedShares[1]);
        Assert.Equal(s3, sortedShares[2]);
    }

    /// <summary>
    /// Tests that <see cref="Shares{TNumber}.FromText"/> (newline-delimited single buffer)
    /// also sorts the parsed shares by x-coordinate ascending — same contract as
    /// <see cref="Shares{TNumber}.FromTextLines"/>.
    /// </summary>
    [Fact]
    public void AscendingOrder_WithPinnedText_SortsSharesByIndex()
    {
        // Arrange
        var input =
            "3-300" + Environment.NewLine +
            "1-100" + Environment.NewLine +
            "2-200";
        using var blob = input.ToPinnedSecure();

        // Act
        using var sortedShares = Shares<BigInteger>.FromText(blob);

        // Assert
        using var p1 = "1-100".ToPinnedSecure();
        using var p2 = "2-200".ToPinnedSecure();
        using var p3 = "3-300".ToPinnedSecure();
        using var s1 = new Share<BigInteger>(p1);
        using var s2 = new Share<BigInteger>(p2);
        using var s3 = new Share<BigInteger>(p3);
        Assert.Equal(s1, sortedShares[0]);
        Assert.Equal(s2, sortedShares[1]);
        Assert.Equal(s3, sortedShares[2]);
    }

    /// <summary>
    /// <see cref="Shares{TNumber}.ToCharArray()"/> emits uppercase hex without prefix, one share per line,
    /// separated and terminated by <see cref="Environment.NewLine"/>, regardless of build configuration.
    /// </summary>
    [Fact]
    public void ToCharArray_NoArgs_ReturnsPinnedUppercaseWithoutPrefix()
    {
        // Arrange
        using var blob = string.Join(Environment.NewLine, TestData.GetPredefinedShares()).ToPinnedSecure();
        using var shares = Shares<BigInteger>.FromText(blob);
        var expected = string.Join(Environment.NewLine, TestData.GetPredefinedShares()) + Environment.NewLine;

        // Act
        using var result = shares.ToCharArray();

        // Assert
        Assert.Equal(expected, new string(result.PoolArray, 0, result.Length));
    }

    /// <summary>
    /// Tests that <see cref="Shares{TNumber}.ToCharArray(bool, bool)"/> serialises the
    /// whole collection by concatenating each share's own
    /// <see cref="Share{TNumber}.ToCharArray(bool, bool)"/> output, separated and
    /// terminated by <see cref="Environment.NewLine"/>. Covers the
    /// uppercase × with-prefix combinations.
    /// </summary>
    /// <param name="uppercase">Hex case to use in the serialisation.</param>
    /// <param name="withPrefix">Whether to include the index/value <c>0x</c>-style prefix.</param>
    [Theory]
    [InlineData(true, false)]
    [InlineData(false, false)]
    [InlineData(true, true)]
    [InlineData(false, true)]
    public void ToCharArray_WithParameters_MatchesPerShareFormatting(bool uppercase, bool withPrefix)
    {
        // Arrange
        var stringArray = new[] { "03-0A", "01-FF", "02-10" };
        using var blob = string.Join(Environment.NewLine, stringArray).ToPinnedSecure();
        using var shares = Shares<BigInteger>.FromText(blob);

        // Act
        using var result = shares.ToCharArray(uppercase, withPrefix);

        // Assert — build expected output per share, honoring sort-by-index
        var lines = shares.Select(s =>
        {
            using var chars = s.ToCharArray(uppercase, withPrefix);
            return new string(chars.PoolArray, 0, chars.Length);
        }).ToArray();
        var expected = string.Join(Environment.NewLine, lines) + Environment.NewLine;
        Assert.Equal(expected, new string(result.PoolArray, 0, result.Length));
    }

    /// <summary>
    /// Tests that <see cref="Shares{TNumber}.ToCharArray()"/> returns a zero-length pinned
    /// buffer for an empty <see cref="Shares{TNumber}"/> collection.
    /// </summary>
    [Fact]
    public void ToCharArray_EmptyCollection_ReturnsZeroLength()
    {
        // Arrange
        using Shares<BigInteger> empty = Array.Empty<Share<BigInteger>>();

        // Act
        using var result = empty.ToCharArray();

        // Assert
        Assert.Equal(0, result.Length);
    }

    /// <summary>
    /// The new implicit <see cref="PinnedPoolArray{Char}"/> operator emits real share material, not the
    /// redacted <c>"*** Secured Value ***"</c> marker. This is the secure serialization path.
    /// </summary>
    [Fact]
    public void ImplicitCastToPinnedPoolArray_EmitsRealContentIncludingRelease()
    {
        // Arrange
        using var blob = string.Join(Environment.NewLine, TestData.GetPredefinedShares()).ToPinnedSecure();
        using var shares = Shares<BigInteger>.FromText(blob);
        var expected = string.Join(Environment.NewLine, TestData.GetPredefinedShares()) + Environment.NewLine;

        // Act
        using PinnedPoolArray<char> serialized = shares;

        // Assert
        Assert.Equal(expected, new string(serialized.PoolArray, 0, serialized.Length));
    }

    /// <summary>
    /// Tests that the implicit <c>Shares&lt;TNumber&gt; → PinnedPoolArray&lt;char&gt;</c>
    /// cast throws <see cref="ArgumentNullException"/> for a <see langword="null"/> source.
    /// </summary>
    [Fact]
    public void ImplicitCastToPinnedPoolArray_NullShares_ThrowsArgumentNullException()
    {
        // Arrange
        Shares<BigInteger> shares = null;

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() =>
        {
            PinnedPoolArray<char> _ = shares;
        });
    }

    /// <summary>
    /// Tests the implicit <c>Shares ↔ PinnedPoolArray&lt;char&gt;</c> round trip: serialise
    /// the collection, re-parse, and verify the resulting collection equals the original.
    /// </summary>
    [Fact]
    public void RoundTrip_ImplicitPinnedPoolArrayBothDirections_PreservesShares()
    {
        // Arrange
        using var input = string.Join(Environment.NewLine, TestData.GetPredefinedShares()).ToPinnedSecure();
        using var original = Shares<BigInteger>.FromText(input);

        // Act — collection → pinned chars → collection
        using PinnedPoolArray<char> serialized = original;
        using var reparsed = Shares<BigInteger>.FromText(serialized);

        // Assert
        Assert.Equal(original, reparsed);
    }

    /// <summary>
    /// Tests that <see cref="Shares{TNumber}.Dispose"/> cascades to every contained
    /// <see cref="Share{TNumber}"/> — subsequent share-level operations throw
    /// <see cref="ObjectDisposedException"/>.
    /// </summary>
    [Fact]
    public void Dispose_DisposesAllContainedShares()
    {
        // Arrange
        var share1 = new Share<BigInteger>(new BigIntCalculator(5), new BigIntCalculator(10));
        var share2 = new Share<BigInteger>(new BigIntCalculator(7), new BigIntCalculator(20));
        Shares<BigInteger> shares = new[] { share1, share2 };

        // Act
        shares.Dispose();

        // Assert: every share is disposed — subsequent Share-level operations throw.
        Assert.Throws<ObjectDisposedException>(() => share1.GetCharCount(withPrefix: false));
        Assert.Throws<ObjectDisposedException>(() => share2.GetCharCount(withPrefix: false));
    }

    /// <summary>
    /// Tests that calling <see cref="Shares{TNumber}.Dispose"/> repeatedly is idempotent —
    /// the second and third calls do not throw or double-dispose the contained shares.
    /// </summary>
    [Fact]
    public void Dispose_Idempotent_NoException()
    {
        // Arrange
        var share = new Share<BigInteger>(new BigIntCalculator(5), new BigIntCalculator(10));
        Shares<BigInteger> shares = new[] { share };

        // Act
        var ex = Record.Exception(() =>
        {
            shares.Dispose();
            shares.Dispose();
            shares.Dispose();
        });

        // Assert
        Assert.Null(ex);
    }

    /// <summary>
    /// Regression for PR #296 P3 #5: on a live <see cref="Shares{TNumber}"/>, the
    /// mutating <see cref="ICollection{T}"/> members must throw
    /// <see cref="NotSupportedException"/> unconditionally — the collection is
    /// permanently read-only and the unreachable post-guard <c>shareList.{Clear, Add, Remove}</c>
    /// branches were removed in this commit.
    /// </summary>
    [Fact]
    public void MutatingMembers_OnLiveCollection_ThrowNotSupportedException()
    {
        // Arrange
        using var share1 = new Share<BigInteger>(new BigIntCalculator(5), new BigIntCalculator(10));
        using var share2 = new Share<BigInteger>(new BigIntCalculator(7), new BigIntCalculator(20));
        using Shares<BigInteger> shares = new[] { share1, share2 };
        using var freshShare = new Share<BigInteger>(new BigIntCalculator(11), new BigIntCalculator(30));

        // Act & Assert
        Assert.Throws<NotSupportedException>(() => shares.Clear());
        Assert.Throws<NotSupportedException>(() => shares.Add(freshShare));
        Assert.Throws<NotSupportedException>(() => shares.Remove(freshShare));
    }

    /// <summary>
    /// Regression guard for PR #296 codex P1 (r3291168176): after
    /// <see cref="Shares{TNumber}.Dispose"/>, every public and explicit-interface member
    /// must throw <see cref="ObjectDisposedException"/>. The disposed-flag check must
    /// dominate other guards (e.g. <see cref="Shares{TNumber}.IsReadOnly"/>-driven
    /// <see cref="NotSupportedException"/> on Add/Remove/Clear). Closes the
    /// <see cref="IDisposable"/>-contract gap where reads such as
    /// <see cref="Shares{TNumber}.Count"/>, the indexer, enumerators, and CopyTo
    /// previously continued to operate on a disposed collection.
    /// </summary>
    [Fact]
    public void PublicMembers_AfterDispose_ThrowObjectDisposedException()
    {
        // Arrange — build a Shares, capture a non-collected fresh share for argument-position
        // calls, then dispose the collection.
        var share1 = new Share<BigInteger>(new BigIntCalculator(5), new BigIntCalculator(10));
        var share2 = new Share<BigInteger>(new BigIntCalculator(7), new BigIntCalculator(20));
        Shares<BigInteger> shares = new[] { share1, share2 };
        using var freshShare = new Share<BigInteger>(new BigIntCalculator(11), new BigIntCalculator(30));
        var destinationArray = new Share<BigInteger>[10];
        shares.Dispose();

        // Act & Assert — every guarded surface must reject the call.
        Assert.Throws<ObjectDisposedException>(() => _ = shares[0]);
        Assert.Throws<ObjectDisposedException>(() => shares.ToCharArray());
        Assert.Throws<ObjectDisposedException>(() => shares.ToCharArray(uppercase: true, withPrefix: true));
        Assert.Throws<ObjectDisposedException>(() => shares.GetEnumerator());
        Assert.Throws<ObjectDisposedException>(() => ((IEnumerable<Share<BigInteger>>)shares).GetEnumerator());
        Assert.Throws<ObjectDisposedException>(() => ((IEnumerable)shares).GetEnumerator());
        Assert.Throws<ObjectDisposedException>(() => _ = shares.IsReadOnly);
        Assert.Throws<ObjectDisposedException>(() => _ = shares.Count);
        Assert.Throws<ObjectDisposedException>(() => shares.Contains(freshShare));
        Assert.Throws<ObjectDisposedException>(() => shares.Clear());
        Assert.Throws<ObjectDisposedException>(() => shares.Add(freshShare));
        Assert.Throws<ObjectDisposedException>(() => shares.Remove(freshShare));
        Assert.Throws<ObjectDisposedException>(() => ((ICollection)shares).CopyTo(destinationArray, 0));
        Assert.Throws<ObjectDisposedException>(() => shares.CopyTo(destinationArray, 0));
        Assert.Throws<ObjectDisposedException>(() => _ = ((ICollection)shares).SyncRoot);
        Assert.Throws<ObjectDisposedException>(() => _ = ((ICollection)shares).IsSynchronized);
#if DEBUG
        Assert.Throws<ObjectDisposedException>(() => shares.ToString());
#endif
    }

    /// <summary>
    /// Tests that <see cref="Shares{TNumber}.FromText"/> returns an empty (but still
    /// disposable) <see cref="Shares{TNumber}"/> when the input pinned buffer is
    /// <see langword="null"/> rather than throwing.
    /// </summary>
    [Fact]
    public void FromText_NullBuffer_ReturnsEmptyShares()
    {
        // Act
        using var shares = Shares<BigInteger>.FromText(null);

        // Assert
        Assert.Empty(shares);
    }

    /// <summary>
    /// Tests that <see cref="Shares{TNumber}.FromTextLines"/> throws
    /// <see cref="ArgumentNullException"/> for a <see langword="null"/> argument — distinct
    /// from <see cref="Shares{TNumber}.FromText"/> which tolerates null input.
    /// </summary>
    [Fact]
    public void FromTextLines_NullArgument_ThrowsArgumentNullException()
    {
        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => Shares<BigInteger>.FromTextLines(null));
    }

    /// <summary>
    /// Tests that <see cref="Shares{TNumber}.FromTextLines"/> tolerates a mixed input array
    /// containing valid pinned buffers, <see langword="null"/> entries, and zero-length
    /// pinned buffers — the empties are skipped and the valid entries are parsed.
    /// </summary>
    [Fact]
    public void FromTextLines_EmptyOrNullEntries_AreSkipped()
    {
        // Arrange — mix of valid, null, and zero-length pinned buffers.
        using var validA = "1-FFFF".ToPinnedSecure();
        using var validB = "2-AAAA".ToPinnedSecure();
        using var emptyEntry = new PinnedPoolArray<char>(0);
        var lines = new[] { validA, null, emptyEntry, validB };

        // Act
        using var shares = Shares<BigInteger>.FromTextLines(lines);

        // Assert — only the two non-empty entries become shares.
        Assert.Equal(2, shares.Count);
    }

    /// <summary>
    /// Tests that <see cref="Shares{TNumber}.FromTextLines"/> treats each input pinned
    /// buffer as a complete single-line share representation — no across-line
    /// concatenation, even if a single buffer happens to contain newline characters
    /// internally (those are rejected as part of share-line validation).
    /// </summary>
    [Fact]
    public void FromTextLines_ParsesEachLineWithoutMultiLineConcat()
    {
        // Arrange — the FromTextLines path must not require a separator-joined buffer.
        using var p1 = "1-FFFF".ToPinnedSecure();
        using var p2 = "2-AAAA".ToPinnedSecure();

        // Act
        using var shares = Shares<BigInteger>.FromTextLines([p1, p2]);

        // Assert
        using var expectedIndex0 = new BigIntCalculator(1);
        using var expectedIndex1 = new BigIntCalculator(2);
        Assert.Equal(2, shares.Count);
        Assert.Equal(expectedIndex0, shares[0].Index);
        Assert.Equal(expectedIndex1, shares[1].Index);
    }
}