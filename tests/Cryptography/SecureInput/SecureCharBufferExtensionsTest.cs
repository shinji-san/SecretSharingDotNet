// ----------------------------------------------------------------------------
// <copyright file="SecureCharBufferExtensionsTest.cs" company="Private">
// Copyright (c) 2026 All Rights Reserved
// </copyright>
// <author>Sebastian Walther</author>
// <date>05/02/2026</date>
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

namespace SecretSharingDotNetTest.Cryptography.SecureInput;

using System;
using System.Linq;
using SecretSharingDotNet.Cryptography.SecureInput;
using Xunit;

public class SecureCharBufferExtensionsTest
{
    [Fact]
    public void ToPinnedSecure_FromString_CopiesAllChars()
    {
        // Arrange
        const string source = "P&ssw0rd!";

        // Act
        using var pinned = source.ToPinnedSecure();

        // Assert
        Assert.Equal(source, new string(pinned.PoolArray, 0, pinned.Length));
    }

    [Fact]
    public void ToPinnedSecure_FromEmptyString_ReturnsEmptyBuffer()
    {
        // Act
        using var pinned = string.Empty.ToPinnedSecure();

        // Assert
        Assert.Equal(0, pinned.Length);
    }

    [Fact]
    public void ToPinnedSecure_FromNullString_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() => ((string)null).ToPinnedSecure());
    }

    [Fact]
    public void ToPinnedSecure_FromString_DoesNotShareBackingStore()
    {
        // Arrange
        const string source = "abc";

        // Act
        using var pinned = source.ToPinnedSecure();
        pinned.PoolArray[0] = 'Z';

        // Assert — mutating pinned must not affect source.
        Assert.Equal('a', source[0]);
    }

#if NET8_0_OR_GREATER || NETSTANDARD2_1_OR_GREATER
    [Fact]
    public void ToPinnedSecure_FromReadOnlySpan_CopiesAllChars()
    {
        // Arrange
        const string sourceText = "Hello, World!";
        ReadOnlySpan<char> source = sourceText.AsSpan();

        // Act
        using var pinned = source.ToPinnedSecure();

        // Assert
        Assert.Equal(sourceText, new string(pinned.PoolArray, 0, pinned.Length));
    }

    [Fact]
    public void ToPinnedSecure_FromEmptySpan_ReturnsEmptyBuffer()
    {
        // Act
        using var pinned = ReadOnlySpan<char>.Empty.ToPinnedSecure();

        // Assert
        Assert.Equal(0, pinned.Length);
    }
#endif

    [Fact]
    public void ToPinnedSecureClearing_FromCharArray_CopiesAndClearsSource()
    {
        // Arrange
        var source = new[] { 'S', 'e', 'c', 'r', 'e', 't' };
        var snapshot = (char[])source.Clone();

        // Act
        using var pinned = source.ToPinnedSecureClearing();

        // Assert — copy is correct; source is wiped.
        Assert.Equal(snapshot, pinned.PoolArray.Take(pinned.Length));
        Assert.Equal(new char[snapshot.Length], source);
    }

    [Fact]
    public void ToPinnedSecureClearing_FromEmptyArray_ReturnsEmptyBuffer()
    {
        // Arrange
        var source = Array.Empty<char>();

        // Act
        using var pinned = source.ToPinnedSecureClearing();

        // Assert
        Assert.Equal(0, pinned.Length);
    }

    [Fact]
    public void ToPinnedSecureClearing_FromNullArray_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() => ((char[])null).ToPinnedSecureClearing());
    }

    [Fact]
    public void ToPinnedSecureShareLines_FromNullArray_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() => ((string[])null).ToPinnedSecureShareLines());
    }

    [Fact]
    public void ToPinnedSecureShareLines_EmptyArray_ReturnsEmptyList()
    {
        // Arrange
        var input = Array.Empty<string>();

        // Act
        using var lines = input.ToPinnedSecureShareLines();

        // Assert
        Assert.Equal(0, lines.Count);
    }

    [Fact]
    public void ToPinnedSecureShareLines_PinsEachLineWithoutConcatenation()
    {
        // Arrange
        var input = new[] { "1-FFFF", "2-AAAA", "3-1234" };

        // Act
        using var lines = input.ToPinnedSecureShareLines();

        // Assert — each input string ends up in its own pinned buffer, character-for-character.
        Assert.Equal(3, lines.Count);
        Assert.All(Enumerable.Range(0, input.Length), i =>
            Assert.Equal(input[i], new string(lines[i].PoolArray, 0, lines[i].Length)));
    }

    [Fact]
    public void ToPinnedSecureShareLines_NullEntry_PinsAsZeroLengthBuffer()
    {
        // Arrange — null entries are tolerated; they show up as empty pinned buffers.
        var input = new[] { "1-FFFF", null, "3-1234" };

        // Act
        using var lines = input.ToPinnedSecureShareLines();

        // Assert
        Assert.Equal(3, lines.Count);
        Assert.Equal(6, lines[0].Length);
        Assert.Equal(0, lines[1].Length);
        Assert.Equal(6, lines[2].Length);
    }

    [Fact]
    public void ToPinnedSecureShareLines_DisposesEveryEntryOnListDispose()
    {
        // Arrange
        var input = new[] { "1-FFFF", "2-AAAA" };
        var lines = input.ToPinnedSecureShareLines();
        var entries = new[] { lines[0], lines[1] };

        // Act
        lines.Dispose();

        // Assert — accessing a disposed PinnedPoolArray's Length throws ObjectDisposedException.
        Assert.Throws<ObjectDisposedException>(() => _ = entries[0].Length);
        Assert.Throws<ObjectDisposedException>(() => _ = entries[1].Length);
    }

    [Fact]
    public void ToPinnedSecureShareLines_DoubleDispose_IsIdempotent()
    {
        // Arrange
        var lines = new[] { "1-FFFF" }.ToPinnedSecureShareLines();

        // Act
        var ex = Record.Exception(() =>
        {
            lines.Dispose();
            lines.Dispose();
            lines.Dispose();
        });

        // Assert
        Assert.Null(ex);
    }
}