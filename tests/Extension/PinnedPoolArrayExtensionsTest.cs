// ----------------------------------------------------------------------------
// <copyright file="PinnedPoolArrayExtensionsTest.cs" company="Private">
// Copyright (c) 2026 All Rights Reserved
// </copyright>
// <author>Sebastian Walther</author>
// <date>09/18/2026 00:00:00 AM</date>
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

namespace SecretSharingDotNetTest.Extension;

using SecretSharingDotNet.Extension;
using SecretSharingDotNet.SecureMemory;
using System;
using Xunit;

/// <summary>
/// Tests for <see cref="PinnedPoolArrayExtensions.AllocateAndFill{TArray}"/>, the allocate-fill-
/// or-dispose step behind <c>Share.ToCharArray</c> and <c>Shares.ToCharArray</c>. Backend-agnostic,
/// so there is no mirrored counterpart.
/// </summary>
public class PinnedPoolArrayExtensionsTest
{
    /// <summary>
    /// On success the buffer reaches the caller live, with the content the fill wrote.
    /// </summary>
    [Fact]
    public void AllocateAndFill_WhenTheFillSucceeds_ReturnsTheLiveBuffer()
    {
        // Act
        using var result = PinnedPoolArrayExtensions.AllocateAndFill<char>(
            3,
            buffer => "abc".CopyTo(0, buffer.PoolArray, 0, 3));

        // Assert
        Assert.False(result.IsDisposed);
        Assert.Equal(3, result.Length);
        Assert.Equal("abc", new string(result.PoolArray, 0, 3));
    }

    /// <summary>
    /// The failure the serializers cannot reach deterministically, triggered on purpose: the fill
    /// writes content and then throws. The exception must reach the caller unchanged, and the
    /// buffer must already be disposed by then — not left pinned and partly filled for a
    /// finalizer. The fill keeps a reference only so the test can look afterwards.
    /// <para>
    /// Deliberately no check of the buffer's content. Once disposed, the array belongs to the
    /// shared pool again, and any thread in the process — another test, or the runner itself —
    /// may already have rented and written it; on .NET Framework the pool has no thread-local
    /// cache to delay that. Reading it would test the pool's traffic, not this helper. Wiping on
    /// dispose is <see cref="PinnedPoolArray{T}"/>'s guarantee; what this helper promises, and what
    /// is asserted here without a race, is that dispose happens.
    /// </para>
    /// </summary>
    [Fact]
    public void AllocateAndFill_WhenTheFillThrowsAfterWriting_DisposesTheBuffer()
    {
        // Arrange
        PinnedPoolArray<char> seen = null;

        // Act
        var thrown = Assert.Throws<InvalidOperationException>(() => PinnedPoolArrayExtensions.AllocateAndFill<char>(
            4,
            buffer =>
            {
                seen = buffer;
                "sec!".CopyTo(0, buffer.PoolArray, 0, 4);
                throw new InvalidOperationException("write failed");
            }));

        // Assert
        Assert.Equal("write failed", thrown.Message);
        Assert.True(seen.IsDisposed);
    }

    /// <summary>
    /// A missing fill is an argument error, raised before anything is allocated.
    /// </summary>
    [Fact]
    public void AllocateAndFill_WithoutAFill_ThrowsArgumentNullException()
    {
        // Act & Assert
        var error = Assert.Throws<ArgumentNullException>(() => PinnedPoolArrayExtensions.AllocateAndFill<char>(4, null));
        Assert.Equal("fill", error.ParamName);
    }
}
