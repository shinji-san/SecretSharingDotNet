// ----------------------------------------------------------------------------
// <copyright file="PinnedPoolArrayList.cs" company="Private">
// Copyright (c) 2026 All Rights Reserved
// </copyright>
// <author>Sebastian Walther</author>
// <date>05/03/2026 00:00:00 AM</date>
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

namespace SecretSharingDotNet.Cryptography.SecureArray;

using Extension;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Threading;

/// <summary>
/// Owns a fixed-length sequence of <see cref="PinnedPoolArray{T}"/> buffers and disposes
/// every entry — securely wiping each backing buffer — when the list itself is disposed.
/// </summary>
/// <typeparam name="T">The element type of the contained pinned buffers.</typeparam>
/// <remarks>
/// Designed for callers that need to pin multiple secret-bearing strings/byte sequences
/// at once (e.g. a list of share lines coming from a UI form). A single <c>using</c> over
/// the list cleans up every nested pinned buffer atomically.
/// </remarks>
public sealed class PinnedPoolArrayList<T> : IReadOnlyList<PinnedPoolArray<T>>, IDisposable where T : unmanaged
{
    private readonly PinnedPoolArray<T>[] entries;
    private int disposed;

    /// <summary>
    /// Initializes a new <see cref="PinnedPoolArrayList{T}"/> taking ownership of every element of
    /// <paramref name="entries"/>. Disposing this list disposes every contained buffer; entries
    /// are not safe to use after that point.
    /// </summary>
    /// <param name="entries">The pinned buffers to wrap. The list takes ownership.</param>
    /// <exception cref="ArgumentNullException"><paramref name="entries"/> is <see langword="null"/>.</exception>
    public PinnedPoolArrayList(PinnedPoolArray<T>[] entries)
    {
        this.entries = entries ?? throw new ArgumentNullException(nameof(entries));
    }

    /// <inheritdoc />
    public int Count => this.entries.Length;

    /// <inheritdoc />
    public PinnedPoolArray<T> this[int index] => this.entries[index];

    /// <inheritdoc />
    public IEnumerator<PinnedPoolArray<T>> GetEnumerator() => ((IEnumerable<PinnedPoolArray<T>>)this.entries).GetEnumerator();

    /// <inheritdoc />
    IEnumerator IEnumerable.GetEnumerator() => this.GetEnumerator();

    /// <summary>
    /// Disposes every contained <see cref="PinnedPoolArray{T}"/>. Idempotent and safe across threads.
    /// </summary>
    public void Dispose()
    {
        if (Interlocked.Exchange(ref this.disposed, 1) == 1)
        {
            return;
        }

        this.entries.DisposeAll();
    }
}