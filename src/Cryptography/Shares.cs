// ----------------------------------------------------------------------------
// <copyright file="Shares.cs" company="Private">
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

namespace SecretSharingDotNet.Cryptography;

using SecureArray;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading;

/// <summary>
/// Represents a set of shares
/// </summary>
/// <typeparam name="TNumber">Numeric data type (An integer type)</typeparam>
#if DEBUG
[DebuggerDisplay("{ToString()}")]
#else
[DebuggerDisplay("*** Secured Value ***")]
#endif
[Serializable]
public sealed class Shares<TNumber> : ICollection<Share<TNumber>>, ICollection, IDisposable
{
    /// <summary>
    /// Saves a collection of shares.
    /// </summary>
    private readonly Collection<Share<TNumber>> shareList;

    /// <summary>
    /// Saves an object that can be used to synchronize access to the <see cref="Shares{TNumber}"/>
    /// </summary>
    [NonSerialized]
    private object syncRoot;

    /// <summary>
    /// Indicates whether the collection and its contained shares have been disposed.
    /// </summary>
    [NonSerialized]
    private bool disposed;

    /// <summary>
    /// Initializes a new instance of the <see cref="Shares{TNumber}"/> class.
    /// </summary>
    /// <param name="shares">A list of <see cref="Share{TNumber}"/> objects.</param>
    /// <exception cref="ArgumentNullException"><paramref name="shares"/> is <see langword="null"/>.</exception>
    internal Shares(IList<Share<TNumber>> shares)
    {
        _ = shares ?? throw new ArgumentNullException(nameof(shares));
        var sortedShares = shares as Share<TNumber>[] ?? shares.ToArray();
        Array.Sort(sortedShares);
        this.shareList = new Collection<Share<TNumber>>(sortedShares);
    }

    /// <summary>
    /// Gets the <see cref="Share{TNumber}"/> associated with the specified index.
    /// </summary>
    /// <param name="i">The index of the <see cref="Share{TNumber}"/> to get.</param>
    /// <returns>Returns a share (shared secret) represented by a <see cref="Share{TNumber}"/>.</returns>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Naming", "CA1704:IdentifiersShouldBeSpelledCorrectly", MessageId = "i")]
    public Share<TNumber> this[int i] => this.shareList[i];

    /// <summary>
    /// Casts a <see cref="Shares{TNumber}"/> object to a <see cref="PinnedPoolArray{T}"/> of <see cref="char"/>
    /// containing the uppercase hex-encoded shares, one per line, separated by <see cref="Environment.NewLine"/>.
    /// </summary>
    /// <param name="shares">A <see cref="Shares{TNumber}"/> object.</param>
    /// <remarks>
    /// Unlike <see cref="ToString"/>, this operator is not redacted in Release builds. It is the
    /// secure serialization path intended for round-tripping shares into pinned storage. The returned
    /// <see cref="PinnedPoolArray{T}"/> is owned by the caller and must be disposed; until then the share
    /// material is only present in pinned, securely cleared memory.
    /// </remarks>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="shares"/> is <see langword="null"/>.</exception>
    public static implicit operator PinnedPoolArray<char>(Shares<TNumber> shares)
    {
        return shares is null ? throw new ArgumentNullException(nameof(shares)) : shares.ToCharArray();
    }

    /// <summary>
    /// Casts a pinned multi-line character buffer to a <see cref="Shares{TNumber}"/> object.
    /// </summary>
    /// <param name="buffer">
    /// A <see cref="PinnedPoolArray{T}"/> of <see cref="char"/> containing two or more
    /// <c>INDEX-VALUE</c> share lines separated by line feed (<c>\n</c>) or carriage return (<c>\r</c>).
    /// Blank lines are skipped. The caller retains ownership of <paramref name="buffer"/>.
    /// </param>
    /// <remarks>
    /// Each non-empty line is copied into its own short-lived pinned sub-buffer for the duration
    /// of the share construction, then securely cleared on dispose. No unpinned heap copy of
    /// the share material is created.
    /// </remarks>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="buffer"/> is <see langword="null"/>.
    /// </exception>
    public static implicit operator Shares<TNumber>(PinnedPoolArray<char> buffer)
    {
        if (buffer is null)
        {
            return new Shares<TNumber>([]);
        }

        var buf = buffer.PoolArray;
        var end = buffer.Length;
        var shares = new List<Share<TNumber>>();
        var lineStart = 0;

        for (var i = 0; i <= end; i++)
        {
            if (i != end && buf[i] != '\n' && buf[i] != '\r')
            {
                continue;
            }

            if (lineStart < i)
            {
                var lineLen = i - lineStart;
                using var linePinned = new PinnedPoolArray<char>(lineLen);
                Array.Copy(buf, lineStart, linePinned.PoolArray, 0, lineLen);
                shares.Add(new Share<TNumber>(linePinned));
            }

            lineStart = i + 1;
        }

        return new Shares<TNumber>(shares);
    }

    /// <summary>
    /// Casts a <see cref="Shares{TNumber}"/> object to an array of <see cref="Share{TNumber}"/> items.
    /// </summary>
    /// <param name="shares">A <see cref="Shares{TNumber}"/> object.</param>
    public static implicit operator Share<TNumber>[](Shares<TNumber> shares) => shares.ToArray();

    /// <summary>
    /// Casts an array of <see cref="Share{TNumber}"/> items to a <see cref="Shares{TNumber}"/> object.
    /// </summary>
    /// <param name="shares">An array of <see cref="Share{TNumber}"/> items.</param>
    /// <returns>A <see cref="Shares{TNumber}"/> instance that contains the specified shares.</returns>
    public static implicit operator Shares<TNumber>(Share<TNumber>[] shares) => new Shares<TNumber>(shares);

    /// <summary>
    /// Converts the collection to a <see cref="PinnedPoolArray{T}"/> of <see cref="char"/> containing
    /// the uppercase hex-encoded shares without coordinate prefixes, one per line, separated and
    /// terminated by <see cref="Environment.NewLine"/>.
    /// </summary>
    /// <returns>
    /// A pinned character buffer with the serialized shares. The caller is responsible for disposing
    /// the returned instance. Returns a buffer of length zero if the collection is empty.
    /// </returns>
    public PinnedPoolArray<char> ToCharArray() => this.ToCharArray(uppercase: true, withPrefix: false);

    /// <summary>
    /// Converts the collection to a <see cref="PinnedPoolArray{T}"/> of <see cref="char"/> containing
    /// the hex-encoded shares, one per line, separated and terminated by <see cref="Environment.NewLine"/>.
    /// </summary>
    /// <param name="uppercase">
    /// <see langword="true"/> to use uppercase hex digits (0A–0F); <see langword="false"/> for lowercase (0a–0f).
    /// </param>
    /// <param name="withPrefix">
    /// <see langword="true"/> to prepend <c>"0x"</c> before each coordinate; <see langword="false"/> for no prefix.
    /// </param>
    /// <returns>
    /// A pinned character buffer with the serialized shares. The caller is responsible for disposing
    /// the returned instance. Returns a buffer of length zero if the collection is empty.
    /// </returns>
    /// <remarks>
    /// The share material is written directly into the final pinned buffer in a single pass, without any
    /// intermediate unpinned <see cref="string"/> or <see cref="System.Text.StringBuilder"/> allocation.
    /// </remarks>
    public PinnedPoolArray<char> ToCharArray(bool uppercase, bool withPrefix = false)
    {
        if (this.shareList.Count == 0)
        {
            return new PinnedPoolArray<char>(0);
        }

        var newline = Environment.NewLine;
        var newlineLen = newline.Length;
        var total = 0;
        for (int i = 0; i < this.shareList.Count; i++)
        {
            total += this.shareList[i].GetCharCount(withPrefix) + newlineLen;
        }

        var result = new PinnedPoolArray<char>(total);
        var pos = 0;
        for (int i = 0; i < this.shareList.Count; i++)
        {
            pos += this.shareList[i].WriteCharsTo(result.PoolArray, pos, uppercase, withPrefix);
            newline.CopyTo(0, result.PoolArray, pos, newlineLen);
            pos += newlineLen;
        }

        return result;
    }

    /// <summary>
    /// Returns the string representation of the <see cref="Shares{TNumber}"/> instance.
    /// </summary>
    /// <returns>
    /// In Debug builds: a human-readable list of shares separated by newlines.
    /// In Release builds: always returns <c>"*** Secured Value ***"</c> to prevent accidental exposure
    /// in logs, exception messages, or other output. Use <see cref="ToCharArray()"/> for explicit serialization.
    /// </returns>
    /// <remarks>
    /// <b>Security warning:</b> DEBUG builds expose share material on the unpinned managed heap — both
    /// via the intermediate <see cref="StringBuilder"/> buffer and the returned <see cref="string"/>.
    /// Neither can be securely cleared: the <see cref="string"/> is immutable, and the
    /// <see cref="StringBuilder"/> internal buffer lives on the GC heap without pinning. Contents remain
    /// recoverable from process memory until collected (and may persist in swap files or crash dumps).
    /// Do not log, serialize, or otherwise persist <see cref="ToString"/> output in any build that
    /// handles real secrets. For secure serialization use <see cref="ToCharArray()"/>, which returns
    /// share material in pinned memory that is securely cleared on <see cref="IDisposable.Dispose"/>.
    /// </remarks>
    public override string ToString()
    {
#if DEBUG
        var stringBuilder = new StringBuilder();
        var shares = this.shareList as Share<TNumber>[] ?? this.shareList.ToArray();
        foreach (var share in shares)
        {
            stringBuilder.AppendLine(share.ToString());
        }

        return stringBuilder.ToString();
#else
        return "*** Secured Value ***";
#endif
    }

    /// <summary>
    /// Returns an enumerator that iterates through a <see cref="Shares{TNumber}"/> collection.
    /// </summary>
    /// <returns>An enumerator that can be used to iterate through the <see cref="Shares{TNumber}"/> collection.</returns>
    IEnumerator<Share<TNumber>> IEnumerable<Share<TNumber>>.GetEnumerator() => this.GetEnumerator();

    /// <summary>
    /// Returns an enumerator that iterates through a <see cref="Shares{TNumber}"/> collection.
    /// </summary>
    /// <returns>An <see cref="IEnumerator"/> object that can be used to iterate through the <see cref="Shares{TNumber}"/> collection.</returns>
    IEnumerator IEnumerable.GetEnumerator() => this.GetEnumerator();

    /// <summary>
    /// Returns an <see cref="SharesEnumerator{TNumber}"/> that iterates through the <see cref="Shares{TNumber}"/> collection.
    /// </summary>
    /// <returns>An <see cref="SharesEnumerator{TNumber}"/> that can be used to iterate through the <see cref="Shares{TNumber}"/> collection.</returns>
    public SharesEnumerator<TNumber> GetEnumerator() => new SharesEnumerator<TNumber>(this.shareList);

    /// <summary>
    /// Gets a value indicating whether the <see cref="Shares{TNumber}"/> collection is read-only.
    /// </summary>
    /// <remarks>Currently, this property always returns <see langword="true"/>.</remarks>
    public bool IsReadOnly => true;

    /// <summary>
    /// Gets the number of <see cref="Share{TNumber}"/> items contained in the <see cref="Shares{TNumber}"/> collection.
    /// </summary>
    public int Count => this.shareList.Count;

    /// <summary>
    /// Determines whether the <see cref="Shares{TNumber}"/> collection contains a specific <see cref="Share{TNumber}"/>.
    /// </summary>
    /// <param name="item">The <see cref="Share{TNumber}"/> to locate in the <see cref="Shares{TNumber}"/> collection.</param>
    /// <returns><see langword="true"/> if item is found in the <see cref="Shares{TNumber}"/> collection; otherwise, <see langword="false"/>.</returns>
    public bool Contains(Share<TNumber> item) => this.shareList.Any(share => share.Equals(item));

    /// <summary>
    /// Removes all items from the <see cref="Shares{TNumber}"/> collection.
    /// </summary>
    /// <remarks>This method is implemented. However, this method does nothing as long as the property <see cref="IsReadOnly"/> is
    /// set to <see langword="true"/>.</remarks>
    /// <exception cref="NotSupportedException">The <see cref="Shares{TNumber}"/> collection is read-only.</exception>
    public void Clear()
    {
        if (this.IsReadOnly)
        {
            throw new NotSupportedException(string.Format(ErrorMessages.ReadOnlyCollection, nameof(Shares<>)));
        }

        this.shareList.Clear();
    }

    /// <summary>
    /// Adds an <see cref="Share{TNumber}"/> to the <see cref="Shares{TNumber}"/> collection.
    /// </summary>
    /// <param name="item">The <see cref="Share{TNumber}"/> to add to the <see cref="Shares{TNumber}"/> collection.</param>
    /// <remarks>This method is implemented. However, this method does nothing as long as the property <see cref="IsReadOnly"/> is
    /// set to <see langword="true"/>.</remarks>
    /// <exception cref="NotSupportedException">The <see cref="Shares{TNumber}"/> collection is read-only.</exception>
    public void Add(Share<TNumber> item)
    {
        if (this.IsReadOnly)
        {
            throw new NotSupportedException(string.Format(ErrorMessages.ReadOnlyCollection, nameof(Shares<>)));
        }

        if (!this.Contains(item))
        {
            this.shareList.Add(item);
        }
    }

    /// <summary>
    /// Removes the first occurrence of a specific <see cref="Share{TNumber}"/> from the <see cref="Shares{TNumber}"/> collection.
    /// </summary>
    /// <param name="item">The <see cref="Share{TNumber}"/> to remove from the <see cref="Shares{TNumber}"/> collection.</param>
    /// <returns></returns>
    /// <remarks>This method is implemented. However, this method does nothing as long as the property <see cref="IsReadOnly"/> is
    /// set to <see langword="true"/>.</remarks>
    /// <exception cref="NotSupportedException">The <see cref="Shares{TNumber}"/> collection is read-only.</exception>
    public bool Remove(Share<TNumber> item)
    {
        if (this.IsReadOnly)
        {
            throw new NotSupportedException(string.Format(ErrorMessages.ReadOnlyCollection, nameof(Shares<>)));
        }

        return this.shareList.Remove(item);
    }

    /// <summary>
    /// Copies the items of the <see cref="Shares{TNumber}"/> collection to an <see cref="Array"/>, starting at a particular <see cref="Array"/> index.
    /// </summary>
    /// <param name="array">The one-dimensional <see cref="Array"/> that is the destination of the items copied from <see cref="Shares{TNumber}"/> collection.
    /// The  <see cref="Array"/> must have zero-based indexing.</param>
    /// <param name="index">The zero-based index in <paramref name="array"/> at which copying begins.</param>
    void ICollection.CopyTo(Array array, int index)
    {
        _ = array ?? throw new ArgumentNullException(nameof(array));
        switch (array)
        {
            case Share<TNumber>[] x:
                this.CopyTo(x, index);
                break;
            default:
                throw new InvalidCastException(string.Format(ErrorMessages.InvalidArrayTypeCast, nameof(array), array.GetType().GetElementType(), typeof(Share<TNumber>)));
        }
    }

    /// <summary>
    /// Copies the items of the <see cref="Shares{TNumber}"/> collection to an array of <see cref="Share{TNumber}"/> items,
    /// starting at a particular array index.
    /// </summary>
    /// <param name="array">The one-dimensional array of <see cref="Share{TNumber}"/> items that is the destination of the
    /// items copied from <see cref="Shares{TNumber}"/> collection.
    /// The array must have zero-based indexing.</param>
    /// <param name="arrayIndex">The zero-based index in <paramref name="array"/> at which copying begins.</param>
    public void CopyTo(Share<TNumber>[] array, int arrayIndex)
    {
        _ = array ?? throw new ArgumentNullException(nameof(array));
        if (arrayIndex < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(arrayIndex), ErrorMessages.StartArrayIndexNegative);
        }

        if (this.Count > array.Length - arrayIndex)
        {
            throw new ArgumentException(ErrorMessages.DestinationArrayHasFewerElements, nameof(array));
        }

        for (int i = 0; i < this.shareList.Count; i++)
        {
            array[i + arrayIndex] = this.shareList[i];
        }
    }

    /// <summary>
    /// Gets an object that can be used to synchronize access to the <see cref="Shares{TNumber}"/> collection.
    /// </summary>
    object ICollection.SyncRoot
    {
        get
        {
            object newValue = new object();
            return (this.syncRoot ?? Interlocked.CompareExchange(ref this.syncRoot, newValue, null)) ?? newValue;
        }
    }

    /// <summary>
    /// Gets a value indicating whether access to the <see cref="Shares{TNumber}"/> collection is synchronized (thread safe).
    /// </summary>
    bool ICollection.IsSynchronized => false;

    /// <summary>
    /// Disposes every <see cref="Share{TNumber}"/> in the collection. Idempotent — subsequent calls
    /// are no-ops.
    /// </summary>
    /// <remarks>
    /// <b>Ownership:</b> a <see cref="Shares{TNumber}"/> collection owns every share it contains.
    /// Disposing the collection disposes all contained shares. Shares removed via
    /// <see cref="Remove"/> are returned to the caller, who then owns disposal.
    /// </remarks>
    public void Dispose()
    {
        if (this.disposed)
        {
            return;
        }

        foreach (var share in this.shareList)
        {
            share?.Dispose();
        }

        this.disposed = true;
    }
}