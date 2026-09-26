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

using Extension;
using Math;
using SecureMemory;
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
/// <remarks>
/// Deliberately not <c>[Serializable]</c>. It carried the attribute until version 1.0.1. With a
/// formatter's defaults it could not be written at all: the only serialized field is the share
/// collection, <see cref="Share{TNumber}"/> is not marked serializable, and the formatter rejects
/// that element type even for an empty collection, since the backing list carries a
/// <c>Share&lt;TNumber&gt;[]</c>. A consumer who registered an <c>ISerializationSurrogate</c> for
/// <see cref="Share{TNumber}"/> could round-trip a populated collection, though, and that path is
/// precisely what S5766 objects to: deserialization does not run the constructor, which copies the
/// shares and sorts them by index, so the ordering this type otherwise guarantees would rest on
/// whatever the payload contains. Formatter-based serialization is obsolete on every modern target
/// (SYSLIB0011, SYSLIB0050) in any case. Persist shares through
/// <see cref="ToCharArray(bool, bool, ShareFormat)"/>, which is the format this library defines and
/// validates on the way back in.
/// </remarks>
#if DEBUG
[DebuggerDisplay("{ToString()}")]
#else
[DebuggerDisplay("*** Secured Value ***")]
#endif
public sealed class Shares<TNumber> : ICollection<Share<TNumber>>, ICollection, IDisposable
{
    /// <summary>
    /// Saves a collection of shares.
    /// </summary>
    private readonly Collection<Share<TNumber>> shareList;

    /// <summary>
    /// Saves an object that can be used to synchronize access to the <see cref="Shares{TNumber}"/>
    /// </summary>
    private object syncRoot;

    /// <summary>
    /// Indicates whether the collection and its contained shares have been disposed
    /// (<c>0</c> = live, <c>1</c> = disposed). Updated atomically via
    /// <see cref="Interlocked.Exchange(ref int, int)"/> so that concurrent
    /// <see cref="Dispose"/> calls cannot both reach the share-cascade-dispose branch.
    /// </summary>
    private int disposed;

    /// <summary>
    /// Initializes a new instance of the <see cref="Shares{TNumber}"/> class.
    /// </summary>
    /// <param name="shares">A list of <see cref="Share{TNumber}"/> objects.</param>
    /// <exception cref="ArgumentNullException"><paramref name="shares"/> is <see langword="null"/>.</exception>
    internal Shares(IList<Share<TNumber>> shares)
    {
        _ = shares ?? throw new ArgumentNullException(nameof(shares));
        // Always copy via ToArray(). The public implicit operator from
        // Share<TNumber>[] reaches this ctor with caller-owned storage; an
        // alias-cast to Share<TNumber>[] followed by Array.Sort would
        // reorder the caller's array as a side effect of construction.
        var sortedShares = shares.ToArray();
        Array.Sort(sortedShares);
        this.shareList = new Collection<Share<TNumber>>(sortedShares);
    }

    /// <summary>
    /// Gets the <see cref="Share{TNumber}"/> associated with the specified index.
    /// </summary>
    /// <param name="i">The index of the <see cref="Share{TNumber}"/> to get.</param>
    /// <returns>Returns a share (shared secret) represented by a <see cref="Share{TNumber}"/>.</returns>
    /// <exception cref="ObjectDisposedException">Thrown when the collection has been disposed.</exception>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Naming", "CA1704:IdentifiersShouldBeSpelledCorrectly", MessageId = "i")]
    public Share<TNumber> this[int i]
    {
        get
        {
            this.ThrowIfDisposed();
            return this.shareList[i];
        }
    }

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
    /// Parses a pinned multi-line character buffer into a <see cref="Shares{TNumber}"/> instance.
    /// </summary>
    /// <param name="buffer">
    /// A <see cref="PinnedPoolArray{T}"/> of <see cref="char"/> containing two or more
    /// <c>INDEX-VALUE</c> share lines separated by line feed (<c>\n</c>) or carriage return (<c>\r</c>).
    /// Blank lines are skipped. The caller retains ownership of <paramref name="buffer"/>.
    /// </param>
    /// <returns>
    /// A new <see cref="Shares{TNumber}"/> containing one entry per non-empty source line, or an
    /// empty collection if <paramref name="buffer"/> is <see langword="null"/>.
    /// </returns>
    /// <remarks>
    /// Each non-empty line is copied into its own short-lived pinned sub-buffer for the duration
    /// of the share construction, then securely cleared on dispose. No unpinned heap copy of
    /// the share material is created.
    /// </remarks>
    public static Shares<TNumber> FromText(PinnedPoolArray<char> buffer)
    {
        if (buffer is null)
        {
            return new Shares<TNumber>([]);
        }

        var buf = buffer.PoolArray;
        var end = buffer.Length;
        var shares = new List<Share<TNumber>>();
        var lineStart = 0;

        try
        {
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

                    // Allocate the share before handing it to the list. If the list's
                    // own Add (e.g. internal resize) throws after the share has been
                    // constructed, the local would otherwise leak the share's
                    // index+value Calculator pinned buffers.
                    Share<TNumber> share = null;
                    try
                    {
                        share = new Share<TNumber>(linePinned);
                        shares.Add(share);
                        share = null;
                    }
                    catch
                    {
                        share?.Dispose();
                        throw;
                    }
                }

                lineStart = i + 1;
            }

            var result = new Shares<TNumber>(shares);
            // Ownership of every share is now held by the returned Shares<TNumber>.
            // Null the local so the catch path below does not double-dispose.
            shares = null;
            return result;
        }
        catch
        {
            // Mid-loop failure (malformed share line, OOM in List resize, etc.) —
            // dispose every share already accumulated before re-throwing.
            shares?.DisposeAll();
            throw;
        }
    }

    /// <summary>
    /// Parses a sequence of pinned single-line buffers — each in <c>INDEX-VALUE</c> format —
    /// into a <see cref="Shares{TNumber}"/> instance. Intended for callers whose share lines
    /// arrive separately (e.g. from a UI form) and who want to keep each line pinned end-to-end
    /// without going through a multi-line concatenation.
    /// </summary>
    /// <param name="lines">
    /// The pinned single-line buffers. <see langword="null"/> entries and zero-length buffers
    /// are skipped. The caller retains ownership of <paramref name="lines"/> and every entry.
    /// </param>
    /// <returns>A new <see cref="Shares{TNumber}"/> containing one entry per non-empty input line.</returns>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="lines"/> is <see langword="null"/>.
    /// </exception>
    public static Shares<TNumber> FromTextLines(IEnumerable<PinnedPoolArray<char>> lines)
    {
        if (lines is null)
        {
            throw new ArgumentNullException(nameof(lines));
        }

        var shares = new List<Share<TNumber>>();
        try
        {
            foreach (var line in lines)
            {
                if (line is null || line.Length == 0)
                {
                    continue;
                }

                // Allocate the share before handing it to the list. If the list's
                // own Add (e.g. internal resize) throws after the share has been
                // constructed, the local would otherwise leak the share's
                // index+value Calculator pinned buffers.
                Share<TNumber> share = null;
                try
                {
                    share = new Share<TNumber>(line);
                    shares.Add(share);
                    share = null;
                }
                catch
                {
                    share?.Dispose();
                    throw;
                }
            }

            var result = new Shares<TNumber>(shares);
            // Ownership of every share is now held by the returned Shares<TNumber>.
            // Null the local so the catch path below does not double-dispose.
            shares = null;
            return result;
        }
        catch
        {
            // Mid-loop failure (malformed share line, OOM in List resize, etc.) —
            // dispose every share already accumulated before re-throwing.
            shares?.DisposeAll();
            throw;
        }
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
    /// Re-issues every share in this collection recording the finite field they were created in,
    /// for shares that carry no record of one.
    /// </summary>
    /// <param name="securityLevel">The Mersenne exponent the split actually used.</param>
    /// <returns>
    /// A new collection of new shares. The caller owns it; this collection is untouched and still
    /// usable, and disposing either leaves the other intact.
    /// </returns>
    /// <remarks>
    /// <para>
    /// The same caller obligation as the single-share form: the exponent must be the one the split
    /// actually used, <em>after</em> any auto-raise inside <c>MakeShares</c>. For shares that
    /// record nothing, a supported exponent that is large enough but simply wrong cannot be
    /// detected, because the coordinates do not say which field produced them. A share that
    /// already records a level is never overwritten: a contradicting exponent is refused.
    /// </para>
    /// <para>
    /// All or nothing. The level is validated once against every share before anything is cloned,
    /// so a collection is never half migrated — and if the cloning itself fails partway, the shares
    /// already produced are disposed rather than leaked.
    /// </para>
    /// <para>
    /// This overload checks the exponent against <see cref="MersennePrimeProvider.Instance"/>, the
    /// library's own table. With a security level manager built on a different
    /// <see cref="IMersennePrimeProvider"/>, use
    /// <see cref="ReissueWithSecurityLevel(int, IMersennePrimeProvider)"/> so migration and
    /// reconstruction answer to the same table.
    /// </para>
    /// </remarks>
    /// <exception cref="ArgumentOutOfRangeException">
    /// <paramref name="securityLevel"/> is not a supported Mersenne prime exponent.
    /// </exception>
    /// <exception cref="ArgumentException">
    /// <paramref name="securityLevel"/> contradicts a level at least one share already records, or
    /// names a field too small for at least one share's coordinates.
    /// </exception>
    /// <exception cref="ObjectDisposedException">Thrown when this instance has been disposed.</exception>
    public Shares<TNumber> ReissueWithSecurityLevel(int securityLevel) =>
        this.ReissueWithSecurityLevel(securityLevel, MersennePrimeProvider.Instance);

    /// <summary>
    /// Re-issues every share in this collection recording the finite field they were created in,
    /// with the given provider deciding which exponents are supported.
    /// </summary>
    /// <param name="securityLevel">The Mersenne exponent the split actually used.</param>
    /// <param name="mersennePrimeProvider">
    /// The provider whose table decides which exponents are supported — the one the security
    /// level manager reconstructing these shares uses. Borrowed for this call only: it is neither
    /// stored on the new shares nor disposed.
    /// </param>
    /// <returns>
    /// A new collection of new shares. The caller owns it; this collection is untouched and still
    /// usable, and disposing either leaves the other intact.
    /// </returns>
    /// <remarks>
    /// The same operation as <see cref="ReissueWithSecurityLevel(int)"/> — all or nothing, every
    /// share validated before the first is cloned — except for which table decides. The exponent
    /// is checked against <paramref name="mersennePrimeProvider"/> exactly, with no rounding up and
    /// no fallback to the built-in table, before the field for the coordinate check is computed.
    /// <para>
    /// The provider is also where an application bounds the exponent. The field check computes
    /// the prime for any exponent the provider supports, and near the top of the built-in table
    /// that takes minutes; a provider limited to the exponents in use keeps migration — like
    /// reconstruction through a security level manager on the same provider — from doing so.
    /// </para>
    /// </remarks>
    /// <exception cref="ArgumentNullException">
    /// <paramref name="mersennePrimeProvider"/> is <see langword="null"/>.
    /// </exception>
    /// <exception cref="ArgumentOutOfRangeException">
    /// <paramref name="securityLevel"/> is not supported by <paramref name="mersennePrimeProvider"/>.
    /// </exception>
    /// <exception cref="ArgumentException">
    /// <paramref name="securityLevel"/> contradicts a level at least one share already records, or
    /// names a field too small for at least one share's coordinates.
    /// </exception>
    /// <exception cref="ObjectDisposedException">Thrown when this instance has been disposed.</exception>
    public Shares<TNumber> ReissueWithSecurityLevel(int securityLevel, IMersennePrimeProvider mersennePrimeProvider)
    {
        this.ThrowIfDisposed();
        if (mersennePrimeProvider is null)
        {
            throw new ArgumentNullException(nameof(mersennePrimeProvider));
        }

        Share<TNumber>.EnsureUsableSecurityLevel(this.shareList, securityLevel, mersennePrimeProvider);

        var reissued = new Share<TNumber>[this.shareList.Count];
        try
        {
            for (int i = 0; i < this.shareList.Count; i++)
            {
                reissued[i] = this.shareList[i].ReissueCore(securityLevel);
            }

            return new Shares<TNumber>(reissued);
        }
        catch
        {
            reissued.DisposeAll();
            throw;
        }
    }

    /// <summary>
    /// Converts the collection to a <see cref="PinnedPoolArray{T}"/> of <see cref="char"/> containing
    /// the uppercase hex-encoded shares without coordinate prefixes, one per line, separated and
    /// terminated by <see cref="Environment.NewLine"/>.
    /// </summary>
    /// <returns>
    /// A pinned character buffer with the serialized shares. The caller is responsible for disposing
    /// the returned instance. Returns a buffer of length zero if the collection is empty.
    /// </returns>
    /// <exception cref="ObjectDisposedException">Thrown when the collection has been disposed.</exception>
    public PinnedPoolArray<char> ToCharArray()
    {
        this.ThrowIfDisposed();
        return this.ToCharArray(uppercase: true, withPrefix: false);
    }

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
    /// <exception cref="ObjectDisposedException">Thrown when the collection has been disposed.</exception>
    public PinnedPoolArray<char> ToCharArray(bool uppercase, bool withPrefix = false) =>
        this.ToCharArray(uppercase, withPrefix, ShareFormat.Legacy);

    /// <summary>
    /// Converts every share to its hex-encoded form in the given format, one per line.
    /// </summary>
    /// <param name="uppercase">
    /// <see langword="true"/> for uppercase hex digits (0A–0F); <see langword="false"/> for lowercase.
    /// </param>
    /// <param name="withPrefix">
    /// <see langword="true"/> to prepend <c>"0x"</c> to every segment, the security level included.
    /// </param>
    /// <param name="format">Which serialized form to write.</param>
    /// <returns>
    /// A <see cref="PinnedPoolArray{T}"/> with the hex-encoded shares. The caller disposes it. If
    /// the write fails after the buffer was allocated, the buffer is disposed before the exception
    /// propagates.
    /// </returns>
    /// <remarks>
    /// All or nothing: <see cref="ShareFormat.Extended"/> throws unless <b>every</b> share records a
    /// level, because the first one that does not stops the write — after the earlier lines have
    /// been measured but before anything is handed back. A collection holding a mixture cannot be
    /// written in the extended form at all, which is the honest outcome: the missing levels cannot
    /// be invented and a file of mixed lines would be worse than a refusal.
    /// </remarks>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="format"/> is not a defined value.</exception>
    /// <exception cref="InvalidOperationException">
    /// <paramref name="format"/> is <see cref="ShareFormat.Extended"/> and at least one share
    /// records no security level.
    /// </exception>
    /// <exception cref="ObjectDisposedException">Thrown when this instance has been disposed.</exception>
    public PinnedPoolArray<char> ToCharArray(bool uppercase, bool withPrefix, ShareFormat format)
    {
        this.ThrowIfDisposed();

        // Before the emptiness short-circuit, not after: an argument the method cannot honour is
        // wrong whether or not there is anything to write, and an empty collection quietly
        // accepting a cast integer would make the contract depend on the data.
        ShareFormatValidation.EnsureDefined(format, nameof(format));
        if (this.shareList.Count == 0)
        {
            return new PinnedPoolArray<char>(0);
        }

        var newline = Environment.NewLine;
        var newlineLen = newline.Length;
        var total = 0;
        for (int i = 0; i < this.shareList.Count; i++)
        {
            total += this.shareList[i].GetCharCount(withPrefix, format) + newlineLen;
        }

        return PinnedPoolArrayExtensions.AllocateAndFill<char>(
            total,
            buffer =>
            {
                var pos = 0;
                for (int i = 0; i < this.shareList.Count; i++)
                {
                    pos += this.shareList[i].WriteCharsTo(buffer.PoolArray, pos, uppercase, withPrefix, format);
                    newline.CopyTo(0, buffer.PoolArray, pos, newlineLen);
                    pos += newlineLen;
                }
            });
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
        this.ThrowIfDisposed();
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
    /// <returns>An <see cref="IEnumerator"/> object that can be used to iterate through the <see cref="Shares{TNumber}"/> collection.</returns>
    /// <exception cref="ObjectDisposedException">Thrown when the collection has been disposed.</exception>
    IEnumerator IEnumerable.GetEnumerator()
    {
        this.ThrowIfDisposed();
        return this.GetEnumerator();
    }

    /// <summary>
    /// Returns an <see cref="IEnumerator{T}"/> of <see cref="Share{TNumber}"/> that iterates through the <see cref="Shares{TNumber}"/> collection.
    /// </summary>
    /// <returns>An <see cref="IEnumerator{T}"/> of <see cref="Share{TNumber}"/> that can be used to iterate through the <see cref="Shares{TNumber}"/> collection.</returns>
    /// <remarks>This method also provides the <see cref="IEnumerable{T}"/> implementation of <see cref="Share{TNumber}"/> for the collection.</remarks>
    /// <exception cref="ObjectDisposedException">Thrown when the collection has been disposed.</exception>
    public IEnumerator<Share<TNumber>> GetEnumerator()
    {
        this.ThrowIfDisposed();
        return new SharesEnumerator<TNumber>(this.shareList);
    }

    /// <summary>
    /// Gets a value indicating whether the <see cref="Shares{TNumber}"/> collection is read-only.
    /// </summary>
    /// <remarks>Currently, this property always returns <see langword="true"/>.</remarks>
    /// <exception cref="ObjectDisposedException">Thrown when the collection has been disposed.</exception>
    public bool IsReadOnly
    {
        get
        {
            this.ThrowIfDisposed();
            return true;
        }
    }

    /// <summary>
    /// Gets the number of <see cref="Share{TNumber}"/> items contained in the <see cref="Shares{TNumber}"/> collection.
    /// </summary>
    /// <exception cref="ObjectDisposedException">Thrown when the collection has been disposed.</exception>
    public int Count
    {
        get
        {
            this.ThrowIfDisposed();
            return this.shareList.Count;
        }
    }

    /// <summary>
    /// Determines whether the <see cref="Shares{TNumber}"/> collection contains a specific <see cref="Share{TNumber}"/>.
    /// </summary>
    /// <param name="item">The <see cref="Share{TNumber}"/> to locate in the <see cref="Shares{TNumber}"/> collection.</param>
    /// <returns><see langword="true"/> if item is found in the <see cref="Shares{TNumber}"/> collection; otherwise, <see langword="false"/>.</returns>
    /// <exception cref="ObjectDisposedException">Thrown when the collection has been disposed.</exception>
    public bool Contains(Share<TNumber> item)
    {
        this.ThrowIfDisposed();
        return this.shareList.Any(share => share.Equals(item));
    }

    /// <summary>
    /// Mutating ICollection member required by the interface contract.
    /// <see cref="Shares{TNumber}"/> is permanently read-only
    /// (<see cref="IsReadOnly"/> returns <see langword="true"/> unconditionally),
    /// so this method always throws <see cref="NotSupportedException"/>.
    /// </summary>
    /// <exception cref="NotSupportedException">Always thrown — the collection is read-only.</exception>
    /// <exception cref="ObjectDisposedException">Thrown when the collection has been disposed.</exception>
    public void Clear()
    {
        this.ThrowIfDisposed();
        throw new NotSupportedException(string.Format(ErrorMessages.ReadOnlyCollection, nameof(Shares<>)));
    }

    /// <summary>
    /// Mutating ICollection member required by the interface contract.
    /// <see cref="Shares{TNumber}"/> is permanently read-only
    /// (<see cref="IsReadOnly"/> returns <see langword="true"/> unconditionally),
    /// so this method always throws <see cref="NotSupportedException"/>.
    /// </summary>
    /// <param name="item">Ignored — the call is rejected before <paramref name="item"/> is inspected.</param>
    /// <exception cref="NotSupportedException">Always thrown — the collection is read-only.</exception>
    /// <exception cref="ObjectDisposedException">Thrown when the collection has been disposed.</exception>
    public void Add(Share<TNumber> item)
    {
        this.ThrowIfDisposed();
        throw new NotSupportedException(string.Format(ErrorMessages.ReadOnlyCollection, nameof(Shares<>)));
    }

    /// <summary>
    /// Mutating ICollection member required by the interface contract.
    /// <see cref="Shares{TNumber}"/> is permanently read-only
    /// (<see cref="IsReadOnly"/> returns <see langword="true"/> unconditionally),
    /// so this method always throws <see cref="NotSupportedException"/>.
    /// </summary>
    /// <param name="item">Ignored — the call is rejected before <paramref name="item"/> is inspected.</param>
    /// <returns>This method never returns; it always throws.</returns>
    /// <exception cref="NotSupportedException">Always thrown — the collection is read-only.</exception>
    /// <exception cref="ObjectDisposedException">Thrown when the collection has been disposed.</exception>
    public bool Remove(Share<TNumber> item)
    {
        this.ThrowIfDisposed();
        throw new NotSupportedException(string.Format(ErrorMessages.ReadOnlyCollection, nameof(Shares<>)));
    }

    /// <summary>
    /// Copies the items of the <see cref="Shares{TNumber}"/> collection to an <see cref="Array"/>, starting at a particular <see cref="Array"/> index.
    /// </summary>
    /// <param name="array">The one-dimensional <see cref="Array"/> that is the destination of the items copied from <see cref="Shares{TNumber}"/> collection.
    /// The  <see cref="Array"/> must have zero-based indexing.</param>
    /// <param name="index">The zero-based index in <paramref name="array"/> at which copying begins.</param>
    /// <exception cref="ObjectDisposedException">Thrown when the collection has been disposed.</exception>
    void ICollection.CopyTo(Array array, int index)
    {
        this.ThrowIfDisposed();
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
    /// <exception cref="ObjectDisposedException">Thrown when the collection has been disposed.</exception>
    public void CopyTo(Share<TNumber>[] array, int arrayIndex)
    {
        this.ThrowIfDisposed();
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
    /// <exception cref="ObjectDisposedException">Thrown when the collection has been disposed.</exception>
    object ICollection.SyncRoot
    {
        get
        {
            this.ThrowIfDisposed();
            object newValue = new object();
            return (this.syncRoot ?? Interlocked.CompareExchange(ref this.syncRoot, newValue, null)) ?? newValue;
        }
    }

    /// <summary>
    /// Gets a value indicating whether access to the <see cref="Shares{TNumber}"/> collection is synchronized (thread safe).
    /// </summary>
    /// <exception cref="ObjectDisposedException">Thrown when the collection has been disposed.</exception>
    bool ICollection.IsSynchronized
    {
        get
        {
            this.ThrowIfDisposed();
            return false;
        }
    }

    /// <summary>
    /// Disposes every <see cref="Share{TNumber}"/> in the collection. Idempotent — subsequent calls
    /// are no-ops.
    /// </summary>
    /// <remarks>
    /// <b>Ownership:</b> a <see cref="Shares{TNumber}"/> collection owns every share it contains, and
    /// disposing the collection disposes them all. The collection is read-only, so there is no removal
    /// path (<see cref="Remove"/> throws) that hands an individual share's ownership back to the caller.
    /// </remarks>
    public void Dispose()
    {
        if (Interlocked.Exchange(ref this.disposed, 1) == 1)
        {
            return;
        }

        foreach (var share in this.shareList)
        {
            share?.Dispose();
        }
    }

    /// <summary>
    /// Throws <see cref="ObjectDisposedException"/> if the collection has been disposed.
    /// </summary>
    private void ThrowIfDisposed()
    {
        if (Volatile.Read(ref this.disposed) == 1)
        {
            throw new ObjectDisposedException(nameof(Shares<>));
        }
    }
}
