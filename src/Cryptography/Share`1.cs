// ----------------------------------------------------------------------------
// <copyright file="Share`1.cs" company="Private">
// Copyright (c) 2025 All Rights Reserved
// </copyright>
// <author>Sebastian Walther</author>
// <date>12/24/2025 08:50:07 PM</date>
// ----------------------------------------------------------------------------

#region License
// ----------------------------------------------------------------------------
// Copyright 2025 Sebastian Walther
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

using Math;
using SecureMemory;
using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.CompilerServices;
using System.Threading;

/// <summary>
/// Represents a single share in a secret-sharing scheme.
/// A share is an <c>(index, value)</c> pair representing a point on the secret polynomial —
/// the index is the X coordinate (also known as the polynomial abscissa), the value is the
/// evaluation of the polynomial at that index.
/// </summary>
/// <remarks>
/// <b>Ownership:</b> <see cref="Share{TNumber}"/> owns the <see cref="Calculator{TNumber}"/>
/// instances passed to it as <see cref="Index"/> and <see cref="Value"/>. Call <see cref="Dispose"/>
/// exactly once to release them; after disposal every member except <see cref="Dispose"/> throws
/// <see cref="ObjectDisposedException"/>. A <see cref="Share{TNumber}"/> stored inside a
/// <see cref="Shares{TNumber}"/> collection is owned by that collection — the collection's
/// <see cref="Shares{TNumber}.Dispose"/> disposes every contained share.
/// <para>
/// Do not call <see cref="IDisposable.Dispose"/> on the <see cref="Index"/> or <see cref="Value"/>
/// properties directly; that breaks the share's invariants. Use <see cref="Dispose"/> on the share
/// itself (or on the containing <see cref="Shares{TNumber}"/>) instead.
/// </para>
/// <para>
/// The type supports parsing from and formatting to the standard share format <c>"INDEX-VALUE"</c>
/// where <c>INDEX</c> and <c>VALUE</c> are hexadecimal. Value-based equality is derived from
/// <see cref="Index"/>, <see cref="Value"/> and <see cref="SecurityLevel"/> — so a share that
/// records no level is <em>not</em> equal to one carrying the same coordinates and a level.
/// </para>
/// </remarks>
#if DEBUG
[DebuggerDisplay("{ToString()}")]
#else
[DebuggerDisplay("*** Secured Value ***")]
#endif
public sealed record Share<TNumber> : IComparable<Share<TNumber>>, IDisposable
{
    /// <summary>
    /// The separator between the X and Y coordinate.
    /// </summary>
    private const char CoordinateSeparator = '-';

    /// <summary>
    /// Backing field for <see cref="Index"/>.
    /// </summary>
    private readonly Calculator<TNumber> index;

    /// <summary>
    /// Backing field for <see cref="Value"/>.
    /// </summary>
    private readonly Calculator<TNumber> value;

    /// <summary>
    /// Backing field for <see cref="SecurityLevel"/>. <see langword="null"/> when this share
    /// carries no record of the field it was created in.
    /// </summary>
    private readonly int? securityLevel;

    /// <summary>
    /// Indicates whether the share has been disposed (<c>0</c> = live, <c>1</c> = disposed).
    /// Updated atomically via <see cref="Interlocked.Exchange(ref int, int)"/> so that
    /// concurrent <see cref="Dispose"/> calls cannot both reach the
    /// <see cref="Index"/> / <see cref="Value"/> cascade-dispose branch.
    /// </summary>
    private int disposed;

    /// <summary>
    /// The index (X coordinate) of this share. In Shamir's Secret Sharing, each share is a point
    /// on a polynomial; the index is the X coordinate of that point.
    /// </summary>
    /// <exception cref="ObjectDisposedException">Thrown when the share has been disposed.</exception>
    public Calculator<TNumber> Index
    {
        get
        {
            this.ThrowIfDisposed();
            return this.index;
        }
    }

    /// <summary>
    /// The value (Y coordinate) of this share — the polynomial evaluated at <see cref="Index"/>.
    /// </summary>
    /// <exception cref="ObjectDisposedException">Thrown when the share has been disposed.</exception>
    public Calculator<TNumber> Value
    {
        get
        {
            this.ThrowIfDisposed();
            return this.value;
        }
    }

    /// <summary>
    /// The Mersenne exponent of the finite field this share was created in, or
    /// <see langword="null"/> when the share carries no record of it.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <see langword="null"/> means exactly one thing: <em>no exponent is present</em>. It does
    /// <b>not</b> establish that the share came from the legacy text format — the public
    /// <see cref="Share{TNumber}(Calculator{TNumber}, Calculator{TNumber})"/> and
    /// <see cref="Share{TNumber}(byte[], byte[])"/> constructors produce the same state, because
    /// a caller supplying coordinates cannot know which field they came from.
    /// </para>
    /// <para>
    /// A share created by <c>MakeShares</c> carries the exponent that actually governed the
    /// polynomial — the value after any auto-raise, not the one the caller requested.
    /// </para>
    /// </remarks>
    /// <exception cref="ObjectDisposedException">Thrown when the share has been disposed.</exception>
    public int? SecurityLevel
    {
        get
        {
            this.ThrowIfDisposed();
            return this.securityLevel;
        }
    }

    /// <summary>
    /// Gets a value indicating whether the share index is even.
    /// </summary>
    /// <exception cref="ObjectDisposedException">Thrown when the share has been disposed.</exception>
    public bool IsIndexEven
    {
        get
        {
            this.ThrowIfDisposed();
            return this.index.IsEven;
        }
    }

    /// <summary>
    /// Gets a value indicating whether the share index is odd.
    /// </summary>
    /// <exception cref="ObjectDisposedException">Thrown when the share has been disposed.</exception>
    public bool IsIndexOdd
    {
        get
        {
            this.ThrowIfDisposed();
            return !this.index.IsEven;
        }
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="Share{TNumber}"/> record with the specified index and value.
    /// </summary>
    /// <param name="index">The index (X coordinate) of the share. Must be positive.</param>
    /// <param name="value">The value (Y coordinate) of the share.</param>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="index"/> or <paramref name="value"/> is <see langword="null"/>.
    /// </exception>
    /// <exception cref="ArgumentOutOfRangeException">
    /// Thrown when <paramref name="index"/> is less than one.
    /// </exception>
    public Share(Calculator<TNumber> index, Calculator<TNumber> value)
    {
        if (index is null)
        {
            throw new ArgumentNullException(nameof(index));
        }

        using var one = Calculator<TNumber>.One;
        if (index < one)
        {
            throw new ArgumentOutOfRangeException(
                nameof(index),
                index,
                ErrorMessages.ShareIndexMustBePositive);
        }

        if (value is null)
        {
            throw new ArgumentNullException(nameof(value));
        }

        this.index = index;
        this.value = value;
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="Share{TNumber}"/> record that records the
    /// finite field it was created in.
    /// </summary>
    /// <param name="index">The index (X coordinate). Ownership transfers to this instance.</param>
    /// <param name="value">The value (Y coordinate). Ownership transfers to this instance.</param>
    /// <param name="securityLevel">
    /// The Mersenne exponent governing the polynomial this share lies on.
    /// </param>
    /// <remarks>
    /// <see langword="internal"/> on purpose: the exponent is not validated here, because the only
    /// caller is <c>SecretSplitter.CreateShares</c> and it passes the value its
    /// <c>ISecurityLevelManager</c> has already normalised. Every path that takes an exponent from
    /// outside the library validates it at that boundary instead.
    /// </remarks>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="index"/> or <paramref name="value"/> is <see langword="null"/>.
    /// </exception>
    /// <exception cref="ArgumentOutOfRangeException">
    /// Thrown when <paramref name="index"/> is less than one.
    /// </exception>
    internal Share(Calculator<TNumber> index, Calculator<TNumber> value, int securityLevel)
        : this(index, value)
    {
        this.securityLevel = securityLevel;
    }

    /// <summary>
    /// Blocks the record-synthesised copy constructor. <see cref="Share{TNumber}"/> owns
    /// its <see cref="Index"/> / <see cref="Value"/> <see cref="Calculator{TNumber}"/>
    /// backing fields under a single-owner contract (see the type-level remarks); a
    /// shallow record clone would alias those references across two instances and the
    /// first <see cref="Dispose"/> would silently invalidate the other copy. The
    /// <c>with</c> expression and any other path that the compiler routes through this
    /// constructor therefore throw <see cref="NotSupportedException"/>. Build new shares
    /// via the public <c>(index, value)</c> constructor, or obtain them from a
    /// <see cref="Shares{TNumber}"/> collection.
    /// </summary>
    /// <param name="original">Ignored — this constructor unconditionally throws.</param>
    /// <exception cref="NotSupportedException">Always thrown.</exception>
    [EditorBrowsable(EditorBrowsableState.Never)]
#pragma warning disable CS0628 // protected member in sealed type — required signature for the record copy constructor that the compiler routes `with` through.
    protected Share(Share<TNumber> original)
#pragma warning restore CS0628
    {
        throw new NotSupportedException(ErrorMessages.ShareIsNonCopyable);
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="Share{TNumber}"/> record by parsing a pinned character buffer.
    /// </summary>
    /// <param name="shareString">
    /// A <see cref="PinnedPoolArray{T}"/> of <see cref="char"/> containing the share in the format
    /// <c>"INDEX-VALUE"</c>, where <c>INDEX</c> and <c>VALUE</c> are hexadecimal strings, optionally prefixed
    /// with lowercase <c>"0x"</c>. Leading and trailing whitespace is ignored.
    /// </param>
    /// <remarks>
    /// The parser operates exclusively on the pinned backing buffer. No intermediate, unpinned
    /// heap copies of the share material are created. The caller retains ownership of
    /// <paramref name="shareString"/> and is responsible for its disposal.
    /// </remarks>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="shareString"/> is <see langword="null"/>.
    /// </exception>
    /// <exception cref="InvalidShareException">
    /// Thrown when <paramref name="shareString"/> is malformed: it does not contain the coordinate
    /// separator, contains non-hexadecimal characters (the message identifies the zero-based position
    /// of the first invalid character), has an empty coordinate after prefix stripping, or decodes to
    /// an index that is not positive.
    /// </exception>
    public Share(PinnedPoolArray<char> shareString)
    {
        var (parsedIndex, parsedValue, parsedSecurityLevel) = ParseCore(shareString);
        this.index = parsedIndex;
        this.value = parsedValue;
        this.securityLevel = parsedSecurityLevel;
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="Share{TNumber}"/> struct from raw byte arrays.
    /// </summary>
    /// <param name="indexBytes">The byte array representing the index (X coordinate).</param>
    /// <param name="valueBytes">The byte array representing the value (Y coordinate).</param>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="indexBytes"/> or <paramref name="valueBytes"/> is <see langword="null"/>.
    /// </exception>
    /// <exception cref="InvalidShareException">
    /// Thrown when the decoded index is less than one.
    /// </exception>
    /// <exception cref="NotSupportedException">
    /// Thrown when no <see cref="Calculator{TNumber}"/> implementation is registered for
    /// <typeparamref name="TNumber"/>.
    /// </exception>
    public Share(byte[] indexBytes, byte[] valueBytes)
    {
        if (indexBytes is null)
        {
            throw new ArgumentNullException(nameof(indexBytes));
        }

        if (valueBytes is null)
        {
            throw new ArgumentNullException(nameof(valueBytes));
        }

        var (decodedIndex, decodedValue) = DecodeFromBytes(indexBytes, valueBytes);
        this.index = decodedIndex;
        this.value = decodedValue;
    }

    /// <summary>
    /// Compares this share to another share by their indices.
    /// </summary>
    /// <param name="other">The other share to compare to. May be <see langword="null"/>.</param>
    /// <returns>
    /// A negative value if this share's index is less than the other's,
    /// zero if they are equal, or a positive value if this share's index is greater.
    /// Any non-null share compares greater than <see langword="null"/>.
    /// </returns>
    /// <exception cref="ObjectDisposedException">Thrown when the share has been disposed.</exception>
    public int CompareTo(Share<TNumber> other)
    {
        this.ThrowIfDisposed();
        if (other is null)
        {
            return 1;
        }

        return this.Index.CompareTo(other.Index);
    }

    /// <summary>
    /// Determines whether this share is equal to <paramref name="other"/>. Value-based
    /// equality derived from <see cref="Index"/>, <see cref="Value"/> and
    /// <see cref="SecurityLevel"/>; the per-Calculator
    /// comparisons delegate to the underlying <typeparamref name="TNumber"/> backend
    /// (constant-time on operand value for the
    /// <see cref="SecretSharingDotNet.Math.Numerics.SecureBigInteger"/> backend via its
    /// fixed-time-limbs equality).
    /// </summary>
    /// <param name="other">The other share to compare to. May be <see langword="null"/>.</param>
    /// <returns>
    /// <see langword="true"/> when both shares carry the same <see cref="Index"/>,
    /// <see cref="Value"/> and <see cref="SecurityLevel"/>; otherwise <see langword="false"/>.
    /// Returns <see langword="false"/> when <paramref name="other"/> is <see langword="null"/>.
    /// </returns>
    /// <remarks>
    /// <see cref="SecurityLevel"/> is compared as a nullable value, not as a wildcard: two shares
    /// that both record no level are equal, and a share recording none differs from one recording
    /// any. Treating <see langword="null"/> as "matches any level" would break transitivity. The
    /// practical consequence is that a share parsed from the legacy two-segment text form is not
    /// equal to its migrated counterpart, which is observable through
    /// <see cref="Shares{TNumber}.Contains"/> and through <c>HashSet</c> membership.
    /// </remarks>
    /// <remarks>
    /// Replaces the compiler-synthesised record equality, which would (a) compare the internal
    /// <c>disposed</c> flag and therefore disagree on equality between a live and a just-disposed
    /// share with otherwise-identical content (contradicting the value-based contract documented
    /// on the class), and (b) route through the SecureBigInteger backend's <c>Equals</c> on a
    /// disposed operand and surface <see cref="ObjectDisposedException"/>.
    ///
    /// The two Calculator-level comparison results are pre-computed into local <see cref="bool"/>s
    /// and folded with a non-short-circuit <c>&amp;</c>; this mirrors the constant-time pattern
    /// of <c>SecureBigInteger.Equals</c> (see the matching S2178 suppression there) and remains
    /// resilient against later refactors that might inline either side of the equality fold
    /// into a short-circuit-sensitive expression.
    /// </remarks>
    /// <exception cref="ObjectDisposedException">Thrown when the share has been disposed.</exception>
    [SuppressMessage("SonarQube", "S2178",
        Justification = "Non-short-circuit AND is intentional in this constant-time context. " +
                        "Using && would emit a conditional branch on `indexEqual` to skip the " +
                        "second operand; the `&` form documents the CT-design intent and is " +
                        "resilient to future refactors that inline either side. Mirrors the " +
                        "established pattern in SecureBigInteger.Equals.")]
    public bool Equals(Share<TNumber> other)
    {
        if (other is null)
        {
            return false;
        }

        this.ThrowIfDisposed();
        other.ThrowIfDisposed();

        if (ReferenceEquals(this, other))
        {
            return true;
        }

        bool indexEqual = this.index.Equals(other.index);
        bool valueEqual = this.value.Equals(other.value);
        // Nullable int equality, not a wildcard: null equals null and differs from every
        // exponent. Treating null as "matches any level" would break transitivity.
        bool levelEqual = this.securityLevel == other.securityLevel;
        return indexEqual & valueEqual & levelEqual;
    }

    /// <summary>
    /// Returns a hash code consistent with <see cref="Equals(Share{TNumber})"/>, derived from
    /// <see cref="Index"/>, <see cref="Value"/> and <see cref="SecurityLevel"/>. Equal shares
    /// therefore hash equally; the converse is not promised, and the contract does not ask for
    /// it. The internal <c>disposed</c> flag is
    /// intentionally excluded from the hash so that an otherwise-identical live and disposed
    /// share would produce the same hash — matching the equality contract.
    /// </summary>
    /// <returns>A hash code for the current share.</returns>
    /// <exception cref="ObjectDisposedException">Thrown when the share has been disposed.</exception>
    [SuppressMessage("ReSharper", "NonReadonlyMemberInGetHashCode",
        Justification = "The index/value Calculator fields are assigned once in the ctor and never reassigned.")]
    [SuppressMessage("SonarQube", "S2328",
        Justification = "The index/value Calculator fields are assigned once in the ctor and never reassigned.")]
    public override int GetHashCode()
    {
        this.ThrowIfDisposed();
#if NETSTANDARD2_1_OR_GREATER || NET8_0_OR_GREATER
        var hash = new HashCode();
        hash.Add(this.index);
        hash.Add(this.value);
        hash.Add(this.securityLevel);
        return hash.ToHashCode();
#else
        unchecked
        {
            int h = 17;
            h = h * 31 + this.index.GetHashCode();
            h = h * 31 + this.value.GetHashCode();
            h = h * 31 + this.securityLevel.GetHashCode();
            return h;
        }
#endif
    }

    /// <summary>
    /// Returns a string representation of the current <see cref="Share{TNumber}"/> instance.
    /// </summary>
    /// <returns>
    /// In Debug builds: the hex-encoded share in the format "INDEX-VALUE".
    /// In Release builds: always returns <c>"*** Secured Value ***"</c> to prevent accidental exposure
    /// in logs, exception messages, or other output. Use <see cref="ToCharArray()"/> for explicit serialization.
    /// </returns>
    /// <remarks>
    /// <b>Security warning:</b> DEBUG builds expose share material on the unpinned managed heap via the
    /// returned <see cref="string"/>. The <see cref="string"/> instance is immutable, cannot be cleared,
    /// and may be relocated by the GC — so its contents remain recoverable from process memory until
    /// collected (and even beyond, in swap files or crash dumps). Do not log, serialize, or otherwise
    /// persist <see cref="ToString"/> output in any build that handles real secrets. For secure
    /// serialization use <see cref="ToCharArray()"/>, which returns share material in pinned memory
    /// that is securely cleared on <see cref="IDisposable.Dispose"/>.
    /// </remarks>
    public override string ToString()
    {
#if DEBUG
        this.ThrowIfDisposed();
        return this.FormatHex(uppercase: true);
#else
        return "*** Secured Value ***";
#endif
    }

    /// <summary>
    /// Converts the share to a <see cref="PinnedPoolArray{Char}"/> containing the uppercase hex-encoded share
    /// characters in the format "INDEX-VALUE".
    /// </summary>
    /// <returns>
    /// A <see cref="PinnedPoolArray{Char}"/> with the hex-encoded share.
    /// The caller is responsible for disposing of the returned instance.
    /// </returns>
    /// <exception cref="ObjectDisposedException">Thrown when the share has been disposed.</exception>
    public PinnedPoolArray<char> ToCharArray() => this.ToCharArray(uppercase: true, withPrefix: false);

    /// <summary>
    /// Converts the share to a <see cref="PinnedPoolArray{Char}"/> containing the hex-encoded share
    /// characters in the format "INDEX-VALUE" or "0xINDEX-0xVALUE".
    /// </summary>
    /// <param name="uppercase">
    /// <see langword="true"/> to use uppercase hex digits (0A–0F); <see langword="false"/> for lowercase (0a–0f).
    /// </param>
    /// <param name="withPrefix">
    /// <see langword="true"/> to prepend <c>"0x"</c> before each coordinate; <see langword="false"/> for no prefix.
    /// </param>
    /// <returns>
    /// A <see cref="PinnedPoolArray{Char}"/> with the hex-encoded share.
    /// The caller is responsible for disposing of the returned instance.
    /// </returns>
    /// <exception cref="ObjectDisposedException">Thrown when the share has been disposed.</exception>
    public PinnedPoolArray<char> ToCharArray(bool uppercase, bool withPrefix = false) =>
        this.ToCharArray(uppercase, withPrefix, ShareFormat.Legacy);

    /// <summary>
    /// Converts the share to a pinned character buffer in the given serialized form.
    /// </summary>
    /// <param name="uppercase">
    /// <see langword="true"/> for uppercase hex digits (0A–0F); <see langword="false"/> for lowercase.
    /// </param>
    /// <param name="withPrefix">
    /// <see langword="true"/> to prepend <c>"0x"</c> to every segment, the security level included.
    /// </param>
    /// <param name="format">Which serialized form to write.</param>
    /// <returns>
    /// A <see cref="PinnedPoolArray{T}"/> with the hex-encoded share. The caller disposes it.
    /// </returns>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="format"/> is not a defined value.</exception>
    /// <exception cref="InvalidOperationException">
    /// <paramref name="format"/> is <see cref="ShareFormat.Extended"/> and this share records no
    /// <see cref="SecurityLevel"/>.
    /// </exception>
    /// <exception cref="ObjectDisposedException">Thrown when the share has been disposed.</exception>
    public PinnedPoolArray<char> ToCharArray(bool uppercase, bool withPrefix, ShareFormat format)
    {
        this.ThrowIfDisposed();
        var total = this.GetCharCount(withPrefix, format);
        var result = new PinnedPoolArray<char>(total);
        this.WriteCharsTo(result.PoolArray, 0, uppercase, withPrefix, format);
        return result;
    }

    /// <summary>
    /// Computes the number of characters that would be produced when serializing this share
    /// via <see cref="ToCharArray(bool, bool)"/> or <see cref="WriteCharsTo(char[], int, bool, bool)"/>.
    /// </summary>
    /// <param name="withPrefix">
    /// <see langword="true"/> if the length should include a <c>"0x"</c> prefix per coordinate;
    /// otherwise <see langword="false"/>.
    /// </param>
    /// <returns>
    /// The number of characters required.
    /// </returns>
    /// <remarks>
    /// Computes the length without materializing the underlying byte representation. Relies on
    /// <see cref="Calculator.ByteCount"/> — which, depending on the concrete calculator, is either
    /// lazily cached or a direct field read — so no <see cref="PinnedPoolArray{T}"/> allocation is
    /// performed. The invariant <c>ByteCount == ByteRepresentation.Length</c> is assumed; it is
    /// asserted in unit tests.
    /// </remarks>
    /// <exception cref="ObjectDisposedException">Thrown when the share has been disposed.</exception>
    public int GetCharCount(bool withPrefix) => this.GetCharCount(withPrefix, ShareFormat.Legacy);

    /// <summary>
    /// Returns the number of characters <see cref="WriteCharsTo(char[], int, bool, bool, ShareFormat)"/>
    /// writes for the given options.
    /// </summary>
    /// <param name="withPrefix">
    /// <see langword="true"/> to count a <c>"0x"</c> prefix on every segment.
    /// </param>
    /// <param name="format">Which serialized form to measure.</param>
    /// <returns>The number of characters required.</returns>
    /// <remarks>
    /// Shares its arithmetic with the writer through <see cref="MeasureChars"/> rather than
    /// restating it. The two used to carry the same expression twice, which is the shape that
    /// quietly disagrees the moment a segment is added.
    /// </remarks>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="format"/> is not a defined value.</exception>
    /// <exception cref="InvalidOperationException">
    /// <paramref name="format"/> is <see cref="ShareFormat.Extended"/> and this share records no
    /// <see cref="SecurityLevel"/>.
    /// </exception>
    /// <exception cref="ObjectDisposedException">Thrown when the share has been disposed.</exception>
    public int GetCharCount(bool withPrefix, ShareFormat format)
    {
        this.ThrowIfDisposed();
        return MeasureChars(this.Index.ByteCount, this.Value.ByteCount, this.SecurityLevelDigits(format), withPrefix);
    }

    /// <summary>
    /// The number of hexadecimal digits the security level occupies in the given format, or zero
    /// when the format does not carry one.
    /// </summary>
    /// <param name="format">The serialized form.</param>
    /// <returns>Zero for <see cref="ShareFormat.Legacy"/>; otherwise the digit count.</returns>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="format"/> is not a defined value.</exception>
    /// <exception cref="InvalidOperationException">
    /// The extended form was requested and this share records no level. Emitting a zero, dropping
    /// back to two segments or guessing would each hand back a share claiming a field it does not
    /// know; the caller has to learn that the information was never there.
    /// </exception>
    private int SecurityLevelDigits(ShareFormat format)
    {
        ShareFormatValidation.EnsureDefined(format, nameof(format));
        if (format == ShareFormat.Legacy)
        {
            return 0;
        }

        if (this.securityLevel is null)
        {
            throw new InvalidOperationException(ErrorMessages.ShareHasNoSecurityLevelToSerialize);
        }

        return HexDigitCount(this.securityLevel.Value);
    }

    /// <summary>
    /// The number of hexadecimal digits needed for a positive <see cref="int"/>, at least one.
    /// </summary>
    /// <param name="value">The value to measure. Security levels are always positive.</param>
    /// <returns>The digit count.</returns>
    private static int HexDigitCount(int value)
    {
        int digits = 1;
        for (int remaining = value >> 4; remaining != 0; remaining >>= 4)
        {
            digits++;
        }

        return digits;
    }

    /// <summary>
    /// The single length rule for the serialized form, shared by the measurer and the writer.
    /// </summary>
    /// <param name="indexByteCount">Byte length of the index coordinate.</param>
    /// <param name="valueByteCount">Byte length of the value coordinate.</param>
    /// <param name="securityLevelDigits">Hex digits of the security level, or zero for none.</param>
    /// <param name="withPrefix">Whether each segment carries a <c>"0x"</c> prefix.</param>
    /// <returns>The total character count.</returns>
    /// <remarks>
    /// The prefix count follows the segment count, so adding a segment does not mean remembering
    /// to change a hard-coded multiplier in two places.
    /// </remarks>
    private static int MeasureChars(int indexByteCount, int valueByteCount, int securityLevelDigits, bool withPrefix)
    {
        int segments = securityLevelDigits > 0 ? 3 : 2;
        int prefixLength = withPrefix ? 2 : 0;
        int total = (segments * prefixLength) + (indexByteCount * 2) + 1 + (valueByteCount * 2);
        if (securityLevelDigits > 0)
        {
            total += 1 + securityLevelDigits;
        }

        return total;
    }

    /// <summary>
    /// Writes the hex-encoded share characters into <paramref name="dest"/> starting at
    /// <paramref name="offset"/>, without allocating an intermediate <see cref="PinnedPoolArray{T}"/>.
    /// </summary>
    /// <param name="dest">The destination character buffer. The caller is responsible for its lifetime and pinning.</param>
    /// <param name="offset">The zero-based index into <paramref name="dest"/> where writing starts.</param>
    /// <param name="uppercase">
    /// <see langword="true"/> to use uppercase hex digits (0A–0F); <see langword="false"/> for lowercase (0a–0f).
    /// </param>
    /// <param name="withPrefix">
    /// <see langword="true"/> to prepend <c>"0x"</c> before each coordinate; <see langword="false"/> for no prefix.
    /// </param>
    /// <returns>
    /// The number of characters written.
    /// </returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="dest"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentOutOfRangeException">Thrown when <paramref name="offset"/> is negative or greater than <c>dest.Length</c>.</exception>
    /// <exception cref="ArgumentException">Thrown when <paramref name="dest"/> has insufficient remaining space.</exception>
    /// <exception cref="ObjectDisposedException">Thrown when the share has been disposed.</exception>
    public int WriteCharsTo(char[] dest, int offset, bool uppercase, bool withPrefix) =>
        this.WriteCharsTo(dest, offset, uppercase, withPrefix, ShareFormat.Legacy);

    /// <summary>
    /// Writes the hex-encoded share characters into <paramref name="dest"/> in the given format.
    /// </summary>
    /// <param name="dest">The destination character buffer. The caller owns its lifetime and pinning.</param>
    /// <param name="offset">The zero-based index into <paramref name="dest"/> where writing starts.</param>
    /// <param name="uppercase">
    /// <see langword="true"/> for uppercase hex digits (0A–0F); <see langword="false"/> for lowercase.
    /// </param>
    /// <param name="withPrefix">
    /// <see langword="true"/> to prepend <c>"0x"</c> to every segment, the security level included.
    /// </param>
    /// <param name="format">Which serialized form to write.</param>
    /// <returns>The number of characters written.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="dest"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentOutOfRangeException">
    /// <paramref name="offset"/> is negative or greater than <c>dest.Length</c>, or
    /// <paramref name="format"/> is not a defined value.
    /// </exception>
    /// <exception cref="ArgumentException"><paramref name="dest"/> has insufficient remaining space.</exception>
    /// <exception cref="InvalidOperationException">
    /// <paramref name="format"/> is <see cref="ShareFormat.Extended"/> and this share records no
    /// <see cref="SecurityLevel"/>.
    /// </exception>
    /// <exception cref="ObjectDisposedException">Thrown when the share has been disposed.</exception>
    public int WriteCharsTo(char[] dest, int offset, bool uppercase, bool withPrefix, ShareFormat format)
    {
        this.ThrowIfDisposed();
        if (dest is null)
        {
            throw new ArgumentNullException(nameof(dest));
        }

        if (offset < 0 || offset > dest.Length)
        {
            throw new ArgumentOutOfRangeException(nameof(offset));
        }

        int securityLevelDigits = this.SecurityLevelDigits(format);
        using var indexBytes = this.Index.ByteRepresentation;
        using var valueBytes = this.Value.ByteRepresentation;
        var total = MeasureChars(indexBytes.Length, valueBytes.Length, securityLevelDigits, withPrefix);
        if (dest.Length - offset < total)
        {
            throw new ArgumentException(ErrorMessages.DestinationArrayHasFewerElements, nameof(dest));
        }

        var pos = offset;
        pos = WritePrefix(dest, pos, withPrefix);
        WriteHexChars(indexBytes, dest, pos, uppercase);
        pos += indexBytes.Length * 2;
        dest[pos++] = CoordinateSeparator;
        pos = WritePrefix(dest, pos, withPrefix);
        WriteHexChars(valueBytes, dest, pos, uppercase);
        pos += valueBytes.Length * 2;
        if (securityLevelDigits > 0)
        {
            dest[pos++] = CoordinateSeparator;
            pos = WritePrefix(dest, pos, withPrefix);
            WriteHexInt32(this.securityLevel.Value, securityLevelDigits, dest, pos, uppercase);
            pos += securityLevelDigits;
        }

        return pos - offset;
    }

    /// <summary>
    /// Writes a positive <see cref="int"/> as <paramref name="digits"/> hexadecimal characters.
    /// </summary>
    /// <param name="value">The value to write.</param>
    /// <param name="digits">The digit count, from <see cref="HexDigitCount"/>.</param>
    /// <param name="dest">The destination buffer.</param>
    /// <param name="offset">Where to start writing.</param>
    /// <param name="uppercase">Whether to use uppercase digits.</param>
    /// <remarks>
    /// The security level is public metadata, so this needs none of the fixed-time care the
    /// coordinate encoding is held to.
    /// </remarks>
    private static void WriteHexInt32(int value, int digits, char[] dest, int offset, bool uppercase)
    {
        char letterBase = uppercase ? 'A' : 'a';
        for (int i = 0; i < digits; i++)
        {
            int nibble = (value >> (4 * i)) & 0xF;
            dest[offset + digits - 1 - i] = nibble < 10
                ? (char)('0' + nibble)
                : (char)(letterBase + nibble - 10);
        }
    }

    /// <summary>
    /// Determines whether one share is less than another based on their indices.
    /// </summary>
    public static bool operator <(Share<TNumber> left, Share<TNumber> right)
        => left is not null && left.CompareTo(right) < 0;

    /// <summary>
    /// Determines whether one share is greater than another based on their indices.
    /// </summary>
    public static bool operator >(Share<TNumber> left, Share<TNumber> right)
        => left is not null ? left.CompareTo(right) > 0 : right is not null;

    /// <summary>
    /// Determines whether one share is less than or equal to another based on their indices.
    /// </summary>
    public static bool operator <=(Share<TNumber> left, Share<TNumber> right)
        => left is null || left.CompareTo(right) <= 0;

    /// <summary>
    /// Determines whether one share is greater than or equal to another based on their indices.
    /// </summary>
    public static bool operator >=(Share<TNumber> left, Share<TNumber> right)
        => left is not null ? left.CompareTo(right) >= 0 : right is null;

    /// <summary>
    /// Releases the <see cref="Calculator{TNumber}"/> instances backing <see cref="Index"/> and
    /// <see cref="Value"/>. Idempotent and safe to call from multiple threads concurrently —
    /// the cascade-dispose runs exactly once.
    /// After disposal, all members except <see cref="Dispose"/> throw
    /// <see cref="ObjectDisposedException"/>.
    /// </summary>
    public void Dispose()
    {
        if (Interlocked.Exchange(ref this.disposed, 1) == 1)
        {
            return;
        }

        // Access the backing fields directly: the public Index / Value property
        // accessors call ThrowIfDisposed, and the disposed flag has already flipped
        // to 1 above. Going through the properties would unconditionally throw and
        // skip the cascade-dispose entirely.
        this.index?.Dispose();
        this.value?.Dispose();
    }

    /// <summary>
    /// Throws <see cref="ObjectDisposedException"/> if the share has been disposed.
    /// </summary>
    private void ThrowIfDisposed()
    {
        if (Volatile.Read(ref this.disposed) == 1)
        {
            throw new ObjectDisposedException(nameof(Share<>));
        }
    }

    /// <summary>
    /// Deconstructs this share into its x and y coordinate.
    /// </summary>
    /// <param name="x">The index (X coordinate) of the share.</param>
    /// <param name="y">The value (Y coordinate) of the share.</param>
    public void Deconstruct(out Calculator<TNumber> x, out Calculator<TNumber> y)
    {
        x = this.Index;
        y = this.Value;
    }

    /// <summary>
    /// Parses the serialized share string into its index and value components.
    /// </summary>
    /// <param name="serialized">The serialized representation of the share, stored in a secured character array.</param>
    /// <returns>A tuple containing the parsed index and value as instances of <see cref="Calculator{TNumber}"/>.</returns>
    /// <remarks>
    /// Validation and decoding run in a single pass: <see cref="DecodeHexToCalculator"/> emits an
    /// <see cref="InvalidShareException"/> at the first non-hexadecimal character it encounters, with
    /// the character's position included in the message.
    /// </remarks>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="serialized"/> is <see langword="null"/>.
    /// </exception>
    /// <exception cref="InvalidShareException">
    /// Thrown when the provided <paramref name="serialized"/> is malformed: it does not contain a
    /// coordinate separator, contains non-hexadecimal characters (the message includes the zero-based
    /// position of the first invalid character), has an empty coordinate, or decodes to an index that
    /// is not positive.
    /// </exception>
    private static (Calculator<TNumber> Index, Calculator<TNumber> Value, int? SecurityLevel) ParseCore(
        PinnedPoolArray<char> serialized)
    {
        if (serialized is null)
        {
            throw new ArgumentNullException(nameof(serialized));
        }

        var buf = serialized.PoolArray;
        var (start, end) = TrimRange(buf, 0, serialized.Length);

        var separatorIndex = IndexOf(buf, start, end, CoordinateSeparator);
        if (separatorIndex < 0)
        {
            throw new InvalidShareException(string.Format(ErrorMessages.InvalidShareFormat, CoordinateSeparator));
        }

        // Two segments or three. A fourth has never been written by this library, and reading it
        // as "the value happens to contain a separator" is how the older parser failed anyway —
        // just with a message about a hex digit rather than about the shape.
        var levelSeparatorIndex = IndexOf(buf, separatorIndex + 1, end, CoordinateSeparator);
        if (levelSeparatorIndex >= 0
            && IndexOf(buf, levelSeparatorIndex + 1, end, CoordinateSeparator) >= 0)
        {
            throw new InvalidShareException(string.Format(ErrorMessages.ShareHasTooManySegments, CoordinateSeparator));
        }

        var valueEnd = levelSeparatorIndex >= 0 ? levelSeparatorIndex : end;
        var indexStart = StripHexPrefix(buf, start, separatorIndex);
        var valueStart = StripHexPrefix(buf, separatorIndex + 1, valueEnd);
        var indexLen = separatorIndex - indexStart;
        var valueLen = valueEnd - valueStart;

        if (indexLen == 0 || valueLen == 0)
        {
            throw new InvalidShareException(ErrorMessages.ShareIndexAndValueMustBeNonEmpty);
        }

        int? securityLevel = null;
        if (levelSeparatorIndex >= 0)
        {
            var levelStart = StripHexPrefix(buf, levelSeparatorIndex + 1, end);
            securityLevel = DecodeHexToInt32(buf, levelStart, end - levelStart);
        }

        Calculator<TNumber> index = null;
        Calculator<TNumber> value = null;
        try
        {
            index = DecodeHexToCalculator(buf, indexStart, indexLen);
            value = DecodeHexToCalculator(buf, valueStart, valueLen);
            using var one = Calculator<TNumber>.One;
            if (index < one)
            {
                throw new InvalidShareException(ErrorMessages.ShareIndexMustBePositive);
            }

            var result = (index, value, securityLevel);
            index = null;
            value = null;

            return result;
        }
        finally
        {
            index?.Dispose();
            value?.Dispose();
        }
    }

    /// <summary>
    /// Decodes raw index and value byte arrays into a pair of <see cref="Calculator{TNumber}"/> instances.
    /// </summary>
    /// <remarks>
    /// Uses the try/finally null-transfer pattern: if the second <see cref="Calculator.Create{TNumber}(byte[], int)"/>
    /// call or the index validation throws, any already-allocated <see cref="Calculator{TNumber}"/> is disposed
    /// to prevent resource leaks.
    /// </remarks>
    /// <exception cref="InvalidShareException">
    /// Thrown when the decoded index is less than one.
    /// </exception>
    /// <exception cref="NotSupportedException">
    /// Thrown when no calculator implementation is registered for <typeparamref name="TNumber"/>
    /// (propagated from <see cref="Calculator.Create{TNumber}(byte[], int)"/>). This is a
    /// configuration error, not invalid user input.
    /// </exception>
    private static (Calculator<TNumber> Index, Calculator<TNumber> Value) DecodeFromBytes(byte[] indexBytes, byte[] valueBytes)
    {
        Calculator<TNumber> index = null;
        Calculator<TNumber> value = null;
        try
        {
            index = Calculator.Create<TNumber>(indexBytes, indexBytes.Length);
            using var one = Calculator<TNumber>.One;
            if (index < one)
            {
                throw new InvalidShareException(ErrorMessages.ShareIndexMustBePositive);
            }

            value = Calculator.Create<TNumber>(valueBytes, valueBytes.Length);

            var result = (index, value);
            index = null;
            value = null;

            return result;
        }
        finally
        {
            index?.Dispose();
            value?.Dispose();
        }
    }

    /// <summary>
    /// Decodes the security level segment: hexadecimal characters to a positive <see cref="int"/>.
    /// </summary>
    /// <param name="buf">The character buffer.</param>
    /// <param name="offset">Start of the segment, after any <c>"0x"</c> prefix.</param>
    /// <param name="length">Length of the segment.</param>
    /// <returns>The decoded exponent.</returns>
    /// <remarks>
    /// Decoded to <see cref="int"/> directly rather than through a <see cref="Calculator{TNumber}"/>:
    /// the level is a small public integer, and the round trip would need a conversion back that
    /// this library deliberately removed. Whether the exponent is one the library <em>supports</em>
    /// is a different question and is not asked here — a share carries no provider to ask. That
    /// check belongs to reconstruction, where a manager is present.
    /// </remarks>
    /// <exception cref="InvalidShareException">
    /// The segment is empty, too long, contains a non-hexadecimal character, or decodes to a
    /// non-positive value.
    /// </exception>
    private static int DecodeHexToInt32(char[] buf, int offset, int length)
    {
        if (length <= 0 || length > 8)
        {
            throw new InvalidShareException(ErrorMessages.ShareSecurityLevelSegmentInvalid);
        }

        int decoded = 0;
        for (int i = 0; i < length; i++)
        {
            var digit = GetHexValue(buf[offset + i]);
            if (digit < 0)
            {
                throw new InvalidShareException(
                    string.Format(ErrorMessages.InvalidHexCharacter, offset + i));
            }

            decoded = (decoded << 4) | digit;
        }

        if (decoded <= 0)
        {
            throw new InvalidShareException(ErrorMessages.ShareSecurityLevelSegmentInvalid);
        }

        return decoded;
    }

    /// <summary>
    /// Decodes a hex substring at <c>buf[offset..offset+length]</c> into a <see cref="Calculator{TNumber}"/>.
    /// Validates and decodes in a single pass — the first non-hexadecimal character triggers an
    /// <see cref="ArgumentException"/> whose message contains the offending character's position.
    /// </summary>
    /// <remarks>
    /// Intermediate byte material is held in a <see cref="PinnedPoolArray{T}"/>, which is securely
    /// cleared on dispose. Odd-length input is left-padded by writing the single high nibble into the
    /// first output byte.
    /// </remarks>
    /// <exception cref="InvalidShareException">
    /// Thrown when a non-hexadecimal character is encountered. The message identifies the zero-based
    /// position of the invalid character within <paramref name="buf"/>.
    /// </exception>
    private static Calculator<TNumber> DecodeHexToCalculator(char[] buf, int offset, int length)
    {
        var byteCount = (length + 1) >> 1;
        using var bytes = new PinnedPoolArray<byte>(byteCount);
        var bytesArray = bytes.PoolArray;
        var writeIndex = 0;
        var readIndex = 0;

        if ((length & 1) == 1)
        {
            var low = GetHexValue(buf[offset]);
            if (low < 0)
            {
                throw new InvalidShareException(string.Format(ErrorMessages.InvalidHexCharacter, offset));
            }

            bytesArray[writeIndex++] = (byte)low;
            readIndex = 1;
        }

        while (readIndex < length)
        {
            var high = GetHexValue(buf[offset + readIndex]);
            var low = GetHexValue(buf[offset + readIndex + 1]);
            if (high < 0 || low < 0)
            {
                throw new InvalidShareException(
                    string.Format(ErrorMessages.InvalidHexCharacter, high < 0 ? offset + readIndex : offset + readIndex + 1));
            }

            bytesArray[writeIndex++] = (byte)((high << 4) | low);
            readIndex += 2;
        }

        return Calculator.Create<TNumber>(bytesArray, bytes.Length);
    }

    /// <summary>
    /// Returns the indexes after trimming the leading and trailing whitespace characters within the specified range of the input buffer.
    /// </summary>
    /// <param name="buf">The character array containing the data to be processed.</param>
    /// <param name="start">The starting index of the range to be trimmed.</param>
    /// <param name="end">The ending index of the range to be trimmed.</param>
    /// <returns>
    /// A tuple containing the updated <paramref name="start"/> and <paramref name="end"/> indices
    /// after removing leading and trailing whitespace.
    /// </returns>
    private static (int Start, int End) TrimRange(char[] buf, int start, int end)
    {
        while (start < end && char.IsWhiteSpace(buf[start]))
        {
            start++;
        }

        while (end > start && char.IsWhiteSpace(buf[end - 1]))
        {
            end--;
        }

        return (start, end);
    }

    /// <summary>
    /// Searches for the first occurrence of the specified character within a specified range in the given character array.
    /// </summary>
    /// <param name="buf">The character array to search within.</param>
    /// <param name="start">The starting index of the range to search.</param>
    /// <param name="end">The ending index of the range to search.</param>
    /// <param name="value">The character to locate in the array.</param>
    /// <returns>The zero-based index of the first occurrence of <paramref name="value"/> within the specified range of <paramref name="buf"/>, or -1 if not found.</returns>
    private static int IndexOf(char[] buf, int start, int end, char value)
    {
        for (var i = start; i < end; i++)
        {
            if (buf[i] == value)
            {
                return i;
            }
        }

        return -1;
    }

    /// <summary>
    /// Returns the offset after stripping a lowercase <c>"0x"</c> prefix from <c>buf[start..end]</c>, if present.
    /// </summary>
    /// <param name="buf">The character array containing the data to process.</param>
    /// <param name="start">The starting index of the range to check in the buffer.</param>
    /// <param name="end">The ending index of the range to check in the buffer.</param>
    /// <returns>
    /// The new starting index after removing the "0x" prefix, or the original starting index if no prefix is present.
    /// </returns>
    private static int StripHexPrefix(char[] buf, int start, int end)
    {
        if (end - start >= 2 && buf[start] == '0' && buf[start + 1] == 'x')
        {
            return start + 2;
        }

        return start;
    }

    /// <summary>
    /// Converts a hexadecimal character to its integer value.
    /// </summary>
    /// <param name="c">The character to convert. Must be a valid hexadecimal character ('0'-'9', 'A'-'F', or 'a'-'f').</param>
    /// <returns>
    /// The integer value of the hexadecimal character. Returns -1 if the input character is not a valid hexadecimal character.
    /// </returns>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static int GetHexValue(char c)
    {
        return c switch
        {
            >= '0' and <= '9' => c - '0',
            >= 'A' and <= 'F' => c - 'A' + 10,
            >= 'a' and <= 'f' => c - 'a' + 10,
            _ => -1
        };
    }

    /// <summary>
    /// Writes a prefix to the specified character array if the <paramref name="withPrefix"/> flag is <see langword="true"/>.
    /// The prefix is "0x". This method returns the updated position index after writing the prefix.
    /// </summary>
    /// <param name="dest">The destination character array where the prefix will be written.</param>
    /// <param name="pos">The starting position in the character array to write the prefix.</param>
    /// <param name="withPrefix">
    /// A flag indicating whether the prefix should be written. If <see langword="false"/>, no prefix is written, and the original position is returned.
    /// </param>
    /// <returns>The updated position in the character array after the prefix has been written.</returns>
    private static int WritePrefix(char[] dest, int pos, bool withPrefix)
    {
        if (!withPrefix)
        {
            return pos;
        }

        dest[pos++] = '0';
        dest[pos++] = 'x';

        return pos;
    }

    /// <summary>
    /// Writes the hexadecimal representation of a byte array to the specified destination character array.
    /// </summary>
    /// <param name="source">The source array of bytes whose hexadecimal representation is to be written.</param>
    /// <param name="dest">The destination character array to which the hexadecimal characters will be written.</param>
    /// <param name="destOffset">The starting index in the destination array where the hexadecimal characters will be written.</param>
    /// <param name="uppercase">Indicates whether the hexadecimal characters should be in uppercase. If <see langword="true"/>, uppercase characters are used; otherwise, lowercase characters are used. Default is <see langword="true"/>.</param>
    private static void WriteHexChars(PinnedPoolArray<byte> source, char[] dest, int destOffset, bool uppercase = true)
    {
        const string hexUpperAlphabet = "0123456789ABCDEF";
        const string hexLowerAlphabet = "0123456789abcdef";
        var hexAlphabet = uppercase ? hexUpperAlphabet : hexLowerAlphabet;
        for (int i = 0; i < source.Length; i++)
        {
            var byteValue = source.PoolArray[i];
            dest[destOffset + i * 2]     = hexAlphabet[byteValue >> 4];
            dest[destOffset + i * 2 + 1] = hexAlphabet[byteValue & 0xF];
        }
    }

#if DEBUG
    /// <summary>
    /// Converts the share into its hexadecimal string representation.
    /// </summary>
    /// <param name="uppercase">Determines whether the resulting hexadecimal string should use uppercase letters.</param>
    /// <returns>The hexadecimal string representation of the share.</returns>
    /// <remarks>
    /// <b>Security warning:</b> The <c>new string(...)</c> allocation copies share material onto the
    /// unpinned managed heap. The resulting <see cref="string"/> is immutable and cannot be securely
    /// cleared — its contents remain recoverable from process memory until a GC collection (and even then
    /// may persist in swap files or crash dumps). This method is gated by <c>#if DEBUG</c> precisely
    /// for this reason: it exists to support <see cref="ToString"/> and <see cref="DebuggerDisplayAttribute"/>
    /// during development. Never add a Release-build caller; use <see cref="ToCharArray()"/> instead,
    /// which keeps share material in pinned memory that is securely cleared on disposal.
    /// </remarks>
    private string FormatHex(bool uppercase)
    {
        using var chars = this.ToCharArray(uppercase, withPrefix: false);
        return new string(chars.PoolArray, 0, chars.Length);
    }
#endif
}
