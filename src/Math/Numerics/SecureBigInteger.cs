// ----------------------------------------------------------------------------
// <copyright file="SecureBigInteger.cs" company="Private">
// Copyright (c) 2025 All Rights Reserved
// </copyright>
// <author>Sebastian Walther</author>
// <date>12/06/2025 08:07:21 PM</date>
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

namespace SecretSharingDotNet.Math.Numerics;

using Cryptography.SecureArray;
using System;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.CompilerServices;
using System.Threading;


/// <summary>
/// Represents a secure arbitrary-precision integer with support for basic arithmetic operations.
/// The internal data is securely cleared from memory when the instance is disposed.
/// </summary>
/// <remarks>
/// <para>
/// <b>Threat model.</b> The "secure" qualifier covers a specific subset of side channels:
/// </para>
/// <para>
/// <b>Protected:</b>
/// </para>
/// <list type="bullet">
/// <item><description>
/// <b>Passive memory disclosure.</b> The canonical limb buffer is GC-pinned via
/// <see cref="PinnedPoolArray{T}"/> and wiped with a 3-pass overwrite plus
/// <c>CryptographicOperations.ZeroMemory</c> on dispose. Heap snapshots, swap files, and
/// reuse-after-free of the same physical pages cannot recover plaintext. The wipe runs on
/// both the explicit <see cref="Dispose()"/> path and the finalizer, with idempotent
/// short-circuit if both fire.
/// </description></item>
/// <item><description>
/// <b>Length-vs-content equality leak.</b> <see cref="Equals(SecureBigInteger)"/> pre-pads
/// both magnitudes to <c>max(this.limbs.Length, other.limbs.Length)</c> and runs the
/// XOR-OR-fold helper <c>FixedTimeLimbsEqual</c> across the full padded length on every
/// call — no early exit on the first differing limb, no length-mismatch fast path, no
/// TFM-conditional code path.
/// </description></item>
/// <item><description>
/// <b>Operand-value timing in core arithmetic.</b> <see cref="op_Addition"/>,
/// <see cref="op_Subtraction"/>, <see cref="op_Multiply"/>, <see cref="op_Division"/>,
/// <see cref="op_Modulus"/>, <see cref="Square"/>, and <see cref="MersenneModulo"/>
/// iterate a fixed number of limbs equal to the public
/// <c>max(left.LimbCount, right.LimbCount)</c> (or the public Mersenne exponent for
/// <see cref="MersenneModulo"/>). Per-limb work uses branchless carry/borrow formulas;
/// no zero-operand short-circuit, no magnitude-equality short-circuit, no
/// content-dependent loop bounds. The byte-decoding helper <c>TwosComplement</c> runs
/// its carry-add for the full input length unconditionally.
/// </description></item>
/// <item><description>
/// <b>RNG quality.</b> Caller responsibility — this type does not generate random data;
/// see <c>Cryptography.SecureRandom</c> for the project's RNG layer.
/// </description></item>
/// </list>
/// <para>
/// <b>Public-input dependence (treated as public, not secret):</b>
/// </para>
/// <list type="bullet">
/// <item><description>
/// <see cref="Pow(int)"/> is variable-time <i>on the exponent value</i> — iteration count
/// is <c>O(log₂(exponent))</c> with a per-iteration branch on the current bit. The base
/// instance is treated as secret and the per-iteration arithmetic on it goes through the
/// constant-time-on-bit-length <see cref="op_Multiply"/>. <b>Callers must not pass
/// secret-derived exponents through this method.</b>
/// </description></item>
/// <item><description>
/// <see cref="ByteCount"/>, <see cref="ToByteArray"/>, <see cref="ToHexadecimal"/>, and
/// <see cref="ToPinnedCharArray"/> derive their output size from the operand magnitude;
/// their runtime is therefore variable-time on the operand value. Hex/decimal parsing
/// throws variable-time on malformed input. All of these are documented public observables
/// — output size is necessarily revealed by the call's contract.
/// </description></item>
/// </list>
/// <para>
/// <b>Not protected (intentional gaps):</b>
/// </para>
/// <list type="bullet">
/// <item><description>
/// <b>Active co-located timing attackers.</b> Cross-VM cache attacks, browser
/// high-resolution timers, and network-RTT measurements against attacker-controlled
/// endpoints may still leak operand magnitudes through micro-architectural side channels
/// (cache-line patterns, branch predictor state, allocator behaviour) that pure managed
/// .NET cannot fully suppress. Consumers in those threat models should layer through a
/// constant-time crypto stack (libsodium-net, hardware-backed enclaves) rather than rely
/// on this type's naming alone.
/// </description></item>
/// <item><description>
/// <b>Concurrent mutating operations.</b> The arithmetic path-internal pattern of
/// <c>result.isNegative = …;</c> after construction is single-threaded. <see cref="Dispose()"/>
/// is the only operation guarded against concurrent invocation (via
/// <see cref="System.Threading.Interlocked.Exchange(ref int, int)"/>); concurrent reads
/// of the same instance are safe iff no thread is mutating, but parallel writes to the
/// same instance from multiple threads are not supported. Treat each
/// <see cref="SecureBigInteger"/> instance as owned by one thread at a time.
/// </description></item>
/// </list>
/// </remarks>
#if DEBUG
[DebuggerDisplay("{ToString(),nq}")]
#else
[DebuggerDisplay("*** Secured Value ***")]
#endif
public sealed class SecureBigInteger : IDisposable, IEquatable<SecureBigInteger>, IComparable<SecureBigInteger>
{
    /// <summary>
    /// The 64-bit-limb array representing the absolute value of the integer in
    /// little-endian order — <c>limbs[0]</c> is the least-significant limb.
    /// Canonical storage as of D9. The logical limb count is
    /// <c>limbs.Length</c>; trimmed to the highest non-zero limb except for
    /// the value zero, which is stored as a single zero limb
    /// (<c>limbs.Length == 1</c>, <c>limbs[0] == 0</c>).
    /// </summary>
    private PinnedPoolArray<ulong> limbs;

    /// <summary>
    /// Indicates whether the current instance represents a negative value.
    /// </summary>
    private bool isNegative;

    /// <summary>
    /// Indicates whether the current instance has been disposed.
    /// </summary>
    private int disposed;

    /// <summary>
    /// Initializes a new instance of the <see cref="SecureBigInteger"/> class with the value zero.
    /// </summary>
    public SecureBigInteger()
    {
        this.limbs = new PinnedPoolArray<ulong>(length: 1);
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="SecureBigInteger"/> class from an <see cref="int"/> value.
    /// </summary>
    /// <param name="value">The <see cref="int"/> value to initialize from.</param>
    public SecureBigInteger(int value) : this((long)value)
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="SecureBigInteger"/> class from a <see cref="long"/> value.
    /// </summary>
    /// <param name="value">The <see cref="long"/> value to initialize from.</param>
    public SecureBigInteger(long value)
    {
        this.limbs = new PinnedPoolArray<ulong>(length: 1);

        if (value == 0)
        {
            return;
        }

        this.isNegative = value < 0;
        // unchecked: -long.MinValue overflows back to long.MinValue, whose ulong
        // reinterpretation is 0x8000_0000_0000_0000 — exactly the magnitude we want.
        this.limbs[0] = unchecked((ulong)(this.isNegative ? -value : value));
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="SecureBigInteger"/> class from a <see cref="ulong"/> value.
    /// </summary>
    /// <param name="value">The <see cref="ulong"/> value to initialize from.</param>
    /// <remarks>
    /// Always non-negative. The full <see cref="ulong"/> range is supported, including
    /// values above <see cref="long.MaxValue"/> that would overflow the
    /// <see cref="SecureBigInteger(long)"/> ctor.
    /// </remarks>
    public SecureBigInteger(ulong value)
    {
        this.limbs = new PinnedPoolArray<ulong>(length: 1);
        this.limbs[0] = value;
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="SecureBigInteger"/> class by copying another instance.
    /// </summary>
    /// <param name="other">The <see cref="SecureBigInteger"/> instance to copy.</param>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="other"/> is <see langword="null"/>.</exception>
    public SecureBigInteger(SecureBigInteger other)
    {
        if (other is null)
        {
            throw new ArgumentNullException(nameof(other));
        }

        other.ThrowIfDisposed();
        this.limbs = new PinnedPoolArray<ulong>(length: other.limbs.Length);
        Array.Copy(other.limbs.PoolArray, this.limbs.PoolArray, other.limbs.Length);
        this.isNegative = other.isNegative;
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="SecureBigInteger"/> class from a byte array and a sign flag.
    /// </summary>
    /// <param name="data">The byte array representing the absolute value.</param>
    /// <param name="isNegative">Indicates whether the value is negative.</param>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="data"/> is <see langword="null"/>.</exception>
    public SecureBigInteger(byte[] data, bool isNegative) : this(data ?? throw new ArgumentNullException(nameof(data)),
        data.Length, isNegative)
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="SecureBigInteger"/> class from a byte array and a sign flag.
    /// </summary>
    /// <param name="data">The byte array representing the absolute value.</param>
    /// <param name="length">The length of the data to consider from the byte array. Must be in the range <c>[0, data.Length]</c>.</param>
    /// <param name="isNegative">Indicates whether the value is negative.</param>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="data"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentOutOfRangeException">Thrown if <paramref name="length"/> is negative or greater than <c>data.Length</c>.</exception>
    public SecureBigInteger(byte[] data, int length, bool isNegative)
    {
        if (data is null)
        {
            throw new ArgumentNullException(nameof(data));
        }

        if (length < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(length), string.Format(ErrorMessages.ValueLowerThanX, 0));
        }

        if (length > data.Length)
        {
            throw new ArgumentOutOfRangeException(nameof(length), string.Format(ErrorMessages.CountExceedsArrayLength, length, data.Length));
        }

        int allocLimbs = length <= 0 ? 1 : (length + 7) / 8;
        this.limbs = new PinnedPoolArray<ulong>(length: allocLimbs);

        if (length > 0)
        {
            BytesToLimbs(data, length, this.limbs);
        }

        this.isNegative = isNegative;
        this.TrimLeadingZerosInPlace();
        if (this.IsZeroInternal())
        {
            this.isNegative = false;
        }
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="SecureBigInteger"/> class from a byte array, which contains
    /// the serialized representation.
    /// </summary>
    /// <param name="data">The byte array containing the serialized representation.</param>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="data"/> is <see langword="null"/>.</exception>
    public SecureBigInteger(byte[] data) : this(data ?? throw new ArgumentNullException(nameof(data)), data.Length)
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="SecureBigInteger"/> class from a byte array, which contains
    /// the serialized representation.
    /// </summary>
    /// <param name="data">The byte array containing the serialized representation.</param>
    /// <param name="length">The length of the byte array containing the serialized representation. Must be in the range <c>[0, data.Length]</c>.</param>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="data"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentOutOfRangeException">Thrown if <paramref name="length"/> is negative or greater than <c>data.Length</c>.</exception>
    public SecureBigInteger(byte[] data, int length)
    {
        if (data is null)
        {
            throw new ArgumentNullException(nameof(data));
        }

        if (length < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(length), string.Format(ErrorMessages.ValueLowerThanX, 0));
        }

        if (length > data.Length)
        {
            throw new ArgumentOutOfRangeException(nameof(length), string.Format(ErrorMessages.CountExceedsArrayLength, length, data.Length));
        }

        if (length == 0)
        {
            this.limbs = new PinnedPoolArray<ulong>(length: 1);
            return;
        }

        var isNegativeRepresentation = IsNegativeRepresentation(data, length);
        this.isNegative = isNegativeRepresentation;

        // The two's-complement decoding stays at byte level — its semantics are
        // defined on the byte representation. The result is then converted to
        // the canonical limb storage in one shot.
        int allocLimbs = (length + 7) / 8;
        this.limbs = new PinnedPoolArray<ulong>(length: allocLimbs);
        if (isNegativeRepresentation)
        {
            using var normalizedData = TwosComplement(data, length);
            BytesToLimbs(normalizedData.PoolArray, length, this.limbs);
        }
        else
        {
            BytesToLimbs(data, length, this.limbs);
        }

        this.TrimLeadingZerosInPlace();
        if (this.IsZeroInternal())
        {
            this.isNegative = false;
        }
    }

    /// <summary>
    /// Finalizes an instance of the <see cref="SecureBigInteger"/> class.
    /// </summary>
    ~SecureBigInteger()
    {
        this.Dispose(false);
    }

    /// <summary>
    /// The character offset used to convert between numeric digits and their character representations.
    /// Aligns with ASCII encoding, where the character '0' has the numeric code 48. Used internally
    /// for parsing and formatting numeric values.
    /// </summary>
    private const char DigitOffset = '0';

    /// <summary>
    /// Gets the number of bytes used to represent the magnitude of this <see cref="SecureBigInteger"/>.
    /// </summary>
    /// <remarks>
    /// Derived from the canonical limb storage: <c>(limbs.Length - 1) * 8 + bytesInLimb(highLimb)</c>,
    /// or 1 if the value is zero (preserving the historical convention from byte storage).
    /// Variable-time on the value of the highest limb — acceptable because <c>ByteCount</c>
    /// is documented as a public observable in the threat model.
    /// </remarks>
    public int ByteCount
    {
        get
        {
            this.ThrowIfDisposed();
            ulong highLimb = this.limbs[this.limbs.Length - 1];
            if (highLimb == 0)
            {
                return 1;
            }

            return ((this.limbs.Length - 1) * 8) + BytesInLimb(highLimb);
        }
    }

    /// <summary>
    /// Counts the number of significant bytes in <paramref name="limb"/>.
    /// Returns 0 when <paramref name="limb"/> is zero. Variable-time on the
    /// limb value — only used to derive public observables (<see cref="ByteCount"/>).
    /// </summary>
    private static int BytesInLimb(ulong limb)
    {
        int count = 0;
        while (limb != 0)
        {
            count++;
            limb >>= 8;
        }

        return count;
    }

    /// <summary>
    /// Gets a value indicating whether the current <see cref="SecureBigInteger"/> instance represents the value zero.
    /// </summary>
    public bool IsZero
    {
        get
        {
            this.ThrowIfDisposed();
            return this.IsZeroInternal();
        }
    }

    /// <summary>
    /// Gets a value indicating whether the current <see cref="SecureBigInteger"/> instance represents the value one.
    /// </summary>
    /// <remarks>
    /// Constant-time on the magnitude limbs: the sign is observable per the threat
    /// model and may legitimately short-circuit to <see langword="false"/>; the
    /// magnitude check XOR-folds the expected pattern (low limb = 1, all higher
    /// limbs = 0) into a single ulong that is compared against zero. The limb-level
    /// limb count <c>limbs.Length</c> is a public observable and may bound the loop.
    /// </remarks>
    public bool IsOne
    {
        get
        {
            this.ThrowIfDisposed();
            if (this.isNegative)
            {
                return false;
            }

            ulong acc = this.limbs[0] ^ 1UL;
            for (int i = 1; i < this.limbs.Length; i++)
            {
                acc |= this.limbs[i];
            }

            return acc == 0;
        }
    }

    /// <summary>
    /// Gets a value indicating whether the current <see cref="SecureBigInteger"/> instance represents an even number.
    /// </summary>
    /// <remarks>
    /// Constant-time bit-test on the magnitude's least-significant limb. The sign flag is
    /// irrelevant: the parity of <c>-x</c> matches the parity of <c>x</c>, and the magnitude
    /// stored here is always non-negative regardless of <c>isNegative</c>.
    /// </remarks>
    public bool IsEven
    {
        get
        {
            this.ThrowIfDisposed();
            return (this.limbs[0] & 1UL) == 0;
        }
    }

    /// <summary>
    /// Gets the sign of the current <see cref="SecureBigInteger"/> instance.
    /// </summary>
    /// <remarks>
    /// Constant-time on the magnitude bytes: <see cref="IsZeroInternal"/> performs
    /// a fixed-iteration OR-fold and returns a branchless zero-test. The polarity
    /// branch on <see cref="isNegative"/> is acceptable because the sign field is
    /// a public observable per the threat model.
    /// </remarks>
    public int Sign
    {
        get
        {
            this.ThrowIfDisposed();
            return this.IsZeroInternal()
                ? 0
                : (this.isNegative ? -1 : 1);
        }
    }

    /// <summary>
    /// Adds two <see cref="SecureBigInteger"/> instances.
    /// </summary>
    /// <param name="left">1st summand</param>
    /// <param name="right">2nd summand</param>
    /// <returns>sum</returns>
    /// <exception cref="ArgumentNullException"><paramref name="left"/> or <paramref name="right"/> is null.</exception>
    public static SecureBigInteger Add(SecureBigInteger left, SecureBigInteger right)
    {
        if (left is null)
        {
            throw new ArgumentNullException(nameof(left));
        }

        if (right is null)
        {
            throw new ArgumentNullException(nameof(right));
        }

        left.ThrowIfDisposed();
        right.ThrowIfDisposed();

        SecureBigInteger result;
        if (left.isNegative == right.isNegative)
        {
            result = AddUnsigned(left, right);
            result.isNegative = left.isNegative;
        }
        else
        {
            // Mixed sign: |a + b| = ||a| - |b||, sign follows the operand with greater magnitude.
            // The previous `case 0` early-return allocated a fresh zero, taking a structurally
            // shorter path than the > 0 / < 0 cases; that allowed timing to distinguish
            // |left| == |right| from |left| ≠ |right|. Merging case 0 into the >= 0 branch
            // removes that leak — both paths now run a SubtractUnsigned with the same iteration
            // count. The remaining >= 0 vs < 0 branch reveals only what the result's own sign
            // already publicly reveals (which operand had greater magnitude).
            var comparison = CompareUnsigned(left, right);
            if (comparison >= 0)
            {
                result = SubtractUnsigned(left, right);
                result.isNegative = left.isNegative;
            }
            else
            {
                result = SubtractUnsigned(right, left);
                result.isNegative = right.isNegative;
            }
        }

        // Normalize: a magnitude-0 result must have isNegative=false (canonical zero).
        // Without this guard, e.g. (+5) + (-5) would hit the >= 0 branch with left.isNegative=false,
        // but (-5) + (+5) would hit the < 0 branch with right.isNegative=false — still safe — yet
        // mixed-magnitude same-sign Subtract paths can land on -0 and rely on this normalization.
        if (result.IsZeroInternal())
        {
            result.isNegative = false;
        }

        return result;
    }

    /// <summary>
    /// Subtracts two <see cref="SecureBigInteger"/> instances.
    /// </summary>
    /// <param name="minuend">minuend</param>
    /// <param name="subtrahend">subtrahend</param>
    /// <returns>difference</returns>
    /// <exception cref="ArgumentNullException"><paramref name="minuend"/> or <paramref name="subtrahend"/> is null.</exception>
    [SuppressMessage("SonarQube", "S2234",
        Justification = "The same-sign branch intentionally swaps minuend/subtrahend when " +
                        "|minuend| < |subtrahend| to satisfy SubtractUnsigned's |minuend| >= |subtrahend| " +
                        "precondition. The swapped argument order is intended, not a copy-paste bug.")]
    public static SecureBigInteger Subtract(SecureBigInteger minuend, SecureBigInteger subtrahend)
    {
        if (minuend is null)
        {
            throw new ArgumentNullException(nameof(minuend));
        }

        if (subtrahend is null)
        {
            throw new ArgumentNullException(nameof(subtrahend));
        }

        minuend.ThrowIfDisposed();
        subtrahend.ThrowIfDisposed();

        SecureBigInteger result;
        if (minuend.isNegative != subtrahend.isNegative)
        {
            // a - (-b) = a + b   |   (-a) - b = -(a + b)
            result = AddUnsigned(minuend, subtrahend);
            result.isNegative = minuend.isNegative;
        }
        else
        {
            // Same sign: the magnitudes determine direction; the result inherits the
            // minuend's sign when |minuend| >= |subtrahend|, and the inverted sign otherwise.
            // The previous `case 0` early-return allocated a fresh zero, taking a structurally
            // shorter path than the > 0 / < 0 cases; that allowed timing to distinguish
            // |minuend| == |subtrahend| from |minuend| ≠ |subtrahend|. Merging case 0 into
            // the >= 0 branch closes that leak.
            var comparison = CompareUnsigned(minuend, subtrahend);
            if (comparison >= 0)
            {
                result = SubtractUnsigned(minuend, subtrahend);
                result.isNegative = minuend.isNegative;
            }
            else
            {
                result = SubtractUnsigned(subtrahend, minuend);
                result.isNegative = !minuend.isNegative;
            }
        }

        // Normalize: e.g. (+5) - (+5) lands on the same-sign >= 0 branch with isNegative=false,
        // but (-5) - (-5) on the same branch with isNegative=true on a magnitude-0 result —
        // i.e. -0. Mixed-sign Subtract on equal magnitudes also produces -0 when minuend is
        // negative. Guard ensures canonical-zero invariant.
        if (result.IsZeroInternal())
        {
            result.isNegative = false;
        }

        return result;
    }

    /// <summary>
    /// Multiplies two <see cref="SecureBigInteger"/> instances.
    /// </summary>
    /// <param name="multiplicand">multiplicand</param>
    /// <param name="multiplier">multiplier</param>
    /// <returns>product</returns>
    /// <exception cref="ArgumentNullException"><paramref name="multiplicand"/> or
    /// <paramref name="multiplier"/> is null.</exception>
    public static SecureBigInteger Multiply(SecureBigInteger multiplicand, SecureBigInteger multiplier)
    {
        if (multiplicand is null)
        {
            throw new ArgumentNullException(nameof(multiplicand));
        }

        if (multiplier is null)
        {
            throw new ArgumentNullException(nameof(multiplier));
        }

        multiplicand.ThrowIfDisposed();
        multiplier.ThrowIfDisposed();

        // No zero-operand short-circuit: branching on `IsZeroInternal()` would leak
        // 1 bit of operand-content (a public-API timing distinction between a zero
        // operand and a non-zero one). MultiplyUnsigned on a zero operand yields a
        // magnitude-0 result naturally — we simply normalize the sign at the end.
        var result = MultiplyUnsigned(multiplicand, multiplier);
        if (!result.IsZeroInternal())
        {
            result.isNegative = multiplicand.isNegative != multiplier.isNegative;
        }

        return result;
    }

    /// <summary>
    /// Divides two <see cref="SecureBigInteger"/> instances.
    /// </summary>
    /// <param name="dividend">dividend</param>
    /// <param name="divisor">divisor</param>
    /// <returns>quotient</returns>
    /// <exception cref="ArgumentNullException"><paramref name="dividend"/> or
    /// <paramref name="divisor"/> is null.</exception>
    /// <exception cref="DivideByZeroException">Thrown if <paramref name="divisor"/> is zero.</exception>
    public static SecureBigInteger Divide(SecureBigInteger dividend, SecureBigInteger divisor)
    {
        if (dividend is null)
        {
            throw new ArgumentNullException(nameof(dividend));
        }

        if (divisor is null)
        {
            throw new ArgumentNullException(nameof(divisor));
        }

        dividend.ThrowIfDisposed();
        divisor.ThrowIfDisposed();

        if (divisor.IsZeroInternal())
        {
            // The DivideByZeroException branch is structurally required by the public
            // contract — it cannot be hidden, and its predicate (divisor.IsZeroInternal)
            // is the same operand-content read that any caller would do anyway.
            throw new DivideByZeroException(ErrorMessages.DivisionByZero);
        }

        // No dividend-zero short-circuit: branching on `dividend.IsZeroInternal()` would
        // leak 1 bit of operand-content. DivideUnsigned with a zero dividend produces a
        // magnitude-0 quotient and remainder naturally; the post-call sign normalization
        // (only assigning isNegative when result is non-zero) keeps the canonical-zero
        // invariant intact.
        // DivideUnsigned allocates BOTH the quotient (return) and the remainder
        // (out-param) as fresh SecureBigInteger instances. The remainder is not
        // needed here, but must be disposed explicitly — discarding it via
        // `out _` would leak a pinned-pool slot (the finalizer on
        // SecureBigInteger only sets the disposed flag and does not release
        // managed resources, see Dispose(bool)) and delay the secret-data wipe
        // until pool-level finalization runs.
        var quotient = DivideUnsigned(dividend, divisor, out var remainder);
        remainder.Dispose();
        // Only assign the sign if the quotient is non-zero. Otherwise we would
        // create a "negative zero" — a magnitude-0 result with isNegative=true —
        // which violates the class invariant that zero is canonically positive
        // and would make Equals(zeroResult, +0) return false.
        if (!quotient.IsZeroInternal())
        {
            quotient.isNegative = dividend.isNegative != divisor.isNegative;
        }

        return quotient;
    }

    /// <summary>
    /// Computes the remainder of the division of two <see cref="SecureBigInteger"/> instances.
    /// </summary>
    /// <param name="dividend">dividend</param>
    /// <param name="divisor">divisor</param>
    /// <returns>remainder</returns>
    /// <exception cref="ArgumentNullException"><paramref name="dividend"/> or
    /// <paramref name="divisor"/> is null.</exception>
    /// <exception cref="DivideByZeroException">Thrown if <paramref name="divisor"/> is zero.</exception>
    public static SecureBigInteger Remainder(SecureBigInteger dividend, SecureBigInteger divisor)
    {
        if (dividend is null)
        {
            throw new ArgumentNullException(nameof(dividend));
        }

        if (divisor is null)
        {
            throw new ArgumentNullException(nameof(divisor));
        }

        dividend.ThrowIfDisposed();
        divisor.ThrowIfDisposed();

        if (divisor.IsZeroInternal())
        {
            // See Divide for the contractual reason this branch is necessary.
            throw new DivideByZeroException(ErrorMessages.DivisionByZero);
        }

        // No dividend-zero short-circuit — see Divide for the rationale. DivideUnsigned
        // produces a magnitude-0 remainder naturally when the dividend is zero.
        // Symmetric to Divide above: DivideUnsigned allocates both outputs, but
        // here the quotient is the unused half. Dispose it via `using` so that
        // its pinned-pool slot is released and its plaintext bytes wiped on the
        // success path; on a throw between the call and the using-scope-exit
        // (none of the operations in this short tail can throw realistically),
        // the using ensures cleanup as well.
        using var quotient = DivideUnsigned(dividend, divisor, out var remainder);
        // Only assign the sign if the remainder is non-zero — otherwise an exact
        // division (e.g. -10 % 5 = 0) would produce a "negative zero" with
        // isNegative=true on a magnitude-0 result, breaking the canonical-zero
        // invariant and Equals against +0.
        if (!remainder.IsZeroInternal())
        {
            remainder.isNegative = dividend.isNegative;
        }

        return remainder;
    }

    /// <summary>
    /// Reduces a non-negative value modulo a Mersenne prime <c>M_p = 2^p - 1</c>
    /// using the classical fold-and-add identity: since
    /// <c>2^p ≡ 1 (mod M_p)</c>, the value <c>(high * 2^p + low)</c> reduces to
    /// <c>(high + low) mod M_p</c> in a single step. Two folds suffice to
    /// shrink any value below <c>2^(2p)</c> down to <c>≤ 2^p</c>; one final
    /// conditional subtract canonicalises the result into <c>[0, M_p - 1]</c>.
    /// </summary>
    /// <param name="exponent">The Mersenne exponent <c>p</c>. Must be positive.
    /// Treated as public information per the threat model: the iteration count
    /// derives from <paramref name="exponent"/> and the operand's limb count,
    /// both observable.</param>
    /// <returns>A new non-negative <see cref="SecureBigInteger"/> representing
    /// <c>this mod (2^exponent - 1)</c>.</returns>
    /// <exception cref="ArgumentOutOfRangeException">
    /// <paramref name="exponent"/> is not positive.
    /// </exception>
    /// <exception cref="ArgumentException">The instance is negative.</exception>
    /// <remarks>
    /// Significantly faster than the generic <see cref="Remainder"/> when the
    /// modulus is a Mersenne prime: each fold pass is linear in the operand's
    /// limb count and avoids the bit-by-bit long division of
    /// <see cref="DivideUnsigned"/>. The Shamir hot path's <c>% prime</c> is
    /// always Mersenne, so this is the perf win planned in D7. Constant-time
    /// on operand content; the iteration count is fixed per call from the
    /// public <paramref name="exponent"/> and <see cref="LimbCount"/>.
    /// </remarks>
    internal SecureBigInteger MersenneModulo(int exponent)
    {
        this.ThrowIfDisposed();
        if (exponent <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(exponent), exponent, string.Format(ErrorMessages.ValueLowerThanX, 1));
        }

        // Negative operands produce mathematical-modulo semantics: the post-fold
        // canonicalisation block at the end of this method transforms |value|
        // mod M_p into M_p - (|value| mod M_p) when the input was negative and
        // the result is non-zero. The sign branch itself is allowed (sign is
        // observable per the threat model); the per-limb work that follows
        // stays branchless on operand content.

        int p = exponent;
        int outLimbCount = (p + 63) / 64;
        int pLimbIdx = (p - 1) / 64;
        int pBitInLimb = (p - 1) % 64;
        ulong pLimbMask = pBitInLimb == 63 ? ulong.MaxValue : (1UL << (pBitInLimb + 1)) - 1;

        int srcLimbCount = this.limbs.Length;

        int workLimbCount = srcLimbCount >= outLimbCount + 1 ? srcLimbCount : outLimbCount + 1;
        using var work = new PinnedPoolArray<ulong>(length: workLimbCount);
        using var scratch = new PinnedPoolArray<ulong>(length: workLimbCount);

        for (int i = 0; i < srcLimbCount; i++)
        {
            work[i] = this.limbs[i];
        }

        // Each fold pass shifts bits-above-p down by p, halving the bit-length
        // above p. iterations = (srcBits / p) + 2 covers the worst case
        // (post-multiply 2p-bit input ⇒ 4 iterations, well over the 2 needed
        // to converge), with the +2 safety margin keeping the count public.
        int iterations = (srcLimbCount * 64) / p + 2;

        for (int iter = 0; iter < iterations; iter++)
        {
            ShiftRightByPLimbs(work, workLimbCount, p, scratch, workLimbCount);

            // Mask `work` to its low p bits — keeps only bits 0..p-1, zeros
            // every higher position. The high limb is masked with pLimbMask;
            // limbs above pLimbIdx are zeroed wholesale.
            if (pLimbIdx < workLimbCount)
            {
                work[pLimbIdx] &= pLimbMask;
            }

            for (int i = pLimbIdx + 1; i < workLimbCount; i++)
            {
                work[i] = 0;
            }

            // work += scratch  (mask = all-ones reuses AddMaskedInPlace as a
            // plain limb-add).
            AddMaskedInPlace(work, workLimbCount, scratch, workLimbCount, ulong.MaxValue);
        }

        // After folding, work ≤ 2^p, contained in `outLimbCount` limbs (the
        // top fold iteration drives bit p down via a final `+ 1`). Build M_p
        // and conditionally subtract: if work ≥ M_p, the trial subtract
        // succeeds; otherwise the borrow flag drives an undo via mask-add.
        using var mersennePrime = new PinnedPoolArray<ulong>(length: outLimbCount);
        for (int i = 0; i < outLimbCount - 1; i++)
        {
            mersennePrime[i] = ulong.MaxValue;
        }

        mersennePrime[outLimbCount - 1] = pLimbMask;

        ulong borrow = SubtractInPlace(work, outLimbCount, mersennePrime, outLimbCount);
        ulong undoMask = 0UL - borrow;
        AddMaskedInPlace(work, outLimbCount, mersennePrime, outLimbCount, undoMask);

        // Mathematical-modulo correction for negative input: if the operand
        // was negative AND the canonical magnitude result is non-zero, the
        // representative in [0, M_p - 1] is M_p - work. For zero result the
        // mathematical modulo of any negative is also zero, so leave work
        // unchanged. The "result is non-zero" check is a fixed-iter OR-fold
        // followed by a branchless 0/all-ones mask.
        if (this.isNegative)
        {
            ulong nonZeroAcc = 0;
            for (int i = 0; i < outLimbCount; i++)
            {
                nonZeroAcc |= work[i];
            }

            // selectMask = all-ones if work != 0, 0 if work == 0.
            ulong selectMask = 0UL - ((nonZeroAcc | (0UL - nonZeroAcc)) >> 63);

            using var negated = new PinnedPoolArray<ulong>(length: outLimbCount);
            for (int i = 0; i < outLimbCount; i++)
            {
                negated[i] = mersennePrime[i];
            }

            SubtractInPlace(negated, outLimbCount, work, outLimbCount);

            for (int i = 0; i < outLimbCount; i++)
            {
                work[i] = (work[i] & ~selectMask) | (negated[i] & selectMask);
            }
        }

        return new SecureBigInteger(work, outLimbCount, isNegative: false);
    }

    /// <summary>
    /// Right-shifts a pinned ulong-limb buffer by <paramref name="shiftBits"/>
    /// bits into a separate destination buffer. Used by
    /// <see cref="MersenneModulo"/> to extract the high <c>(N - p)</c> bits
    /// of the working value into the fold accumulator.
    /// </summary>
    /// <remarks>
    /// CT-helper. The <c>shiftBitsInLimb == 0</c> branch is on the public
    /// <paramref name="shiftBits"/> exponent (constant per call), not on
    /// operand data, so the per-call timing is data-independent. Out-of-range
    /// source reads return zero — required because the destination may walk
    /// past <c>sourceCount</c> when <c>workLimbCount > srcLimbCount</c>.
    /// </remarks>
    [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
    private static void ShiftRightByPLimbs(
        PinnedPoolArray<ulong> source, int sourceCount,
        int shiftBits,
        PinnedPoolArray<ulong> destination, int destinationCount)
    {
        int shiftLimbs = shiftBits / 64;
        int shiftBitsInLimb = shiftBits % 64;

        if (shiftBitsInLimb == 0)
        {
            for (int i = 0; i < destinationCount; i++)
            {
                int srcIdx = i + shiftLimbs;
                destination[i] = srcIdx < sourceCount ? source[srcIdx] : 0UL;
            }
        }
        else
        {
            int invBits = 64 - shiftBitsInLimb;
            for (int i = 0; i < destinationCount; i++)
            {
                int srcIdx = i + shiftLimbs;
                ulong lo = srcIdx < sourceCount ? source[srcIdx] : 0UL;
                ulong hi = srcIdx + 1 < sourceCount ? source[srcIdx + 1] : 0UL;
                destination[i] = (lo >> shiftBitsInLimb) | (hi << invBits);
            }
        }
    }

    /// <summary>
    /// Computes the square of the current <see cref="SecureBigInteger"/> instance.
    /// </summary>
    /// <returns>A new <see cref="SecureBigInteger"/> representing <c>this * this</c>.</returns>
    public SecureBigInteger Square()
    {
        this.ThrowIfDisposed();
        return Multiply(this, this);
    }

    /// <summary>
    /// Computes the absolute value of the current <see cref="SecureBigInteger"/> instance.
    /// </summary>
    /// <returns>A new non-negative <see cref="SecureBigInteger"/> with the same magnitude as
    /// the current instance.</returns>
    public SecureBigInteger Abs()
    {
        this.ThrowIfDisposed();
        return new SecureBigInteger(this.limbs, this.limbs.Length, isNegative: false);
    }

    /// <summary>
    /// Computes the negation of the current <see cref="SecureBigInteger"/> instance.
    /// </summary>
    /// <returns>Negated value.</returns>
    /// <remarks>
    /// Constant-time on the magnitude: copies all limbs unconditionally and flips the
    /// sign flag. The limbs constructor canonicalises a zero magnitude paired with the
    /// negative flag back to non-negative zero, so <c>Negate(0)</c> still returns zero
    /// without any explicit zero check.
    /// </remarks>
    public SecureBigInteger Negate()
    {
        this.ThrowIfDisposed();
        return new SecureBigInteger(this.limbs, this.limbs.Length, !this.isNegative);
    }

    /// <summary>
    /// Computes the power of the current <see cref="SecureBigInteger"/> instance raised to the specified exponent.
    /// </summary>
    /// <param name="exponent">
    /// The exponent to raise the current instance to. Must be non-negative.
    /// <para>
    /// <b>Constant-time contract:</b> <paramref name="exponent"/> is treated as <i>public</i> —
    /// its value (and therefore the iteration count <c>O(log₂(exponent))</c>) may influence
    /// runtime. Callers must not pass secret-derived exponents through this method. The base
    /// instance, by contrast, is treated as secret and the per-iteration arithmetic does not
    /// branch on its bits.
    /// </para>
    /// </param>
    /// <returns>A new <see cref="SecureBigInteger"/> representing <c>this^exponent</c>.</returns>
    /// <exception cref="ArgumentException">Thrown if <paramref name="exponent"/> is negative.</exception>
    public SecureBigInteger Pow(int exponent)
    {
        this.ThrowIfDisposed();

        switch (exponent)
        {
            case < 0:
                throw new ArgumentException(ErrorMessages.ExponentMustBeNonNegative, nameof(exponent));
            case 0:
                return new SecureBigInteger(1);
            case 1:
                return new SecureBigInteger(this);
        }

        var result = new SecureBigInteger(1);
        var baseValue = new SecureBigInteger(this);
        var exp = exponent;

        try
        {
            while (exp > 0)
            {
                if ((exp & 1) == 1)
                {
                    var temp = Multiply(result, baseValue);
                    result.Dispose();
                    result = temp;
                }

                exp >>= 1;

                if (exp > 0)
                {
                    var temp = Multiply(baseValue, baseValue);
                    baseValue.Dispose();
                    baseValue = temp;
                }
            }

            return result;
        }
        catch
        {
            result.Dispose();
            throw;
        }
        finally
        {
            baseValue.Dispose();
        }
    }

    /// <summary>
    /// Converts the current <see cref="SecureBigInteger"/> instance to a byte array representation.
    /// </summary>
    /// <returns>
    /// A byte array containing the serialized representation of the current instance,
    /// including its sign and data.
    /// </returns>
    public PinnedPoolArray<byte> ToByteArray()
    {
        this.ThrowIfDisposed();

        // limbs.Length is trimmed to the highest non-zero limb (or 1 for zero by
        // convention), so ByteCount derives from the high limb's BytesInLimb plus
        // the lower limbs' full 8-byte width.
        int actualByteLength;
        ulong highLimb = this.limbs[this.limbs.Length - 1];
        if (highLimb == 0)
        {
            // Zero — single zero byte (preserves the historical convention).
            actualByteLength = 1;
        }
        else
        {
            actualByteLength = ((this.limbs.Length - 1) * 8) + BytesInLimb(highLimb);
        }

        if (this.isNegative)
        {
            using var rawBytes = new PinnedPoolArray<byte>(length: actualByteLength);
            LimbsToBytes(this.limbs, rawBytes);
            return TwosComplement(rawBytes.PoolArray, actualByteLength);
        }

        // Pad with one trailing zero byte if the magnitude's high bit is set,
        // so the unsigned interpretation survives a round-trip through
        // sign-aware decoders (matching System.Numerics.BigInteger semantics).
        bool needsPadding = highLimb != 0
            && ((highLimb >> (((BytesInLimb(highLimb) - 1) * 8) + 7)) & 1UL) != 0;
        int resultLen = needsPadding ? actualByteLength + 1 : actualByteLength;
        var result = new PinnedPoolArray<byte>(length: resultLen);
        // LimbsToBytes is output-driven on bytesOut.Length — temporarily shrink
        // result.Length so only the magnitude bytes are written; the optional
        // trailing pad byte stays zero from the ctor's buffer initialisation.
        result.Length = actualByteLength;
        LimbsToBytes(this.limbs, result);
        result.Length = resultLen;
        return result;
    }

    #region Limb conversion helpers

    // Limb storage is canonical as of D9. The helpers below convert to/from
    // the byte representation when callers (serialisation, two's-complement
    // ctor) need a byte-oriented view.
    //
    // The byte-to-limb assembly is explicit (not MemoryMarshal.Cast), so the
    // representation is host-endian-independent: limb[i] stores the byte at
    // magnitude offset (i*8 + j) in bit position (j*8), regardless of CPU
    // endianness.

    /// <summary>
    /// Returns the magnitude of this instance as a freshly allocated sequence of
    /// 64-bit limbs in little-endian order: <c>limb[0]</c> holds magnitude bytes
    /// 0..7, <c>limb[1]</c> holds bytes 8..15, etc. The sign bit is not included;
    /// query <see cref="Sign"/> separately.
    /// </summary>
    /// <returns>
    /// A new <see cref="PinnedPoolArray{T}"/> of <see cref="ulong"/> with
    /// <c>Length == <see cref="LimbCount"/></c>. Caller takes ownership and
    /// must dispose to wipe the buffer.
    /// </returns>
    /// <remarks>
    /// Direct copy from the canonical limb storage as of D9 — no byte-to-limb
    /// conversion any more.
    /// </remarks>
    internal PinnedPoolArray<ulong> ToLimbs()
    {
        this.ThrowIfDisposed();
        int count = this.limbs.Length;
        var copy = new PinnedPoolArray<ulong>(length: count);
        Array.Copy(this.limbs.PoolArray, copy.PoolArray, count);
        return copy;
    }

    /// <summary>
    /// Number of 64-bit limbs in the canonical limb storage of this instance.
    /// Always at least 1.
    /// </summary>
    internal int LimbCount
    {
        get
        {
            this.ThrowIfDisposed();
            return this.limbs.Length;
        }
    }

    /// <summary>
    /// Initializes a new instance from a magnitude expressed as 64-bit limbs
    /// (little-endian) plus an explicit sign flag.
    /// </summary>
    /// <param name="limbs">Limbs representing the magnitude.</param>
    /// <param name="limbCount">
    /// Number of valid limbs in <paramref name="limbs"/>; must be in
    /// <c>[1, limbs.Length]</c>.
    /// </param>
    /// <param name="isNegative">Sign of the value.</param>
    /// <exception cref="ArgumentNullException">
    /// <paramref name="limbs"/> is <see langword="null"/>.
    /// </exception>
    /// <exception cref="ArgumentOutOfRangeException">
    /// <paramref name="limbCount"/> is less than 1 or greater than
    /// <c>limbs.Length</c>.
    /// </exception>
    /// <remarks>
    /// As of D9 limbs are the canonical storage — this constructor copies the
    /// caller-supplied limbs directly into the field and trims to the highest
    /// non-zero limb. Caller retains ownership of <paramref name="limbs"/>.
    /// </remarks>
    internal SecureBigInteger(PinnedPoolArray<ulong> limbs, int limbCount, bool isNegative)
    {
        if (limbs is null)
        {
            throw new ArgumentNullException(nameof(limbs));
        }

        if (limbCount < 1)
        {
            throw new ArgumentOutOfRangeException(nameof(limbCount), string.Format(ErrorMessages.ValueLowerThanX, 1));
        }

        if (limbCount > limbs.Length)
        {
            throw new ArgumentOutOfRangeException(nameof(limbCount), string.Format(ErrorMessages.CountExceedsArrayLength, limbCount, limbs.Length));
        }

        this.limbs = new PinnedPoolArray<ulong>(length: limbCount);
        Array.Copy(limbs.PoolArray, this.limbs.PoolArray, limbCount);

        this.isNegative = isNegative;
        this.TrimLeadingZerosInPlace();
        if (this.IsZeroInternal())
        {
            this.isNegative = false;
        }
    }

    private static void BytesToLimbs(byte[] bytes, int byteCount, PinnedPoolArray<ulong> limbsOut)
    {
        int limbsLen = limbsOut.Length;
        for (int i = 0; i < limbsLen; i++)
        {
            ulong limb = 0;
            int offset = i * 8;
            for (int j = 0; j < 8; j++)
            {
                int idx = offset + j;
                if (idx >= byteCount)
                {
                    break;
                }

                limb |= ((ulong)bytes[idx]) << (j * 8);
            }

            limbsOut[i] = limb;
        }
    }

    /// <summary>
    /// Writes the magnitude in <paramref name="limbs"/> as little-endian bytes
    /// into <paramref name="bytesOut"/>. The output length is governed by
    /// <c>bytesOut.Length</c> — only that many bytes are written, even if
    /// <paramref name="limbs"/> contains higher-order data.
    /// </summary>
    /// <remarks>
    /// Output-driven loop: iterates exactly <c>bytesOut.Length</c> times with
    /// a straight-line per-iteration body (shift + mask + write). No inner
    /// branch on operand content. Caller precondition:
    /// <c>bytesOut.Length &lt;= limbs.Length * 8</c>.
    /// </remarks>
    private static void LimbsToBytes(PinnedPoolArray<ulong> limbs, PinnedPoolArray<byte> bytesOut)
    {
        int byteCount = bytesOut.Length;
        for (int byteIdx = 0; byteIdx < byteCount; byteIdx++)
        {
            int limbIdx = byteIdx >> 3;
            int byteInLimb = byteIdx & 7;
            bytesOut[byteIdx] = (byte)(limbs[limbIdx] >> (byteInLimb * 8));
        }
    }

    #endregion

    /// <summary>
    /// Determines whether the given little-endian byte array represents a negative
    /// number in two's-complement form.
    /// </summary>
    /// <param name="data">The little-endian byte array to evaluate.</param>
    /// <param name="length">The number of bytes from <paramref name="data"/> that make up the value.</param>
    /// <returns>
    /// <see langword="true"/> if the high bit of the most-significant byte
    /// (<c>data[length - 1]</c>) is set; otherwise, <see langword="false"/>.
    /// </returns>
    /// <remarks>
    /// The caller-supplied <paramref name="length"/> is authoritative — trailing high-order
    /// zero bytes must <b>not</b> be trimmed before the sign-bit check, because in
    /// two's-complement encoding such a zero byte is the disambiguator that distinguishes
    /// e.g. <c>[0x80]</c> (= -128) from <c>[0x80, 0x00]</c> (= +128). This matches the
    /// convention used by <c>System.Numerics.BigInteger.ToByteArray()</c>.
    /// </remarks>
    private static bool IsNegativeRepresentation(byte[] data, int length)
    {
        if (data is null || length <= 0)
        {
            return false;
        }

        return (data[length - 1] & 0x80) != 0;
    }

    /// <summary>
    /// Computes the two's complement of the given byte array representation of a number.
    /// </summary>
    /// <param name="data">The byte array representing the number to compute the two's complement for.</param>
    /// <param name="length">The length of the byte array.</param>
    /// <returns>A new byte array representing the two's complement of the given number.</returns>
    /// <remarks>
    /// Constant-time on the input bytes: both the bitwise-NOT loop and the carry-add
    /// loop iterate the full <paramref name="length"/> unconditionally. The previous
    /// implementation aborted the carry-add as soon as <c>carry == 0</c>, which made
    /// the iteration count vary with the bit pattern of the input — a content-derived
    /// timing distinction we close here. Once the carry naturally becomes zero, every
    /// subsequent iteration adds 0 and is a true no-op, so extending the loop to the
    /// full length is a correctness-preserving CT-stiffening change.
    /// </remarks>
    private static PinnedPoolArray<byte> TwosComplement(byte[] data, int length)
    {
        if (length == 0 || data is null || (length == 1 && data[0] == 0))
        {
            var zeroArray = new PinnedPoolArray<byte>(length: 1);
            zeroArray[0] = 0;
            return zeroArray;
        }

        var twosCompArray = new PinnedPoolArray<byte>(length: length);
        for (int i = 0; i < length; i++)
        {
            twosCompArray[i] = (byte)~data[i];
        }

        int carry = 1;
        for (int i = 0; i < length; i++)
        {
            int sum = twosCompArray[i] + carry;
            twosCompArray[i] = (byte)sum;
            carry = sum >> 8;
        }

        return twosCompArray;
    }

    /// <summary>
    /// Addition operator for <see cref="SecureBigInteger"/>.
    /// </summary>
    /// <param name="left">1st summand</param>
    /// <param name="right">2nd summand</param>
    /// <returns>sum</returns>
    public static SecureBigInteger operator +(SecureBigInteger left, SecureBigInteger right) => Add(left, right);

    /// <summary>
    /// Subtraction operator for <see cref="SecureBigInteger"/>.
    /// </summary>
    /// <param name="left">minuend</param>
    /// <param name="right">subtrahend</param>
    /// <returns>difference</returns>
    public static SecureBigInteger operator -(SecureBigInteger left, SecureBigInteger right) => Subtract(left, right);

    /// <summary>
    /// Multiplication operator for <see cref="SecureBigInteger"/>.
    /// </summary>
    /// <param name="left">multiplicand</param>
    /// <param name="right">multiplier</param>
    /// <returns>product</returns>
    public static SecureBigInteger operator *(SecureBigInteger left, SecureBigInteger right) => Multiply(left, right);

    /// <summary>
    /// Division operator for <see cref="SecureBigInteger"/>.
    /// </summary>
    /// <param name="left">dividend</param>
    /// <param name="right">divisor</param>
    /// <returns>quotient</returns>
    public static SecureBigInteger operator /(SecureBigInteger left, SecureBigInteger right) => Divide(left, right);

    /// <summary>
    /// Remainder operator for <see cref="SecureBigInteger"/>.
    /// </summary>
    /// <param name="left">dividend</param>
    /// <param name="right">divisor</param>
    /// <returns>remainder</returns>
    public static SecureBigInteger operator %(SecureBigInteger left, SecureBigInteger right) => Remainder(left, right);

    /// <summary>
    /// Unary negation operator for <see cref="SecureBigInteger"/>.
    /// </summary>
    /// <param name="value">Value to negate</param>
    /// <returns>Negated value</returns>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="value"/> is <see langword="null"/>.</exception>
    public static SecureBigInteger operator -(SecureBigInteger value)
    {
        if (value is null)
        {
            throw new ArgumentNullException(nameof(value));
        }

        return value.Negate();
    }

    /// <summary>
    /// Defines the behavior of the increment operator (++) for the <see cref="SecureBigInteger"/> class,
    /// which increases the value of a <see cref="SecureBigInteger"/> instance by one.
    /// </summary>
    /// <param name="value">The <see cref="SecureBigInteger"/> value to increment.</param>
    /// <returns>A new <see cref="SecureBigInteger"/> instance representing the incremented value.</returns>
    public static SecureBigInteger operator ++(SecureBigInteger value)
    {
        using var one = new SecureBigInteger(1);
        return Add(value, one);
    }

    /// <summary>
    /// Defines the behavior of the decrement operator (--) for the <see cref="SecureBigInteger"/> class,
    /// which decreases the value of a <see cref="SecureBigInteger"/> instance by one.
    /// </summary>
    /// <param name="value">The <see cref="SecureBigInteger"/> value to decrement.</param>
    /// <returns>A new <see cref="SecureBigInteger"/> instance representing the decremented value.</returns>
    public static SecureBigInteger operator --(SecureBigInteger value)
    {
        using var one = new SecureBigInteger(1);
        return Subtract(value, one);
    }

    /// <summary>
    /// Equality operator for <see cref="SecureBigInteger"/>.
    /// </summary>
    /// <param name="left">first object to compare</param>
    /// <param name="right">second object to compare</param>
    /// <returns><see langword="true"/> if the <paramref name="left"/> instance is equal to the
    /// <paramref name="right"/> instance; otherwise, <see langword="false"/>.</returns>
    public static bool operator ==(SecureBigInteger left, SecureBigInteger right)
    {
        // Both-null fast path stays — null is not disposed and matches the standard
        // operator== contract. The ReferenceEquals fast path for two non-null operands
        // moves into Equals, after the disposal check.
        if (left is null)
        {
            return right is null;
        }

        if (right is null)
        {
            return false;
        }

        return left.Equals(right);
    }

    /// <summary>
    /// Inequality operator for <see cref="SecureBigInteger"/>.
    /// </summary>
    /// <param name="left">first object to compare</param>
    /// <param name="right">second object to compare</param>
    /// <returns><see langword="true"/> if the <paramref name="left"/> instance is not equal to the
    /// <paramref name="right"/> instance; otherwise, <see langword="false"/>.</returns>
    public static bool operator !=(SecureBigInteger left, SecureBigInteger right) => !(left == right);

    /// <summary>
    /// Defines the less-than operator for comparing two instances of <see cref="SecureBigInteger"/>.
    /// </summary>
    /// <param name="left">The first <see cref="SecureBigInteger"/> to compare.</param>
    /// <param name="right">The second <see cref="SecureBigInteger"/> to compare.</param>
    /// <returns>
    /// Returns <see langword="true"/> if <paramref name="left"/> is less than <paramref name="right"/>;
    /// otherwise, <see langword="false"/>.
    /// </returns>
    /// <exception cref="ArgumentNullException">
    /// Thrown if <paramref name="left"/> or <paramref name="right"/> is <see langword="null"/>.
    /// </exception>
    [SuppressMessage("SonarQube", "S3877",
        Justification = "Throwing ArgumentNullException on null is the documented contract across " +
                        "all operators of this class. The class implements IComparable<T> where " +
                        "null arguments have no defined order, so a 'null = smallest value' fallback " +
                        "would silently mask programmer error in a cryptographic context.")]
    public static bool operator <(SecureBigInteger left, SecureBigInteger right)
    {
        if (left is null)
        {
            throw new ArgumentNullException(nameof(left));
        }

        if (right is null)
        {
            throw new ArgumentNullException(nameof(right));
        }

        return left.CompareTo(right) < 0;
    }

    /// <summary>
    /// Performs a greater-than comparison between two instances of <see cref="SecureBigInteger"/>.
    /// </summary>
    /// <param name="left">The first <see cref="SecureBigInteger"/> to compare.</param>
    /// <param name="right">The second <see cref="SecureBigInteger"/> to compare.</param>
    /// <returns>
    /// <see langword="true"/> if the <paramref name="left"/> is greater than the <paramref name="right"/>;
    /// otherwise, <see langword="false"/>.
    /// </returns>
    /// <exception cref="ArgumentNullException">
    /// Thrown if either <paramref name="left"/> or <paramref name="right"/> is <see langword="null"/>.
    /// </exception>
    [SuppressMessage("SonarQube", "S3877", Justification = "See operator <(SecureBigInteger, SecureBigInteger).")]
    public static bool operator >(SecureBigInteger left, SecureBigInteger right)
    {
        if (left is null)
        {
            throw new ArgumentNullException(nameof(left));
        }

        if (right is null)
        {
            throw new ArgumentNullException(nameof(right));
        }

        return left.CompareTo(right) > 0;
    }

    /// <summary>
    /// Less-than-or-equal operator for <see cref="SecureBigInteger"/>.
    /// </summary>
    /// <param name="left">The first <see cref="SecureBigInteger"/> to compare.</param>
    /// <param name="right">The second <see cref="SecureBigInteger"/> to compare.</param>
    /// <returns><see langword="true"/> if <paramref name="left"/> is less than or equal to
    /// <paramref name="right"/>; otherwise, <see langword="false"/>.</returns>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="left"/> or
    /// <paramref name="right"/> is <see langword="null"/>.</exception>
    [SuppressMessage("SonarQube", "S3877", Justification = "See operator <(SecureBigInteger, SecureBigInteger).")]
    public static bool operator <=(SecureBigInteger left, SecureBigInteger right)
    {
        if (left is null)
        {
            throw new ArgumentNullException(nameof(left));
        }

        if (right is null)
        {
            throw new ArgumentNullException(nameof(right));
        }

        return left.CompareTo(right) <= 0;
    }

    /// <summary>
    /// Greater-than-or-equal operator for <see cref="SecureBigInteger"/>.
    /// </summary>
    /// <param name="left">The first <see cref="SecureBigInteger"/> to compare.</param>
    /// <param name="right">The second <see cref="SecureBigInteger"/> to compare.</param>
    /// <returns><see langword="true"/> if <paramref name="left"/> is greater than or equal to
    /// <paramref name="right"/>; otherwise, <see langword="false"/>.</returns>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="left"/> or
    /// <paramref name="right"/> is <see langword="null"/>.</exception>
    [SuppressMessage("SonarQube", "S3877", Justification = "See operator <(SecureBigInteger, SecureBigInteger).")]
    public static bool operator >=(SecureBigInteger left, SecureBigInteger right)
    {
        if (left is null)
        {
            throw new ArgumentNullException(nameof(left));
        }

        if (right is null)
        {
            throw new ArgumentNullException(nameof(right));
        }

        return left.CompareTo(right) >= 0;
    }

    /// <summary>
    /// Implicit conversion from <see cref="int"/> to <see cref="SecureBigInteger"/>.
    /// </summary>
    /// <param name="value">The integer value to convert.</param>
    /// <returns>A <see cref="SecureBigInteger"/> instance representing the integer value.</returns>
    public static implicit operator SecureBigInteger(int value) => new SecureBigInteger(value);

    /// <summary>
    /// Implicit conversion from <see cref="long"/> to <see cref="SecureBigInteger"/>.
    /// </summary>
    /// <param name="value">The long integer value to convert.</param>
    /// <returns>A <see cref="SecureBigInteger"/> instance representing the long integer value.</returns>
    public static implicit operator SecureBigInteger(long value) => new SecureBigInteger(value);

    /// <summary>
    /// Implicit conversion from <see cref="ulong"/> to <see cref="SecureBigInteger"/>.
    /// </summary>
    /// <param name="value">The unsigned long integer value to convert.</param>
    /// <returns>A <see cref="SecureBigInteger"/> instance representing the unsigned long integer value.</returns>
    /// <remarks>
    /// Covers the full <see cref="ulong"/> range, including values above
    /// <see cref="long.MaxValue"/>. Without this overload such literals would have
    /// to be routed through a manual byte-array constructor.
    /// </remarks>
    public static implicit operator SecureBigInteger(ulong value) => new SecureBigInteger(value);

    /// <summary>
    /// Explicit conversion from <see cref="SecureBigInteger"/> to <see cref="int"/>.
    /// </summary>
    /// <param name="value">The <see cref="SecureBigInteger"/> instance to convert.</param>
    /// <returns>A <see cref="int"/> value  representing the <see cref="SecureBigInteger" /> instance.</returns>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="value"/> is null.</exception>
    /// <exception cref="OverflowException">Thrown if the <see cref="SecureBigInteger"/> value is too large for <see cref="int"/>.</exception>
    public static explicit operator int(SecureBigInteger value)
    {
        if (value is null)
        {
            throw new ArgumentNullException(nameof(value));
        }

        value.ThrowIfDisposed();

        if (value.limbs.Length > 1 || value.limbs[0] > uint.MaxValue)
        {
            throw new OverflowException(ErrorMessages.ValueTooLargeForInt);
        }

        uint result = (uint)value.limbs[0];

        if (result > int.MaxValue && !(value.isNegative && result == (uint)int.MaxValue + 1))
        {
            throw new OverflowException(ErrorMessages.ValueTooLargeForInt);
        }

        return value.isNegative ? -(int)result : (int)result;
    }

    /// <summary>
    /// Explicit conversion from <see cref="SecureBigInteger"/> to <see cref="long"/>.
    /// </summary>
    /// <param name="value">The <see cref="SecureBigInteger"/> instance to convert.</param>
    /// <returns>A <see cref="long"/> value representing the <see cref="SecureBigInteger" /> instance.</returns>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="value"/> is null.</exception>
    /// <exception cref="OverflowException">Thrown if the <see cref="SecureBigInteger"/> value is too large for <see cref="long"/>.</exception>
    public static explicit operator long(SecureBigInteger value)
    {
        if (value is null)
        {
            throw new ArgumentNullException(nameof(value));
        }

        value.ThrowIfDisposed();

        if (value.limbs.Length > 1)
        {
            throw new OverflowException(ErrorMessages.ValueTooLargeForLong);
        }

        ulong result = value.limbs[0];

        if (result > long.MaxValue && !(value.isNegative && result == (ulong)long.MaxValue + 1))
        {
            throw new OverflowException(ErrorMessages.ValueTooLargeForLong);
        }

        return value.isNegative ? -(long)result : (long)result;
    }

    /// <summary>
    /// Adds two unsigned <see cref="SecureBigInteger"/> values and returns the sum.
    /// </summary>
    /// <param name="left">First operand.</param>
    /// <param name="right">Second operand.</param>
    /// <returns>A new non-negative <see cref="SecureBigInteger"/> representing
    /// <c>|left| + |right|</c>.</returns>
    /// <remarks>
    /// Constant-time on the magnitude: iterates a fixed number of limbs equal to
    /// <c>max(left.LimbCount, right.LimbCount) + 1</c>, propagating the carry via the
    /// branchless bit-fold formula <c>((l &amp; r) | ((l | r) &amp; ~sum)) &gt;&gt; 63</c>.
    /// No data-dependent loop bound and no early exit when the carry stops propagating.
    /// </remarks>
    private static SecureBigInteger AddUnsigned(SecureBigInteger left, SecureBigInteger right)
    {
        int leftCount = left.LimbCount;
        int rightCount = right.LimbCount;
        int maxCount = leftCount >= rightCount ? leftCount : rightCount;
        int resultCount = maxCount + 1;

        using var result = new PinnedPoolArray<ulong>(length: resultCount);
        ulong carry = 0;

        for (int i = 0; i < resultCount; i++)
        {
            ulong l = i < leftCount ? left.limbs[i] : 0UL;
            ulong r = i < rightCount ? right.limbs[i] : 0UL;

            ulong sum = l + r + carry;
            // Branchless carry-out from a 64-bit add: bit 63 of
            // ((l AND r) OR ((l OR r) AND NOT sum)) is 1 iff l + r + carry overflowed
            // 2^64. Verified for all 8 single-bit cases (a, b, carry-in) → (sum, carry-out).
            carry = ((l & r) | ((l | r) & ~sum)) >> 63;
            result[i] = sum;
        }

        return new SecureBigInteger(result, resultCount, isNegative: false);
    }

    /// <summary>
    /// Subtracts two unsigned <see cref="SecureBigInteger"/> instances and returns the result.
    /// Requires <c>|minuend| &gt;= |subtrahend|</c>; the result is undefined otherwise.
    /// </summary>
    /// <param name="minuend">Minuend.</param>
    /// <param name="subtrahend">Subtrahend.</param>
    /// <returns>A new non-negative <see cref="SecureBigInteger"/> representing
    /// <c>|minuend| - |subtrahend|</c>.</returns>
    /// <remarks>
    /// Constant-time on the magnitudes: iterates a fixed number of limbs equal to
    /// <c>max(minuend.LimbCount, subtrahend.LimbCount)</c>. Borrow propagation uses
    /// two unsigned-overflow checks per limb expressed as <c>&lt;</c>/<c>&gt;</c>
    /// comparisons; on x86/ARM the JIT lowers these to <c>setb</c>/<c>setbe</c>
    /// instructions without a branch.
    /// </remarks>
    private static SecureBigInteger SubtractUnsigned(SecureBigInteger minuend, SecureBigInteger subtrahend)
    {
        int mCount = minuend.LimbCount;
        int sCount = subtrahend.LimbCount;
        int maxCount = mCount >= sCount ? mCount : sCount;

        using var result = new PinnedPoolArray<ulong>(length: maxCount);
        ulong borrow = 0;

        for (int i = 0; i < maxCount; i++)
        {
            ulong m = i < mCount ? minuend.limbs[i] : 0UL;
            ulong s = i < sCount ? subtrahend.limbs[i] : 0UL;

            // Step 1: combine subtrahend limb with incoming borrow.
            ulong sb = s + borrow;
            ulong borrow1 = sb < s ? 1UL : 0UL;
            // Step 2: subtract from the minuend limb.
            ulong diff = m - sb;
            ulong borrow2 = diff > m ? 1UL : 0UL;
            borrow = borrow1 | borrow2;
            result[i] = diff;
        }

        return new SecureBigInteger(result, maxCount, isNegative: false);
    }

    /// <summary>
    /// Multiplies two unsigned <see cref="SecureBigInteger"/> values and returns the product.
    /// </summary>
    /// <param name="left">First operand.</param>
    /// <param name="right">Second operand.</param>
    /// <returns>A new non-negative <see cref="SecureBigInteger"/> representing
    /// <c>|left| * |right|</c>.</returns>
    /// <remarks>
    /// Constant-time on the magnitudes: schoolbook multiplication on 64-bit limbs.
    /// The outer loop runs <c>left.LimbCount</c> iterations and the inner loop runs
    /// <c>right.LimbCount</c> iterations, both bounded by public observables (the
    /// limb counts depend on the operand magnitudes' bit lengths, which the threat
    /// model treats as observable). There is no zero-skip path on either operand,
    /// no early termination of the carry chain, and the inner-loop body has no
    /// data-dependent branches — every iteration performs the same 64×64→128
    /// multiplication, three branchless ulong additions, and three carry
    /// computations.
    /// </remarks>
    private static SecureBigInteger MultiplyUnsigned(SecureBigInteger left, SecureBigInteger right)
    {
        int leftCount = left.LimbCount;
        int rightCount = right.LimbCount;
        int resultCount = leftCount + rightCount;

        using var result = new PinnedPoolArray<ulong>(length: resultCount);

        for (int i = 0; i < leftCount; i++)
        {
            ulong carry = 0;
            ulong leftLimb = left.limbs[i];
            for (int j = 0; j < rightCount; j++)
            {
                MultiplyToHighLow(leftLimb, right.limbs[j], out ulong productHigh, out ulong productLow);

                // Three-way add with branchless carry capture:
                //   result[i+j] += productLow (carry1 if it wrapped)
                //   then            += previous-carry (carry2 if THAT wrapped)
                // The two carries can never both be 1 simultaneously: that would
                // require result[i+j] + productLow ≥ 2^64 AND the truncated sum to
                // also be ≥ 2^64 - carryIn, which exceeds the maximum
                // (2 × (2^64 - 1) = 2^65 - 2). So carry1 + carry2 ∈ {0, 1}, and
                // the next iteration's carry productHigh + (0 or 1) ≤ 2^64 - 1
                // (productHigh ≤ 2^64 - 2 for any 64×64 product) — no further
                // wrap to handle.
                ulong currentLimb = result[i + j];

                ulong sumWithLow = currentLimb + productLow;
                ulong carry1 = sumWithLow < currentLimb ? 1UL : 0UL;

                ulong sumWithCarry = sumWithLow + carry;
                ulong carry2 = sumWithCarry < sumWithLow ? 1UL : 0UL;

                result[i + j] = sumWithCarry;
                carry = productHigh + carry1 + carry2;
            }

            // The position one beyond the inner loop's last write is still zero
            // (it has not been touched in this or any prior outer iteration —
            // outer-i writes positions [i, i + rightCount - 1], so position
            // i + rightCount is first reached here). Safe to overwrite with the
            // accumulated final carry.
            result[i + rightCount] = carry;
        }

        return new SecureBigInteger(result, resultCount, isNegative: false);
    }

#if NET5_0_OR_GREATER
    /// <summary>
    /// Computes the full 128-bit product of two 64-bit unsigned integers. Routes
    /// through <see cref="Math.BigMul(ulong, ulong, out ulong)"/> on .NET 5+
    /// (single-instruction <c>MUL r/m64</c> on x64), which the JIT lowers to a
    /// constant-time hardware multiplication on every supported architecture.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void MultiplyToHighLow(ulong x, ulong y, out ulong high, out ulong low)
    {
        // Math.BigMul(a, b, out lo) RETURNS the high 64 bits and OUTS the low
        // 64 bits — naming the receiving variable for the return value `high`
        // and the out-parameter target `low` is essential. Swapping these
        // locally produces the correct numeric result only for products that
        // fit in 64 bits (where high == 0); larger products come out with
        // their halves transposed, which propagates through long division
        // (EE/GCD over Mersenne primes) into apparent non-termination.
        high = Math.BigMul(x, y, out low);
    }
#else
    /// <summary>
    /// Computes the full 128-bit product of two 64-bit unsigned integers via four
    /// 32×32 partial products (the standard fallback formula used when
    /// <c>Math.BigMul(ulong, ulong, out ulong)</c> is not available on the target
    /// framework). Each 32×32 multiplication compiles to a single hardware
    /// instruction on x86/x64/ARM64 — constant-time on those platforms. The
    /// recombination uses only addition and bit-shifts, no branches.
    /// </summary>
    private static void MultiplyToHighLow(ulong x, ulong y, out ulong high, out ulong low)
    {
        uint xLow = (uint)x;
        uint xHigh = (uint)(x >> 32);
        uint yLow = (uint)y;
        uint yHigh = (uint)(y >> 32);

        ulong loLo = (ulong)xLow * yLow;
        ulong hiLo = (ulong)xHigh * yLow;
        ulong loHi = (ulong)xLow * yHigh;
        ulong hiHi = (ulong)xHigh * yHigh;

        ulong cross = (loLo >> 32) + (hiLo & 0xFFFFFFFFUL) + loHi;
        low = (loLo & 0xFFFFFFFFUL) | (cross << 32);
        high = (hiLo >> 32) + (cross >> 32) + hiHi;
    }
#endif

    /// <summary>
    /// Performs an unsigned division of two <see cref="SecureBigInteger"/> instances and returns the quotient.
    /// Additionally, calculates the remainder of the division and outputs it through the <paramref name="remainder"/> parameter.
    /// </summary>
    /// <param name="dividend">The <see cref="SecureBigInteger"/> to divide.</param>
    /// <param name="divisor">The <see cref="SecureBigInteger"/> to divide by.</param>
    /// <param name="remainder">The out parameter that will contain the remainder of the division.</param>
    /// <returns>A new <see cref="SecureBigInteger"/> representing the unsigned quotient of the division.</returns>
    /// <remarks>
    /// Constant-time long division on 64-bit limbs. The bit loop iterates
    /// <c>dividend.LimbCount * 64</c> times unconditionally — a public observable
    /// that depends on the operand byte length, never on its content. Each
    /// iteration:
    /// <list type="number">
    ///   <item>shifts the partial remainder left by one bit (linear in
    ///   <c>remainderLimbCount</c>);</item>
    ///   <item>OR-s in the dividend bit at the current position;</item>
    ///   <item>trial-subtracts the divisor in place, tracking the final borrow;</item>
    ///   <item>conditionally adds the divisor back when the trial subtraction
    ///   underflowed, gated by a branchless mask <c>0 - borrow</c>;</item>
    ///   <item>writes the canSubtract flag into the quotient bit at the same
    ///   position via an unconditional OR with <c>(canSubtract &lt;&lt; bit)</c>.</item>
    /// </list>
    /// The classical "compare-and-subtract" branch is replaced by always-subtract +
    /// always-undo-when-borrow. The final remainder is bounded by
    /// <c>divisor - 1</c>; the pre-subtract value is bounded by <c>2*divisor - 1</c>,
    /// which is why the remainder buffer is sized at <c>divisor.LimbCount + 1</c>.
    /// </remarks>
    private static SecureBigInteger DivideUnsigned(SecureBigInteger dividend, SecureBigInteger divisor,
        out SecureBigInteger remainder)
    {
        int dividendLimbCount = dividend.LimbCount;
        int divisorLimbCount = divisor.LimbCount;
        int totalBits = dividendLimbCount * 64;

        // Pre-subtract maximum: shift-left of (divisor - 1) plus an OR-in bit
        // gives 2*(divisor - 1) + 1 < 2*divisor, which fits in
        // divisor.LimbCount + 1 limbs. The +1 absorbs the shift overflow from
        // the high limb of the post-shift value.
        int remainderLimbCount = divisorLimbCount + 1;
        using var rem = new PinnedPoolArray<ulong>(length: remainderLimbCount);
        using var quot = new PinnedPoolArray<ulong>(length: dividendLimbCount);

        for (int bit = totalBits - 1; bit >= 0; bit--)
        {
            ShiftLeftByOneBitInPlace(rem, remainderLimbCount);

            // OR in the dividend bit at position `bit` (LSB-indexed; bit/64
            // selects the limb, bit%64 the bit within it).
            ulong dividendBit = (dividend.limbs[bit >> 6] >> (bit & 63)) & 1UL;
            rem[0] |= dividendBit;

            ulong borrow = SubtractInPlace(rem, remainderLimbCount, divisor.limbs, divisorLimbCount);

            // canSubtract = NOT borrow (1 if rem ≥ divisor, 0 if rem < divisor).
            // undoMask    = all-ones if the trial subtract underflowed (need to
            // revert), zero otherwise.
            ulong canSubtract = borrow ^ 1UL;
            ulong undoMask = 0UL - borrow;

            AddMaskedInPlace(rem, remainderLimbCount, divisor.limbs, divisorLimbCount, undoMask);

            // Set quotient bit to canSubtract — an unconditional OR works
            // because quot[qLimbIdx] starts at zero (PinnedPoolArray ctor
            // zeroes the buffer) and each bit position is written exactly once.
            quot[bit >> 6] |= canSubtract << (bit & 63);
        }

        remainder = new SecureBigInteger(rem, remainderLimbCount, isNegative: false);
        return new SecureBigInteger(quot, dividendLimbCount, isNegative: false);
    }

    /// <summary>
    /// Shifts a pinned ulong-limb buffer left by one bit, in place. High bits
    /// propagate up through the limb chain LSB-first; the bit shifted out of
    /// the highest limb is discarded (callers must size their buffer to absorb
    /// the worst-case shift).
    /// </summary>
    /// <remarks>
    /// CT-helper marked <c>NoInlining | NoOptimization</c> per the project
    /// convention for limb-level constant-time primitives, mirroring the BCL
    /// <c>CryptographicOperations.FixedTimeEquals</c> pattern (available on
    /// .NET 5+ but referenced here textually so older TFMs keep building).
    /// The loop iteration count is <paramref name="limbCount"/>, a public
    /// observable; the per-iteration body has no data-dependent branches.
    /// </remarks>
    [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
    private static void ShiftLeftByOneBitInPlace(PinnedPoolArray<ulong> limbs, int limbCount)
    {
        ulong shiftCarry = 0;
        for (int i = 0; i < limbCount; i++)
        {
            ulong oldLimb = limbs[i];
            limbs[i] = (oldLimb << 1) | shiftCarry;
            shiftCarry = oldLimb >> 63;
        }
    }

    /// <summary>
    /// Subtracts <paramref name="subtrahend"/> from <paramref name="minuend"/>
    /// in place, returning the final borrow (1 if the unsigned subtraction
    /// underflowed, 0 otherwise). Both buffers are read LSB-first; the
    /// subtrahend may be shorter than the minuend, in which case the missing
    /// high limbs are treated as zero.
    /// </summary>
    /// <remarks>
    /// CT-helper. Borrow propagation uses the two-step pattern of D4-step-1:
    /// <c>borrow1</c> captures wrap of <c>(s + carryIn)</c>, <c>borrow2</c>
    /// captures wrap of <c>(m - sb)</c>; their bitwise-OR is the new borrow.
    /// On x86 RyuJIT the <c>&lt;</c> and <c>&gt;</c> operators on <c>ulong</c>
    /// lower to <c>setb</c>/<c>seta</c> — branchless even with
    /// <c>NoOptimization</c>, because the basic CMP+SETcc lowering is part of
    /// standard code emission.
    /// </remarks>
    [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
    private static ulong SubtractInPlace(
        PinnedPoolArray<ulong> minuend, int minuendCount,
        PinnedPoolArray<ulong> subtrahend, int subtrahendCount)
    {
        ulong borrow = 0;
        for (int i = 0; i < minuendCount; i++)
        {
            ulong s = i < subtrahendCount ? subtrahend[i] : 0UL;
            ulong sb = s + borrow;
            ulong borrow1 = sb < s ? 1UL : 0UL;
            ulong diff = minuend[i] - sb;
            ulong borrow2 = diff > minuend[i] ? 1UL : 0UL;
            borrow = borrow1 | borrow2;
            minuend[i] = diff;
        }

        return borrow;
    }

    /// <summary>
    /// Adds <paramref name="addend"/> to <paramref name="accumulator"/> in
    /// place, with each addend limb gated by <paramref name="mask"/>: when
    /// <paramref name="mask"/> is all-ones the addend is added unchanged;
    /// when it is zero the addition is a no-op (every addLimb becomes zero).
    /// Used as a constant-time conditional add in the divide loop's
    /// "trial-subtract + undo-on-borrow" pattern.
    /// </summary>
    /// <remarks>
    /// CT-helper. The mask is computed branchlessly by the caller from the
    /// trial subtract's borrow flag (<c>0 - borrow</c>), so no data-dependent
    /// branch ever reaches this routine; the loop iteration count is
    /// <paramref name="accumulatorCount"/>, a public observable.
    /// </remarks>
    [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
    private static void AddMaskedInPlace(
        PinnedPoolArray<ulong> accumulator, int accumulatorCount,
        PinnedPoolArray<ulong> addend, int addendCount,
        ulong mask)
    {
        ulong carry = 0;
        for (int i = 0; i < accumulatorCount; i++)
        {
            ulong a = i < addendCount ? addend[i] : 0UL;
            ulong addLimb = a & mask;
            ulong sum = accumulator[i] + addLimb;
            ulong carry1 = sum < accumulator[i] ? 1UL : 0UL;
            ulong sumWithCarry = sum + carry;
            ulong carry2 = sumWithCarry < sum ? 1UL : 0UL;
            accumulator[i] = sumWithCarry;
            carry = carry1 | carry2;
        }
    }

    /// <summary>
    /// Compares two <see cref="SecureBigInteger"/> instances as unsigned values and returns a value that indicates their relative order.
    /// </summary>
    /// <param name="left">The first <see cref="SecureBigInteger"/> instance to compare.</param>
    /// <param name="right">The second <see cref="SecureBigInteger"/> instance to compare.</param>
    /// <returns>
    /// A signed integer that indicates the relative order of the values:
    /// Less than zero if <paramref name="left"/> is less than <paramref name="right"/>.
    /// Zero if <paramref name="left"/> is equal to <paramref name="right"/>.
    /// Greater than zero if <paramref name="left"/> is greater than <paramref name="right"/>.
    /// </returns>
    /// <remarks>
    /// Constant-time on the magnitudes: walks every limb of <c>max(left.LimbCount,
    /// right.LimbCount)</c> from least- to most-significant, computing per-limb
    /// gt/lt flags via <c>(b - a) &gt;&gt; 63</c> (the high-bit-of-wrap trick) and
    /// folding them into a running result with a branchless overwrite-if-non-zero
    /// mask. Because later iterations process more-significant limbs, the final
    /// non-zero limb encountered determines the result — exactly the lexicographic
    /// MSB-first ordering required.
    /// </remarks>
    private static int CompareUnsigned(SecureBigInteger left, SecureBigInteger right)
    {
        int leftCount = left.LimbCount;
        int rightCount = right.LimbCount;
        int maxCount = leftCount >= rightCount ? leftCount : rightCount;

        long result = 0;
        for (int i = 0; i < maxCount; i++)
        {
            ulong l = i < leftCount ? left.limbs[i] : 0UL;
            ulong r = i < rightCount ? right.limbs[i] : 0UL;

            // l > r and l < r as 0/1 ulongs. The C# `<`/`>` operators on ulong
            // lower to `setb`/`seta` on x86 RyuJIT — branchless. The naive
            // bit-fold `(r - l) >> 63` is *wrong* for limbs in [2^63, 2^64),
            // because the unsigned wrap-result and a non-wrapping difference
            // both set bit 63 in those cases.
            ulong gt = l > r ? 1UL : 0UL;
            ulong lt = l < r ? 1UL : 0UL;
            long limbDiff = (long)gt - (long)lt;

            // mask = -1L if limbDiff != 0, 0L otherwise. Arithmetic right shift on
            // signed long sign-extends the high bit.
            long mask = (limbDiff | -limbDiff) >> 63;
            result = (result & ~mask) | (limbDiff & mask);
        }

        return (int)result;
    }

    /// <summary>
    /// Trims leading-zero limbs from the canonical limb storage, leaving exactly
    /// one zero limb when the value is zero. Adjusts <c>limbs.Length</c> to reflect
    /// the trimmed count without touching the underlying capacity (the unused
    /// high limbs remain zero from the buffer's initialisation).
    /// </summary>
    private void TrimLeadingZerosInPlace()
    {
        this.limbs.Length = GetActualLength(this);
    }

    /// <summary>
    /// Returns the index-based limb count after trimming leading-zero limbs from
    /// <paramref name="secureBigInteger"/>'s canonical storage, with a minimum of
    /// 1 (the single zero limb representing the value zero).
    /// </summary>
    private static int GetActualLength(SecureBigInteger secureBigInteger)
    {
        var src = secureBigInteger.limbs;
        for (int i = src.Length - 1; i >= 0; i--)
        {
            if (src[i] != 0)
            {
                return i + 1;
            }
        }

        return 1;
    }

    /// <summary>
    /// Determines whether the current <see cref="SecureBigInteger"/> instance represents the value zero.
    /// </summary>
    /// <returns>
    /// True if the instance represents the value zero; otherwise, false.
    /// </returns>
    /// <summary>
    /// Returns <see langword="true"/> iff the magnitude limbs are all zero,
    /// independent of the sign flag.
    /// </summary>
    /// <remarks>
    /// Branchless on the magnitude: ORs every limb into a single ulong
    /// accumulator, then compares against zero. The <c>acc == 0</c> final test
    /// compiles to <c>setz</c> on x86 RyuJIT, branchless. Loop bound is
    /// <c>limbs.Length</c>, a public observable.
    /// </remarks>
    private bool IsZeroInternal()
    {
        ulong acc = 0;
        int len = this.limbs.Length;
        for (int i = 0; i < len; i++)
        {
            acc |= this.limbs[i];
        }

        return acc == 0;
    }

    /// <summary>
    /// Throws an <see cref="ObjectDisposedException"/> if the current instance has been disposed.
    /// </summary>
    /// <exception cref="ObjectDisposedException">
    /// Thrown when an attempt is made to access a disposed instance of <see cref="SecureBigInteger"/>.
    /// </exception>
    private void ThrowIfDisposed()
    {
        if (Volatile.Read(ref this.disposed) == 1)
        {
            throw new ObjectDisposedException(nameof(SecureBigInteger));
        }
    }

    /// <summary>
    /// Releases all resources used by the current instance of the <see cref="SecureBigInteger"/> class.
    /// </summary>
    public void Dispose()
    {
        this.Dispose(true);
        GC.SuppressFinalize(this);
    }

    /// <summary>
    /// Releases the resources used by the <see cref="SecureBigInteger"/> instance.
    /// </summary>
    /// <param name="disposing"><see langword="true"/> when called from the explicit
    /// <see cref="Dispose()"/> path; <see langword="false"/> when called from the
    /// finalizer.</param>
    /// <remarks>
    /// Both paths dispose <see cref="limbs"/> identically. The standard "skip managed
    /// resources from the finalizer" guidance is rejected here because:
    /// <list type="bullet">
    ///   <item><see cref="PinnedPoolArray{T}.Dispose"/> is finalizer-safe (it touches
    ///   only its own GCHandle, the static <c>ArrayPool&lt;T&gt;.Shared</c> singleton,
    ///   and a private buffer — none of which depend on other managed objects that may
    ///   already have been finalized).</item>
    ///   <item>If a caller forgets to <see cref="Dispose()"/>, deferring the secure
    ///   wipe until <see cref="PinnedPoolArray{T}"/>'s own finalizer eventually runs
    ///   creates a non-deterministic window where pinned plaintext is reachable from
    ///   a heap-snapshot attacker. Forcing the wipe in our finalizer path closes that
    ///   window to a single GC cycle.</item>
    ///   <item>The disposal is idempotent — <see cref="PinnedPoolArray{T}.Dispose"/>
    ///   returns early if already disposed, so the cascade
    ///   (SecureBigInteger.Finalize → PinnedPoolArray.Dispose → PinnedPoolArray.Finalize
    ///   no-ops) is correct regardless of finalizer ordering.</item>
    /// </list>
    /// The <paramref name="disposing"/> parameter is therefore retained only for
    /// API-shape compatibility with the conventional Dispose pattern.
    /// </remarks>
    [SuppressMessage("ReSharper", "UnusedParameter.Local",
        Justification = "Retained for the conventional Dispose-pattern shape; both paths intentionally take the same release route — see remarks.")]
    private void Dispose(bool disposing)
    {
        if (Interlocked.Exchange(ref this.disposed, 1) == 1)
        {
            return;
        }

        // Wipe pinned plaintext on both paths. PinnedPoolArray.Dispose is idempotent
        // and finalizer-safe, so even when invoked twice (once from here, once from
        // PinnedPoolArray's own finalizer) the second call short-circuits.
        this.limbs?.Dispose();
        this.limbs = null;
    }

    /// <summary>
    /// Determines whether the current instance is equal to another <see cref="SecureBigInteger"/> instance.
    /// </summary>
    /// <param name="other">The <see cref="SecureBigInteger"/> instance to compare with the current instance.</param>
    /// <returns><see langword="true"/> if the current instance is equal to the <paramref name="other"/> instance;
    /// otherwise, <see langword="false"/>.</returns>
    /// <remarks>
    /// <para>
    /// The limb-by-limb comparison is constant-time per the operands' configured limb lengths.
    /// Both magnitudes are first zero-padded into pinned pool buffers of size
    /// <c>max(this.limbs.Length, other.limbs.Length)</c>, then compared with a fixed-time
    /// XOR-OR-fold primitive that runs the full padded length on every call — there is no
    /// early exit on the first differing limb and no length-mismatch fast path.
    /// </para>
    /// <para>
    /// The sign flag is folded into the result via a non-short-circuiting bitwise AND, so the
    /// runtime does not branch on whether the signs match before the magnitude compare. The
    /// remaining length-only observable (the loop runs
    /// <c>max(this.limbs.Length, other.limbs.Length)</c> iterations) reflects already-public
    /// buffer sizing, not limb content.
    /// </para>
    /// <para>
    /// As of D9 the comparison runs uniformly across all target frameworks via
    /// <see cref="FixedTimeLimbsEqual"/> — no TFM-conditional path. The 8× factor over a
    /// byte-level fold reflects one ulong-XOR covering 8 bytes per loop iteration.
    /// </para>
    /// </remarks>
    [SuppressMessage("SonarQube", "S2178",
        Justification = "Non-short-circuit AND is intentional in this constant-time context. " +
                        "Using && would emit a conditional branch on `limbsEqual` to skip the " +
                        "second operand; while both operands here are pre-computed bool values " +
                        "so today the branch carries no secret data, the `&` form documents the " +
                        "CT-design intent and is resilient to future refactors that inline " +
                        "expressions into either side.")]
    public bool Equals(SecureBigInteger other)
    {
        if (other is null)
        {
            return false;
        }

        // Disposal check before the ReferenceEquals fast-path: comparing two
        // disposed instances (or self-comparing a disposed instance) must throw
        // ObjectDisposedException, not silently return true.
        this.ThrowIfDisposed();
        other.ThrowIfDisposed();

        if (ReferenceEquals(this, other))
        {
            return true;
        }

        bool signsEqual = this.isNegative == other.isNegative;

        int leftLen = this.limbs.Length;
        int rightLen = other.limbs.Length;
        int maxLen = leftLen >= rightLen ? leftLen : rightLen;
        using var leftBuf = new PinnedPoolArray<ulong>(length: maxLen);
        using var rightBuf = new PinnedPoolArray<ulong>(length: maxLen);
        Array.Clear(leftBuf.PoolArray, 0, maxLen);
        Array.Clear(rightBuf.PoolArray, 0, maxLen);
        Array.Copy(this.limbs.PoolArray, leftBuf.PoolArray, leftLen);
        Array.Copy(other.limbs.PoolArray, rightBuf.PoolArray, rightLen);

        bool limbsEqual = FixedTimeLimbsEqual(leftBuf, rightBuf);

        return limbsEqual & signsEqual;
    }

    /// <summary>
    /// Determines whether the specified object is equal to the current <see cref="SecureBigInteger"/> instance.
    /// </summary>
    /// <param name="obj">The object to compare with the current <see cref="SecureBigInteger"/>.</param>
    /// <returns>
    /// <see langword="true"/> if the specified object is equal to the current <see cref="SecureBigInteger"/>;
    /// otherwise, <see langword="false"/>.
    /// </returns>
    public override bool Equals(object obj) => obj is SecureBigInteger other && this.Equals(other);

    /// <summary>
    /// Constant-time equality compare on two equal-length limb buffers via
    /// XOR-OR-fold into a single ulong accumulator. Returns <see langword="true"/>
    /// iff every limb pair is bitwise-identical.
    /// </summary>
    /// <remarks>
    /// CT-helper. The loop runs <c>left.Length</c> iterations (caller invariant:
    /// equal lengths); per-iteration body is straight-line XOR + OR with no
    /// branches. <c>NoInlining | NoOptimization</c> mirrors the BCL precedent
    /// of <c>CryptographicOperations.FixedTimeEquals</c>.
    /// </remarks>
    [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
    private static bool FixedTimeLimbsEqual(PinnedPoolArray<ulong> left, PinnedPoolArray<ulong> right)
    {
        int len = left.Length;
        ulong accumulator = 0;
        for (int i = 0; i < len; i++)
        {
            accumulator |= left[i] ^ right[i];
        }

        return accumulator == 0;
    }

    /// <summary>
    /// Returns the hash code for the current instance of the <see cref="SecureBigInteger"/> class.
    /// </summary>
    /// <returns>An integer representing the hash code of the current instance.</returns>
    [SuppressMessage("ReSharper", "NonReadonlyMemberInGetHashCode", Justification = "Fields are not externally mutable. Fields are internally mutable only for creation purposes.")]
    [SuppressMessage("SonarQube", "S2328", Justification = "Fields are not externally mutable. Fields are internally mutable only for creation purposes.")]
    public override int GetHashCode()
    {
        this.ThrowIfDisposed();
        int len = this.limbs.Length;
#if NETSTANDARD2_1_OR_GREATER || NET8_0_OR_GREATER
        var hash = new HashCode();
        hash.Add(this.Sign);
        hash.Add(len);
        for (int i = 0; i < len; i++)
        {
            hash.Add(this.limbs[i]);
        }

        return hash.ToHashCode();
#else
        unchecked
        {
            var hash = 17;
            hash = hash * 31 + this.Sign.GetHashCode();
            hash = hash * 31 + len.GetHashCode();
            for (int i = 0; i < len; i++)
            {
                hash = hash * 31 + this.limbs[i].GetHashCode();
            }

            return hash;
        }
#endif
    }

    /// <summary>
    /// Compares the current instance to another <see cref="SecureBigInteger"/> object
    /// and returns an integer indicating the relative order of the objects.
    /// </summary>
    /// <param name="other">The <see cref="SecureBigInteger"/> object to compare with the current instance.</param>
    /// <returns>
    /// A signed integer indicating the relative values of the current instance and the <paramref name="other"/> object:
    /// - Less than zero if the current instance is less than <paramref name="other"/>.
    /// - Zero if the current instance is equal to <paramref name="other"/>.
    /// - Greater than zero if the current instance is greater than <paramref name="other"/>.
    /// </returns>
    public int CompareTo(SecureBigInteger other)
    {
        if (other is null)
        {
            return 1;
        }

        this.ThrowIfDisposed();
        other.ThrowIfDisposed();

        if (this.isNegative != other.isNegative)
        {
            return this.isNegative ? -1 : 1;
        }

        int comparison = CompareUnsigned(this, other);
        return this.isNegative ? -comparison : comparison;
    }

    /// <summary>
    /// Counts the decimal-digit length of the magnitude of <paramref name="value"/>
    /// (sign-independent). Used by <see cref="ToPinnedCharArray"/> to size the output
    /// buffer. Integer-only; replaces the previous <c>Log10</c>-based estimate, which
    /// performed double-precision floating-point arithmetic on operand-derived
    /// quantities and was therefore unsuitable for a CT-conscious backend.
    /// </summary>
    /// <param name="value">The value whose magnitude's decimal-digit length is wanted.</param>
    /// <returns><c>0</c> when <paramref name="value"/> is zero, otherwise the
    /// decimal-digit count of <c>|value|</c>.</returns>
    private static int CountDecimalDigits(SecureBigInteger value)
    {
        if (value.IsZeroInternal())
        {
            return 0;
        }

        SecureBigInteger temp = null;
        try
        {
            temp = new SecureBigInteger(value);
            temp.isNegative = false;
            using var ten = new SecureBigInteger(10);
            using var zero = new SecureBigInteger(0);
            int count = 0;
            while (CompareUnsigned(temp, zero) > 0)
            {
                count++;
                var quotient = DivideUnsigned(temp, ten, out var rem);
                // Transfer ownership of `quotient` into `temp` BEFORE any
                // potentially-throwing dispose. If `rem.Dispose()` or
                // `oldTemp.Dispose()` throws, the surrounding finally still
                // disposes `temp` (now holding `quotient`), so no allocation
                // is orphaned.
                var oldTemp = temp;
                temp = quotient;
                rem.Dispose();
                oldTemp.Dispose();
            }

            return count;
        }
        finally
        {
            temp?.Dispose();
        }
    }

    /// <summary>
    /// Converts the current <see cref="SecureBigInteger"/> instance to a character array representation.
    /// </summary>
    /// <returns>A character array containing the string representation of the current instance.</returns>
    public PinnedPoolArray<char> ToPinnedCharArray()
    {
        this.ThrowIfDisposed();

        if (this.IsZeroInternal())
        {
            var zeroArray = new PinnedPoolArray<char>(length: 1);
            zeroArray[0] = DigitOffset;
            return zeroArray;
        }

        // Determine digit count by counting repeated divisions by 10. The previous
        // implementation called Log10 (removed in the CT refactor — its double-arithmetic
        // path was not constant-time on the operand value). Two-pass counting is integer-only
        // and uses the same DivideUnsigned helper as the digit-extraction loop below.
        int digitCount = CountDecimalDigits(this);
        var totalLength = this.isNegative ? digitCount + 1 : digitCount;

        // `result` ownership transfers to caller on success; catch disposes it on
        // exception. `temp` is always disposed in finally. Pattern parallels the
        // constructor / ModPow.
        PinnedPoolArray<char> result = null;
        SecureBigInteger temp = null;
        try
        {
            result = new PinnedPoolArray<char>(length: totalLength);
            var index = totalLength - 1;

            temp = new SecureBigInteger(this);
            temp.isNegative = false;
            using var zero = new SecureBigInteger(0);
            using var ten = new SecureBigInteger(10);

            while (CompareUnsigned(temp, zero) > 0)
            {
                var quotient = DivideUnsigned(temp, ten, out var rem);
                try
                {
                    result[index--] = (char)(DigitOffset + (byte)(rem.limbs[0] & 0xFF));
                    temp.Dispose();
                    temp = quotient;
                    quotient = null; // ownership transferred to temp
                }
                finally
                {
                    quotient?.Dispose();
                    rem.Dispose();
                }
            }

            if (this.isNegative)
            {
                result[0] = '-';
            }

            var ret = result;
            result = null;
            return ret;
        }
        catch
        {
            result?.Dispose();
            throw;
        }
        finally
        {
            temp?.Dispose();
        }
    }

    /// <summary>
    /// Returns a string representation of the <see cref="SecureBigInteger"/> instance.
    /// </summary>
    /// <returns>
    /// A string that represents the current <see cref="SecureBigInteger"/> instance.
    /// In debug mode, the string includes the numerical value of the object, while in release mode,
    /// it returns a placeholder string indicating secured content.
    /// </returns>
    public override string ToString()
    {
        this.ThrowIfDisposed();
#if DEBUG
        using var pinnedCharArray = this.ToPinnedCharArray();
        var s = new string(pinnedCharArray.PoolArray, 0, pinnedCharArray.Length);
        return $"{nameof(SecureBigInteger)}({s})";
#else
        return "*** Secured Value ***";
#endif
    }

    /// <summary>
    /// Converts the current <see cref="SecureBigInteger"/> instance to its hexadecimal string representation.
    /// </summary>
    /// <returns>
    /// A <see cref="PinnedPoolArray{T}"/> containing the hexadecimal representation of the number.
    /// If the instance is negative, the resulting hexadecimal string starts with a '-' character.
    /// </returns>
    public PinnedPoolArray<char> ToHexadecimal()
    {
        this.ThrowIfDisposed();

        // Match the historical contract: 2 hex chars per *significant* magnitude
        // byte (i.e. ByteCount, not limbs.Length * 8). This keeps Share's
        // GetHexLength predictor in sync with the actual output length.
        int byteLength = this.ByteCount;
        int hexLength = byteLength * 2;
        int totalLength = this.isNegative ? hexLength + 1 : hexLength;
        var result = new PinnedPoolArray<char>(length: totalLength);
        int index = 0;

        if (this.isNegative)
        {
            result[index++] = '-';
        }

        for (int byteIdx = byteLength - 1; byteIdx >= 0; byteIdx--)
        {
            int limbIdx = byteIdx >> 3;
            int byteInLimb = byteIdx & 7;
            byte b = (byte)(this.limbs[limbIdx] >> (byteInLimb * 8));
            result[index++] = GetHexChar((b >> 4) & 0xF);
            result[index++] = GetHexChar(b & 0xF);
        }

        return result;
    }

    private static char GetHexChar(int value)
    {
        return value < 10 ? (char)(DigitOffset + value) : (char)('A' + value - 10);
    }

    /// <summary>
    /// 128-entry ASCII lookup table mapping each hex character to its 0..15
    /// nibble value. Non-hex ASCII positions hold <c>0xFF</c> (sentinel for
    /// invalid). The table is loaded once at type initialisation and is
    /// considered public information (the hex alphabet leaks no secrets).
    /// </summary>
    private static readonly byte[] HexCharLookup = BuildHexCharLookup();

    private static byte[] BuildHexCharLookup()
    {
        var table = new byte[128];
        for (int i = 0; i < 128; i++)
        {
            table[i] = 0xFF;
        }

        for (int i = 0; i <= 9; i++)
        {
            table['0' + i] = (byte)i;
        }

        for (int i = 0; i < 6; i++)
        {
            table['a' + i] = (byte)(10 + i);
            table['A' + i] = (byte)(10 + i);
        }

        return table;
    }

    private static int DecodeHexChar(char c)
    {
        if (c >= 128 || HexCharLookup[c] == 0xFF)
        {
            throw new FormatException(string.Format(ErrorMessages.NumberFormatInvalidChar, c));
        }

        return HexCharLookup[c];
    }

    /// <summary>
    /// Reconstructs a <see cref="SecureBigInteger"/> from its hexadecimal
    /// representation, the inverse of <see cref="ToHexadecimal"/>.
    /// </summary>
    /// <param name="hex">
    /// Pinned character buffer containing the hex digits in the order:
    /// optional sign (<c>'-'</c> or <c>'+'</c>) → optional <c>0x</c> /
    /// <c>0X</c> base prefix → one or more hex digits. Mixed-case digits are
    /// accepted (<c>0-9</c>, <c>a-f</c>, <c>A-F</c>). Odd-length digit
    /// sequences are allowed; the leading digit then represents the low
    /// nibble of the most-significant magnitude byte. Examples that all
    /// parse to the same value: <c>"7B2"</c>, <c>"07B2"</c>, <c>"0x7B2"</c>,
    /// <c>"0X07B2"</c>.
    /// </param>
    /// <returns>A new <see cref="SecureBigInteger"/> with the parsed value.
    /// The caller takes ownership and must dispose.</returns>
    /// <exception cref="ArgumentNullException">
    /// <paramref name="hex"/> is <see langword="null"/>.
    /// </exception>
    /// <exception cref="ArgumentException">
    /// <paramref name="hex"/> is empty.
    /// </exception>
    /// <exception cref="FormatException">
    /// <paramref name="hex"/> contains a sign character without any following
    /// digits, or contains a non-hex character.
    /// </exception>
    /// <remarks>
    /// <para>
    /// The input must be supplied as a <see cref="PinnedPoolArray{T}"/> of
    /// <see cref="char"/> rather than a <see cref="string"/> or
    /// <see cref="ReadOnlySpan{T}"/>: those alternative containers cannot be
    /// securely cleared (managed strings are GC-relocatable and possibly
    /// interned, spans give no ownership over their backing storage). Callers
    /// who already hold a <see cref="string"/> can bridge through
    /// <see cref="Cryptography.SecureInput.SecureCharBufferExtensions.ToPinnedSecure(string)"/>
    /// — that helper documents the residual leakage of the source string.
    /// </para>
    /// <para>
    /// Parsing of valid input is best-effort constant-time: each hex digit is
    /// resolved through a fixed 128-entry lookup table, and the byte assembly
    /// loop walks the input in a fixed-stride pattern that does not branch on
    /// digit values. The throw on invalid hex characters short-circuits and is
    /// therefore variable-time in the failure mode — acceptable because
    /// invalid input is by definition malformed public data, not secret
    /// material.
    /// </para>
    /// </remarks>
    public static SecureBigInteger FromHexadecimal(PinnedPoolArray<char> hex)
    {
        if (hex is null)
        {
            throw new ArgumentNullException(nameof(hex));
        }

        int length = hex.Length;
        if (length == 0)
        {
            throw new ArgumentException(ErrorMessages.ValueCannotBeEmpty, nameof(hex));
        }

        bool isNegative = false;
        int hexStart = 0;
        char first = hex[0];
        if (first == '-')
        {
            isNegative = true;
            hexStart = 1;
        }
        else if (first == '+')
        {
            hexStart = 1;
        }

        // Optional 0x / 0X base prefix. Detected only after the sign so that
        // both "-0xFF" and "0xFF" work; ambiguous shorter inputs like "0" or
        // "0X" alone do not match (length check guards both).
        if (length - hexStart >= 2
            && hex[hexStart] == '0'
            && (hex[hexStart + 1] == 'x' || hex[hexStart + 1] == 'X'))
        {
            hexStart += 2;
        }

        int hexCharCount = length - hexStart;
        if (hexCharCount == 0)
        {
            throw new FormatException(ErrorMessages.NumberFormatSignWithoutDigits);
        }

        int byteCount = (hexCharCount + 1) / 2;
        using var bytes = new PinnedPoolArray<byte>(length: byteCount);

        for (int i = 0; i < hexCharCount; i++)
        {
            char c = hex[hexStart + i];
            int nibble = DecodeHexChar(c);

            // Position from the LSB end; the input walks MSB-first, the byte
            // buffer is little-endian, so the leftmost char ends up in the
            // highest byte index.
            int posFromEnd = hexCharCount - 1 - i;
            int byteIdx = posFromEnd / 2;
            bool highNibble = (posFromEnd & 1) != 0;
            bytes[byteIdx] |= highNibble ? (byte)(nibble << 4) : (byte)nibble;
        }

        return new SecureBigInteger(bytes.PoolArray, byteCount, isNegative);
    }
}
