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

#if (!NET8_0_OR_GREATER && !NETSTANDARD2_1_OR_GREATER)
using Extension;
#endif
using Cryptography.SecureArray;
using System;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.CompilerServices;
#if (NET8_0_OR_GREATER || NETSTANDARD2_1_OR_GREATER)
using System.Security.Cryptography;
#endif
using System.Threading;


/// <summary>
/// Represents a secure arbitrary-precision integer with support for basic arithmetic operations.
/// The internal data is securely cleared from memory when the instance is disposed.
/// </summary>
/// <remarks>
/// <para>
/// <b>Threat model.</b> The "secure" qualifier covers a specific subset of side channels:
/// </para>
/// <list type="bullet">
/// <item><description>
/// <b>Protected:</b> passive memory disclosure (the underlying buffer is GC-pinned and wiped
/// with a 3-pass overwrite plus <c>CryptographicOperations.ZeroMemory</c> on dispose, so heap
/// snapshots, swap files, and reuse-after-free cannot recover plaintext); equality leaks
/// (<see cref="Equals(SecureBigInteger)"/> pre-pads to <c>max(left, right)</c> and uses
/// fixed-time comparison, so timing does not leak prefix-match length).
/// </description></item>
/// <item><description>
/// <b>Not protected:</b> timing side channels in arithmetic. <see cref="op_Addition"/>,
/// <see cref="op_Subtraction"/>, <see cref="op_Multiply"/>, <see cref="op_Division"/>,
/// <see cref="op_Modulus"/>, <see cref="Pow"/>, and the comparison
/// operators are variable-time — runtime depends on operand bit length, carry
/// propagation, and quotient-iteration count. An attacker who can measure the runtime of
/// these operations (cross-VM cache attack, browser high-resolution timer, network-RTT
/// measurement on a server endpoint that performs arithmetic on attacker-influenced inputs)
/// can in principle infer magnitude information about secret-derived values.
/// </description></item>
/// </list>
/// <para>
/// Constant-time arithmetic in pure managed .NET is non-trivial and is on the future-work
/// list, not the current contract. Consumers whose threat model includes co-located active
/// timing attackers should layer the operation through a constant-time crypto stack
/// (libsodium-net, hardware-backed enclaves) rather than rely on this type's naming alone.
/// </para>
/// </remarks>
#if DEBUG
[DebuggerDisplay("{ToString(),nq}")]
#else
[DebuggerDisplay("*** Secured Value ***")]
#endif
public sealed class SecureBigInteger : IDisposable, IEquatable<SecureBigInteger>, IComparable<SecureBigInteger>
{
    /// <summary>
    /// The byte array representing the absolute value of the integer in little-endian
    /// order — <c>data[0]</c> is the least-significant byte.
    /// </summary>
    private PinnedPoolArray<byte> data;

    /// <summary>
    /// The actual length of the data in the <see cref="data"/> array.
    /// </summary>
    private int Length
    {
        get => this.data.Length;
        set => this.data.Length = value;
    } 

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
        this.data = new PinnedPoolArray<byte>(1);
        this.data[0] = 0;
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
        if (value == 0)
        {
            this.data = new PinnedPoolArray<byte>(1);
            return;
        }

        this.isNegative = value < 0;
        // unchecked: -long.MinValue overflows back to long.MinValue, whose ulong
        // reinterpretation is 0x8000_0000_0000_0000 — exactly the magnitude we want.
        ulong absoluteValue = unchecked((ulong)(this.isNegative ? -value : value));

        int byteCount = 0;
        ulong temp = absoluteValue;
        while (temp > 0)
        {
            byteCount++;
            temp >>= 8;
        }

        this.data = new PinnedPoolArray<byte>(byteCount);
        for (int i = 0; i < byteCount; i++)
        {
            this.data[i] = (byte)(absoluteValue & 0xFF);
            absoluteValue >>= 8;
        }
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
        if (value == 0)
        {
            this.data = new PinnedPoolArray<byte>(1);
            return;
        }

        this.isNegative = false;

        int byteCount = 0;
        ulong temp = value;
        while (temp > 0)
        {
            byteCount++;
            temp >>= 8;
        }

        this.data = new PinnedPoolArray<byte>(byteCount);
        ulong remaining = value;
        for (int i = 0; i < byteCount; i++)
        {
            this.data[i] = (byte)(remaining & 0xFF);
            remaining >>= 8;
        }
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
        this.data = new PinnedPoolArray<byte>(other.Length);
        Array.Copy(other.data.PoolArray, this.data.PoolArray, other.Length);
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

        if (length == 0)
        {
            this.data = new PinnedPoolArray<byte>(1);
            return;
        }

        this.data = new PinnedPoolArray<byte>(length);
        Array.Copy(data, this.data.PoolArray, length);
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
            this.data = new PinnedPoolArray<byte>(1);
            return;
        }

        var isNegativeRepresentation = IsNegativeRepresentation(data, length);
        this.isNegative = isNegativeRepresentation;
        var trimmedLength = GetActualLength(data, length);
        this.data = new PinnedPoolArray<byte>(trimmedLength);
        if (isNegativeRepresentation)
        {
            using var normalizedData = TwosComplement(data, this.Length);
            Array.Copy(normalizedData.PoolArray, this.data.PoolArray, this.Length);
        }
        else
        {
            Array.Copy(data, this.data.PoolArray, this.Length);
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
    /// Gets the number of bytes used to represent the internal data of the SecureBigInteger.
    /// </summary>
    public int ByteCount
    {
        get
        {
            this.ThrowIfDisposed();
            return this.Length;
        }
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
    /// Constant-time on the magnitude bytes: the sign is observable per the threat
    /// model and may legitimately short-circuit to <see langword="false"/>; the
    /// magnitude check XOR-folds the expected pattern (low byte = 1, all higher
    /// bytes = 0) into a single byte that is compared against zero. The byte-level
    /// length <see cref="Length"/> is a public observable and may bound the loop.
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

            int len = this.Length;
            if (len == 0)
            {
                return false;
            }

            byte acc = (byte)(this.data[0] ^ 1);
            for (int i = 1; i < len; i++)
            {
                acc |= this.data[i];
            }

            return acc == 0;
        }
    }

    /// <summary>
    /// Gets a value indicating whether the current <see cref="SecureBigInteger"/> instance represents an even number.
    /// </summary>
    /// <remarks>
    /// Constant-time bit-test on the magnitude's least-significant byte. The sign flag is
    /// irrelevant: the parity of <c>-x</c> matches the parity of <c>x</c>, and the magnitude
    /// stored here is always non-negative regardless of <c>isNegative</c>.
    /// </remarks>
    public bool IsEven
    {
        get
        {
            this.ThrowIfDisposed();
            return (this.data[0] & 0x01) == 0;
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
            return result;
        }

        var comparison = CompareUnsigned(left, right);
        switch (comparison)
        {
            case 0:
                return new SecureBigInteger(0);
            case > 0:
                result = SubtractUnsigned(left, right);
                result.isNegative = left.isNegative;
                break;
            default:
                result = SubtractUnsigned(right, left);
                result.isNegative = right.isNegative;
                break;
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
            return result;
        }

        // Same sign: the magnitudes determine direction; the result inherits the
        // minuend's sign when |minuend| >= |subtrahend|, and the inverted sign otherwise.
        var comparison = CompareUnsigned(minuend, subtrahend);
        switch (comparison)
        {
            case 0:
                return new SecureBigInteger(0);
            case > 0:
                result = SubtractUnsigned(minuend, subtrahend);
                result.isNegative = minuend.isNegative;
                break;
            default:
                result = SubtractUnsigned(subtrahend, minuend);
                result.isNegative = !minuend.isNegative;
                break;
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

        if (multiplicand.IsZeroInternal() || multiplier.IsZeroInternal())
        {
            return new SecureBigInteger(0);
        }

        var result = MultiplyUnsigned(multiplicand, multiplier);
        result.isNegative = multiplicand.isNegative != multiplier.isNegative;

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
            throw new DivideByZeroException(ErrorMessages.DivisionByZero);
        }

        if (dividend.IsZeroInternal())
        {
            return new SecureBigInteger(0);
        }

        // DivideUnsigned allocates BOTH the quotient (return) and the remainder
        // (out-param) as fresh SecureBigInteger instances. The remainder is not
        // needed here, but must be disposed explicitly — discarding it via
        // `out _` would leak a pinned-pool slot (the finalizer on
        // SecureBigInteger only sets the disposed flag and does not release
        // managed resources, see Dispose(bool)) and delay the secret-data wipe
        // until pool-level finalization runs.
        var quotient = DivideUnsigned(dividend, divisor, out var remainder);
        remainder.Dispose();
        quotient.isNegative = dividend.isNegative != divisor.isNegative;

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
            throw new DivideByZeroException(ErrorMessages.DivisionByZero);
        }

        if (dividend.IsZeroInternal())
        {
            return new SecureBigInteger(0);
        }

        // Symmetric to Divide above: DivideUnsigned allocates both outputs, but
        // here the quotient is the unused half. Dispose it via `using` so that
        // its pinned-pool slot is released and its plaintext bytes wiped on the
        // success path; on a throw between the call and the using-scope-exit
        // (none of the operations in this short tail can throw realistically),
        // the using ensures cleanup as well.
        using var quotient = DivideUnsigned(dividend, divisor, out var remainder);
        remainder.isNegative = dividend.isNegative;
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

        using var srcLimbs = this.ToLimbs();
        int srcLimbCount = this.LimbCount;

        int workLimbCount = srcLimbCount >= outLimbCount + 1 ? srcLimbCount : outLimbCount + 1;
        using var work = new PinnedPoolArray<ulong>(workLimbCount);
        using var scratch = new PinnedPoolArray<ulong>(workLimbCount);

        for (int i = 0; i < srcLimbCount; i++)
        {
            work[i] = srcLimbs[i];
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
        using var mersennePrime = new PinnedPoolArray<ulong>(outLimbCount);
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

            using var negated = new PinnedPoolArray<ulong>(outLimbCount);
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
        var secureBigInteger = new SecureBigInteger(this);
        secureBigInteger.isNegative = false;
        return secureBigInteger;
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
        using var limbs = this.ToLimbs();
        return new SecureBigInteger(limbs, this.LimbCount, !this.isNegative);
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
        if (this.isNegative)
        {
            return TwosComplement(this.data.PoolArray, this.Length);
        }

        bool needsPadding = this.Length > 0 && (this.data[this.Length - 1] & 0x80) != 0;
        var result = new PinnedPoolArray<byte>(needsPadding ? this.Length + 1 : this.Length);
        Array.Copy(this.data.PoolArray, result.PoolArray, this.Length);
        return result;
    }

    #region D2 — ulong-limb interop (transitional dual-rail)

    // The byte-array representation (`this.data`) remains canonical until D9.
    // The methods in this region expose the magnitude as 64-bit limbs in
    // little-endian order so that constant-time operations introduced in
    // D3–D9 can iterate over machine-word limbs instead of bytes — both for
    // performance (Multiply scales O(n²) in the limb width) and to ease the
    // safegcd implementation in D7, which is naturally limb-oriented.
    //
    // The byte-to-limb assembly is explicit (not MemoryMarshal.Cast), so the
    // representation is host-endian-independent: limb[i] stores the byte at
    // magnitude offset (i*8 + j) in bit position (j*8), regardless of CPU
    // endianness.

    /// <summary>
    /// Returns the magnitude of this instance as a freshly allocated sequence of
    /// 64-bit limbs in little-endian order: <c>limb[0]</c> holds magnitude bytes
    /// 0..7, <c>limb[1]</c> holds bytes 8..15, etc. The high limb is zero-padded
    /// if the magnitude byte length is not a multiple of 8. The sign bit is not
    /// included; query <see cref="Sign"/> separately.
    /// </summary>
    /// <returns>
    /// A new <see cref="PinnedPoolArray{T}"/> of <see cref="ulong"/> with
    /// <c>Length == <see cref="LimbCount"/></c>. Caller takes ownership and
    /// must dispose to wipe the buffer.
    /// </returns>
    internal PinnedPoolArray<ulong> ToLimbs()
    {
        this.ThrowIfDisposed();
        int limbCount = this.LimbCount;
        var limbs = new PinnedPoolArray<ulong>(limbCount);
        BytesToLimbs(this.data.PoolArray, this.Length, limbs);
        return limbs;
    }

    /// <summary>
    /// Number of 64-bit limbs required to represent this instance's magnitude.
    /// Always at least 1; equivalent to <c>max(1, ceil(byteLength / 8))</c>.
    /// </summary>
    internal int LimbCount
    {
        get
        {
            this.ThrowIfDisposed();
            int byteLength = this.Length;
            return byteLength <= 0 ? 1 : (byteLength + 7) / 8;
        }
    }

    /// <summary>
    /// Initializes a new instance from a magnitude expressed as 64-bit limbs
    /// (little-endian) plus an explicit sign flag. Inverse of
    /// <see cref="ToLimbs"/>.
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
    /// The constructor securely wipes its transient byte buffer before
    /// returning. Caller retains ownership of <paramref name="limbs"/>.
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

        int byteCapacity = limbCount * 8;
        using var byteBuf = new PinnedPoolArray<byte>(byteCapacity);
        LimbsToBytes(limbs, limbCount, byteBuf.PoolArray);

        int actualByteLength = GetActualLength(byteBuf.PoolArray, byteCapacity);
        this.data = new PinnedPoolArray<byte>(actualByteLength);
        Array.Copy(byteBuf.PoolArray, this.data.PoolArray, actualByteLength);

        this.isNegative = isNegative;
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

    private static void LimbsToBytes(PinnedPoolArray<ulong> limbs, int limbCount, byte[] bytesOut)
    {
        for (int i = 0; i < limbCount; i++)
        {
            ulong limb = limbs[i];
            int offset = i * 8;
            for (int j = 0; j < 8; j++)
            {
                bytesOut[offset + j] = (byte)(limb >> (j * 8));
            }
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
    private static PinnedPoolArray<byte> TwosComplement(byte[] data, int length)
    {
        if (length == 0 || data is null || (length == 1 && data[0] == 0))
        {
            var zeroArray = new PinnedPoolArray<byte>(1);
            zeroArray[0] = 0;
            return zeroArray;
        }

        var twosCompArray = new PinnedPoolArray<byte>(length);
        for (int i = 0; i < length; i++)
        {
            twosCompArray[i] = (byte)~data[i];
        }

        int carry = 1;
        for (int i = 0; i < length && carry != 0; i++)
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
        if (ReferenceEquals(left, right))
        {
            return true;
        }

        if (left is null || right is null)
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

        if (value.Length > 4)
        {
            throw new OverflowException(ErrorMessages.ValueTooLargeForInt);
        }

        uint result = 0;
        for (var i = Math.Min(3, value.Length - 1); i >= 0; i--)
        {
            result = (result << 8) | value.data[i];
        }

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

        if (value.Length > 8)
        {
            throw new OverflowException(ErrorMessages.ValueTooLargeForLong);
        }

        var result = 0UL;
        for (var i = Math.Min(7, value.Length - 1); i >= 0; i--)
        {
            result = result << 8 | value.data[i];
        }

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
        using var leftLimbs = left.ToLimbs();
        using var rightLimbs = right.ToLimbs();
        int leftCount = left.LimbCount;
        int rightCount = right.LimbCount;
        int maxCount = leftCount >= rightCount ? leftCount : rightCount;
        int resultCount = maxCount + 1;

        using var result = new PinnedPoolArray<ulong>(resultCount);
        ulong carry = 0;

        for (int i = 0; i < resultCount; i++)
        {
            ulong l = i < leftCount ? leftLimbs[i] : 0UL;
            ulong r = i < rightCount ? rightLimbs[i] : 0UL;

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
        using var mLimbs = minuend.ToLimbs();
        using var sLimbs = subtrahend.ToLimbs();
        int mCount = minuend.LimbCount;
        int sCount = subtrahend.LimbCount;
        int maxCount = mCount >= sCount ? mCount : sCount;

        using var result = new PinnedPoolArray<ulong>(maxCount);
        ulong borrow = 0;

        for (int i = 0; i < maxCount; i++)
        {
            ulong m = i < mCount ? mLimbs[i] : 0UL;
            ulong s = i < sCount ? sLimbs[i] : 0UL;

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
        using var leftLimbs = left.ToLimbs();
        using var rightLimbs = right.ToLimbs();
        int leftCount = left.LimbCount;
        int rightCount = right.LimbCount;
        int resultCount = leftCount + rightCount;

        using var result = new PinnedPoolArray<ulong>(resultCount);

        for (int i = 0; i < leftCount; i++)
        {
            ulong carry = 0;
            ulong leftLimb = leftLimbs[i];
            for (int j = 0; j < rightCount; j++)
            {
                MultiplyToHighLow(leftLimb, rightLimbs[j], out ulong productHigh, out ulong productLow);

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
        using var dividendLimbs = dividend.ToLimbs();
        using var divisorLimbs = divisor.ToLimbs();
        int dividendLimbCount = dividend.LimbCount;
        int divisorLimbCount = divisor.LimbCount;
        int totalBits = dividendLimbCount * 64;

        // Pre-subtract maximum: shift-left of (divisor - 1) plus an OR-in bit
        // gives 2*(divisor - 1) + 1 < 2*divisor, which fits in
        // divisor.LimbCount + 1 limbs. The +1 absorbs the shift overflow from
        // the high limb of the post-shift value.
        int remainderLimbCount = divisorLimbCount + 1;
        using var rem = new PinnedPoolArray<ulong>(remainderLimbCount);
        using var quot = new PinnedPoolArray<ulong>(dividendLimbCount);

        for (int bit = totalBits - 1; bit >= 0; bit--)
        {
            ShiftLeftByOneBitInPlace(rem, remainderLimbCount);

            // OR in the dividend bit at position `bit` (LSB-indexed; bit/64
            // selects the limb, bit%64 the bit within it).
            ulong dividendBit = (dividendLimbs[bit >> 6] >> (bit & 63)) & 1UL;
            rem[0] |= dividendBit;

            ulong borrow = SubtractInPlace(rem, remainderLimbCount, divisorLimbs, divisorLimbCount);

            // canSubtract = NOT borrow (1 if rem ≥ divisor, 0 if rem < divisor).
            // undoMask    = all-ones if the trial subtract underflowed (need to
            // revert), zero otherwise.
            ulong canSubtract = borrow ^ 1UL;
            ulong undoMask = 0UL - borrow;

            AddMaskedInPlace(rem, remainderLimbCount, divisorLimbs, divisorLimbCount, undoMask);

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
        using var leftLimbs = left.ToLimbs();
        using var rightLimbs = right.ToLimbs();
        int leftCount = left.LimbCount;
        int rightCount = right.LimbCount;
        int maxCount = leftCount >= rightCount ? leftCount : rightCount;

        long result = 0;
        for (int i = 0; i < maxCount; i++)
        {
            ulong l = i < leftCount ? leftLimbs[i] : 0UL;
            ulong r = i < rightCount ? rightLimbs[i] : 0UL;

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
    /// Compares two unsigned byte arrays representing large integer values.
    /// </summary>
    /// <param name="left">The byte array representing the first unsigned integer.</param>
    /// <param name="leftLen">The number of significant bytes in the first unsigned integer.</param>
    /// <param name="right">The byte array representing the second unsigned integer.</param>
    /// <param name="rightLen">The number of significant bytes in the second unsigned integer.</param>
    /// <returns>
    /// Returns 1 if the first unsigned integer is greater than the second,
    /// -1 if the first unsigned integer is less than the second, and 0 if they are equal.
    /// </returns>
    private static int CompareUnsigned(byte[] left, int leftLen, byte[] right, int rightLen)
    {
        if (leftLen > rightLen)
        {
            return 1;
        }

        if (leftLen < rightLen)
        {
            return -1;
        }

        for (var i = leftLen - 1; i >= 0; i--)
        {
            if (left[i] > right[i])
            {
                return 1;
            }

            if (left[i] < right[i])
            {
                return -1;
            }
        }

        return 0;
    }

    /// <summary>
    /// Removes leading zeros from the internal representation of the <see cref="SecureBigInteger"/> instance.
    /// Adjusts the length property to accurately reflect the number of significant bytes.
    /// </summary>
    private void TrimLeadingZerosInPlace()
    {
        this.Length = GetActualLength(this);
    }

    /// <summary>
    /// Computes the actual length of the given byte array excluding leading zero bytes.
    /// </summary>
    /// <param name="data">The byte array for which the actual length is to be determined.</param>
    /// <param name="length">The length of the byte array to consider.</param>
    /// <returns>The actual length of the byte array, excluding leading zero bytes. If the array contains only zeros,
    /// it returns 1.</returns>
    private static int GetActualLength(byte[] data, int length)
    {
        for (var i = length - 1; i >= 0; i--)
        {
            if (data[i] != 0)
            {
                return i + 1;
            }
        }

        return 1;
    }

    /// <summary>
    /// Calculates the actual length of significant data in the specified <see cref="SecureBigInteger"/> instance,
    /// excluding leading zeros.
    /// </summary>
    /// <param name="secureBigInteger">The <see cref="SecureBigInteger"/> instance for which to calculate the actual length.</param>
    /// <returns>The number of significant bytes in the <paramref name="secureBigInteger"/> instance.</returns>
    private static int GetActualLength(SecureBigInteger secureBigInteger)
    {
        return GetActualLength(secureBigInteger.data.PoolArray, secureBigInteger.Length);
    }

    /// <summary>
    /// Determines whether the current <see cref="SecureBigInteger"/> instance represents the value zero.
    /// </summary>
    /// <returns>
    /// True if the instance represents the value zero; otherwise, false.
    /// </returns>
    /// <summary>
    /// Returns <see langword="true"/> iff the magnitude bytes are all zero,
    /// independent of the sign flag.
    /// </summary>
    /// <remarks>
    /// Branchless on the magnitude: ORs every byte of <see cref="data"/> into a
    /// single accumulator, then compares against zero. The <c>acc == 0</c>
    /// final test compiles to <c>setz</c> on x86 RyuJIT, branchless. Loop bound
    /// is <see cref="Length"/>, a public observable.
    /// </remarks>
    private bool IsZeroInternal()
    {
        byte acc = 0;
        int len = this.Length;
        for (int i = 0; i < len; i++)
        {
            acc |= this.data[i];
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
    /// <param name="disposing">A boolean value indicating whether to release managed resources (true) or
    /// only unmanaged resources (false).</param>
    private void Dispose(bool disposing)
    {
        if (Interlocked.Exchange(ref this.disposed, 1) == 1)
        {
            return;
        }

        if (!disposing)
        {
            return;
        }

        // Release managed resources if any
        this.data?.Dispose();
        this.data = null;
    }

    /// <summary>
    /// Determines whether the current instance is equal to another <see cref="SecureBigInteger"/> instance.
    /// </summary>
    /// <param name="other">The <see cref="SecureBigInteger"/> instance to compare with the current instance.</param>
    /// <returns><see langword="true"/> if the current instance is equal to the <paramref name="other"/> instance;
    /// otherwise, <see langword="false"/>.</returns>
    /// <remarks>
    /// <para>
    /// The byte-by-byte comparison is constant-time per the operands' configured byte lengths.
    /// Both magnitudes are first zero-padded into pinned pool buffers of size
    /// <c>max(this.Length, other.Length)</c>, then compared with a fixed-time primitive that
    /// runs the full padded length on every call — there is no early exit on the first
    /// differing byte and no length-mismatch fast path.
    /// </para>
    /// <para>
    /// The sign flag is folded into the result via a non-short-circuiting bitwise AND, so the
    /// runtime does not branch on whether the signs match before the byte compare. The
    /// remaining length-only observable (the loop runs <c>max(this.Length, other.Length)</c>
    /// iterations) reflects already-public buffer sizing, not byte content.
    /// </para>
    /// <para>
    /// Pre-padding to equal length is what makes this strict CT on every target framework.
    /// On legacy targets <see cref="Extension.ArrayExtensions.FixedTimeEquals(byte[], byte[], int, int)"/>
    /// would tolerate unequal lengths via internal zero-padding, but that introduces
    /// length-dependent ternaries and memory-access asymmetries inside its hot loop that we
    /// avoid here by feeding both arrays at the same length.
    /// </para>
    /// </remarks>
    [SuppressMessage("SonarQube", "S2178",
        Justification = "Non-short-circuit AND is intentional in this constant-time context. " +
                        "Using && would emit a conditional branch on `bytesEqual` to skip the " +
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

        if (ReferenceEquals(this, other))
        {
            return true;
        }

        this.ThrowIfDisposed();
        other.ThrowIfDisposed();

        bool signsEqual = this.isNegative == other.isNegative;

        int maxLen = Math.Max(this.Length, other.Length);
        using var leftBuf = new PinnedPoolArray<byte>(maxLen);
        using var rightBuf = new PinnedPoolArray<byte>(maxLen);
        Array.Clear(leftBuf.PoolArray, 0, maxLen);
        Array.Clear(rightBuf.PoolArray, 0, maxLen);
        Array.Copy(this.data.PoolArray, leftBuf.PoolArray, this.Length);
        Array.Copy(other.data.PoolArray, rightBuf.PoolArray, other.Length);

#if (NET8_0_OR_GREATER || NETSTANDARD2_1_OR_GREATER)
        bool bytesEqual = CryptographicOperations.FixedTimeEquals(
            leftBuf.PoolArray.AsSpan(0, maxLen),
            rightBuf.PoolArray.AsSpan(0, maxLen));
#else
        bool bytesEqual = leftBuf.PoolArray.FixedTimeEquals(rightBuf.PoolArray, maxLen, maxLen);
#endif

        return bytesEqual & signsEqual;
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
    /// Returns the hash code for the current instance of the <see cref="SecureBigInteger"/> class.
    /// </summary>
    /// <returns>An integer representing the hash code of the current instance.</returns>
    [SuppressMessage("ReSharper", "NonReadonlyMemberInGetHashCode", Justification = "Fields are not externally mutable. Fields are internally mutable only for creation purposes.")]
    [SuppressMessage("SonarQube", "S2328", Justification = "Fields are not externally mutable. Fields are internally mutable only for creation purposes.")]
    public override int GetHashCode()
    {
        this.ThrowIfDisposed();
#if NETSTANDARD2_1_OR_GREATER || NET8_0_OR_GREATER
        var hash = new HashCode();
        hash.Add(this.Sign);
        hash.Add(this.Length);
#if NET8_0_OR_GREATER
        hash.AddBytes(this.data.PoolArray.AsSpan(0, this.Length));
#else
        for (int i = 0; i < this.Length; i++)
        {
            hash.Add(this.data[i]);
        }
#endif
        return hash.ToHashCode();
#else
        unchecked
        {
            var hash = 17;
            hash = hash * 31 + this.Sign.GetHashCode();
            hash = hash * 31 + this.Length.GetHashCode();
            for (int i = 0; i < this.Length; i++)
            {
                hash = hash * 31 + this.data[i].GetHashCode();
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

        int comparison = CompareUnsigned(this.data.PoolArray, this.Length, other.data.PoolArray, other.Length);
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
            while (CompareUnsigned(temp.data.PoolArray, temp.Length, zero.data.PoolArray, 1) > 0)
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
            var zeroArray = new PinnedPoolArray<char>(1);
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
            result = new PinnedPoolArray<char>(totalLength);
            var index = totalLength - 1;

            temp = new SecureBigInteger(this);
            temp.isNegative = false;
            using var zero = new SecureBigInteger(0);
            using var ten = new SecureBigInteger(10);

            while (CompareUnsigned(temp.data.PoolArray, temp.Length, zero.data.PoolArray, 1) > 0)
            {
                var quotient = DivideUnsigned(temp, ten, out var rem);
                try
                {
                    result[index--] = (char)(DigitOffset + rem.data[0]);
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

        var hexLength = this.Length * 2;
        var totalLength = this.isNegative ? hexLength + 1 : hexLength;
        var result = new PinnedPoolArray<char>(totalLength);
        var index = 0;

        if (this.isNegative)
        {
            result[index++] = '-';
        }

        for (int i = this.Length - 1; i >= 0; i--)
        {
            byte b = this.data[i];
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
        using var bytes = new PinnedPoolArray<byte>(byteCount);

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
