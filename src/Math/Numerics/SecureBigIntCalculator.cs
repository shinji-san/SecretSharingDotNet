// ----------------------------------------------------------------------------
// <copyright file="SecureBigIntCalculator.cs" company="Private">
// Copyright (c) 2022 All Rights Reserved
// </copyright>
// <author>Sebastian Walther</author>
// <date>08/20/2022 02:34:00 PM</date>
// ----------------------------------------------------------------------------

#region License
// ----------------------------------------------------------------------------
// Copyright 2022 Sebastian Walther
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
using System.Threading;

/// <summary>
/// <see cref="Calculator"/> implementation of <see cref="SecureBigInteger"/>.
/// </summary>
/// <remarks>
/// <para>
/// Inherits the threat-model boundaries of <see cref="SecureBigInteger"/>: protected
/// against passive memory disclosure and with constant-time arithmetic / equality
/// primitives. See the <c>SecureBigInteger</c> XML doc remarks for the full
/// breakdown including the <see cref="SecureBigInteger.Pow"/> exponent-is-public
/// caveat.
/// </para>
/// <para>
/// <b>Disposed-state propagation.</b> Every accessor (<see cref="IsZero"/>,
/// <see cref="IsOne"/>, <see cref="IsEven"/>, <see cref="Sign"/>,
/// <see cref="ByteCount"/>, <see cref="ByteRepresentation"/>) and every
/// arithmetic operator routes through <see cref="Calculator{TNumber}.Value"/> and
/// therefore propagates <see cref="ObjectDisposedException"/> from the wrapped
/// <see cref="SecureBigInteger"/> once <see cref="Dispose(bool)"/> has run.
/// </para>
/// </remarks>
internal sealed class SecureBigIntCalculator : Calculator<SecureBigInteger>
{
    /// <summary>
    /// Indicates whether the instance has been disposed (<c>0</c> = live, <c>1</c> = disposed).
    /// Updated atomically via <see cref="Interlocked.Exchange(ref int, int)"/> so that
    /// concurrent <see cref="Dispose(bool)"/> calls cannot both reach the
    /// <c>this.Value.Dispose()</c> branch.
    /// </summary>
    private int disposed;

    /// <summary>
    /// Initializes a new instance of the <see cref="SecureBigIntCalculator"/> class.
    /// </summary>
    /// <param name="val">
    /// Numeric value. <see langword="null"/> is interpreted as zero — this fallback
    /// is required to support <see cref="Calculator{TNumber}.Zero"/> for the
    /// reference-type <see cref="SecureBigInteger"/> backend, where
    /// <c>default(TNumber)</c> evaluates to <see langword="null"/> and the implicit
    /// <see cref="SecureBigInteger"/>-to-<see cref="Calculator{TNumber}"/> conversion
    /// routes through this constructor.
    /// <para>
    /// The constructor takes a <b>defensive deep copy</b> of <paramref name="val"/>
    /// via <see cref="SecureBigInteger(SecureBigInteger)"/>; the caller retains
    /// ownership of the passed-in instance and is responsible for disposing it
    /// independently. Required because <see cref="Dispose(bool)"/> wipes
    /// <see cref="Calculator{TNumber}.Value"/> — without the defensive copy any
    /// <c>using var calc = (Calculator&lt;SecureBigInteger&gt;)someValue;</c> idiom
    /// (e.g. the implicit <see cref="SecureBigInteger"/>-to-<c>Secret</c> wrapping
    /// operator) would destroy the caller's instance on calculator dispose.
    /// </para>
    /// </param>
    public SecureBigIntCalculator(SecureBigInteger val)
        : base(val is null ? new SecureBigInteger() : new SecureBigInteger(val))
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="SecureBigIntCalculator"/> class.
    /// </summary>
    /// <param name="data">byte stream representation of a numeric value</param>
    /// <param name="length">length of the byte stream representation</param>
    public SecureBigIntCalculator(byte[] data, int length) : base(new SecureBigInteger(data, length))
    {
    }

    /// <summary>
    /// Finalizes an instance of the <see cref="SecureBigIntCalculator"/> class.
    /// </summary>
    ~SecureBigIntCalculator()
    {
        this.Dispose(false);
    }

    /// <summary>
    /// Creates a new instance of the <see cref="SecureBigIntCalculator"/> class with the same value as the current instance.
    /// </summary>
    /// <returns>A new <see cref="Calculator{SecureBigInteger}"/> object that is a copy of the current instance.</returns>
    public override Calculator<SecureBigInteger> Clone() => new SecureBigIntCalculator(this.Value);

    /// <summary>
    /// Determines whether this instance and an <paramref name="other"/> specified <see cref="Calculator{SecureBigInteger}"/> instance are equal.
    /// </summary>
    /// <param name="other">The <see cref="Calculator{SecureBigInteger}"/> instance to compare</param>
    /// <returns><see langword="true"/> if the value of the <paramref name="other"/> parameter is the same as the value of this instance; otherwise <see langword="false"/>.
    /// If <paramref name="other"/> is <see langword="null"/>, the method returns <see langword="false"/>.</returns>
    /// <remarks>
    /// Delegates to <see cref="SecureBigInteger.Equals(SecureBigInteger)"/>, which performs a
    /// constant-time limb-by-limb comparison: both magnitudes are zero-padded to
    /// <c>max(left.LimbCount, right.LimbCount)</c> ulong limbs and fed to the
    /// fixed-time <c>FixedTimeLimbsEqual</c> XOR-OR-fold primitive — no early exit on the
    /// first differing limb and no length-mismatch fast path. The sign flag is folded into
    /// the result via a non-short-circuiting bitwise AND. The only remaining length
    /// observable (loop iteration count) reflects the already-public limb-buffer size,
    /// not limb content.
    /// </remarks>
    public override bool Equals(Calculator<SecureBigInteger> other)
    {
        return other is not null && this.Value.Equals(other.Value);
    }

    /// <summary>
    /// This method represents the Greater Than operator.
    /// </summary>
    /// <param name="right">right-hand operand</param>
    /// <returns>This method returns <see langword="true"/> if this instance is greater than the <paramref name="right"/> instance, <see langword="false"/> otherwise.</returns>
    protected override bool GreaterThan(SecureBigInteger right) => this.Value > right;

    /// <summary>
    /// This method represents the Lower Than operator.
    /// </summary>
    /// <param name="right">right-hand operand</param>
    /// <returns>This method returns <see langword="true"/> if this instance is less than the <paramref name="right"/> instance, <see langword="false"/> otherwise.</returns>
    protected override bool LowerThan(SecureBigInteger right) => this.Value < right;

    /// <summary>
    /// This method represents the Greater Than Or Equal To operator.
    /// </summary>
    /// <param name="right">right-hand operand</param>
    /// <returns>This method returns <see langword="true"/> if this instance is greater than or equal to the <paramref name="right"/> instance, <see langword="false"/> otherwise.</returns>
    protected override bool EqualOrGreaterThan(SecureBigInteger right) => this.Value >= right;

    /// <summary>
    /// This method represents the Lower Than Or Equal To operator.
    /// </summary>
    /// <param name="right">right-hand operand</param>
    /// <returns>This method returns <see langword="true"/> if this instance is less than or equal to the <paramref name="right"/> instance, <see langword="false"/> otherwise.</returns>
    protected override bool EqualOrLowerThan(SecureBigInteger right) => this.Value <= right;

    /// <summary>
    /// Compares this instance to a second <see cref="Calculator{SecureBigInteger}"/> and returns an integer that
    /// indicates whether the value of this instance is less than, equal to, or greater than the value of the specified object.
    /// </summary>
    /// <param name="other">The object to compare</param>
    /// <returns>A signed integer value that indicates the relationship of this instance to <paramref name="other"/>parameter</returns>
    public override int CompareTo(Calculator<SecureBigInteger> other)
    {
        return this.Value.CompareTo(other?.Value ?? throw new ArgumentNullException(nameof(other)));
    }

    /// <summary>
    /// Adds the current <see cref="SecureBigIntCalculator"/> instance with the <paramref name="right"/>
    /// <see cref="SecureBigIntCalculator"/> instance.
    /// </summary>
    /// <param name="right">Right value to add (right summand).</param>
    /// <returns>The sum of the current <see cref="SecureBigIntCalculator"/> instance and the <paramref name="right"/>
    /// <see cref="SecureBigIntCalculator"/> instance.</returns>
    /// <remarks>
    /// The intermediate <see cref="SecureBigInteger"/> sum is held in a <c>using</c> local so the
    /// <c>SecureBigInteger → Calculator&lt;SecureBigInteger&gt;</c> implicit conversion (which
    /// deep-copies via <see cref="SecureBigIntCalculator(SecureBigInteger)"/>) runs before the
    /// finally block wipes the temporary's pinned limb buffer. Without the <c>using</c> the
    /// pinned plaintext intermediate would remain reachable until finalisation.
    /// </remarks>
    protected override Calculator<SecureBigInteger> Add(SecureBigInteger right)
    {
        using var sum = this.Value + right;
        return sum;
    }

    /// <summary>
    /// Subtracts the current <see cref="SecureBigIntCalculator"/> instance with the <paramref name="right"/>
    /// <see cref="SecureBigIntCalculator"/> instance.
    /// </summary>
    /// <param name="right">Right value to subtract (subtrahend).</param>
    /// <returns>The difference of the current <see cref="SecureBigIntCalculator"/> instance and the <paramref name="right"/>
    /// <see cref="SecureBigIntCalculator"/> instance.</returns>
    /// <remarks>See <see cref="Add"/> for the dispose-temporary-before-finalisation rationale.</remarks>
    protected override Calculator<SecureBigInteger> Subtract(SecureBigInteger right)
    {
        using var difference = this.Value - right;
        return difference;
    }

    /// <summary>
    /// Multiplies the current <see cref="SecureBigIntCalculator"/> instance with the <paramref name="right"/>
    /// <see cref="SecureBigIntCalculator"/> instance.
    /// </summary>
    /// <param name="right">multiplicand</param>
    /// <returns>The product of the current <see cref="SecureBigIntCalculator"/> instance and the <paramref name="right"/>
    /// <see cref="SecureBigIntCalculator"/> instance.</returns>
    /// <remarks>See <see cref="Add"/> for the dispose-temporary-before-finalisation rationale.</remarks>
    protected override Calculator<SecureBigInteger> Multiply(SecureBigInteger right)
    {
        using var product = this.Value * right;
        return product;
    }

    /// <summary>
    /// Divides the current <see cref="SecureBigIntCalculator"/> instance with the <paramref name="right"/>
    /// <see cref="SecureBigIntCalculator"/> instance.
    /// </summary>
    /// <param name="right">divisor</param>
    /// <returns>The quotient of the current <see cref="SecureBigIntCalculator"/> instance and the <paramref name="right"/>
    /// <see cref="SecureBigIntCalculator"/> instance.</returns>
    /// <remarks>See <see cref="Add"/> for the dispose-temporary-before-finalisation rationale.</remarks>
    protected override Calculator<SecureBigInteger> Divide(SecureBigInteger right)
    {
        using var quotient = this.Value / right;
        return quotient;
    }

    /// <summary>
    /// The modulo operation
    /// </summary>
    /// <param name="right">divisor</param>
    /// <returns>The remainder as <see cref="SecureBigIntCalculator"/> instance.</returns>
    /// <remarks>See <see cref="Add"/> for the dispose-temporary-before-finalisation rationale.</remarks>
    protected override Calculator<SecureBigInteger> Modulo(SecureBigInteger right)
    {
        using var remainder = this.Value % right;
        return remainder;
    }

    /// <summary>
    /// Returns a new <see cref="SecureBigIntCalculator"/> instance whose value is one greater
    /// than this instance. Does not mutate the current instance.
    /// </summary>
    /// <returns>A new instance equal to <c>this + 1</c>.</returns>
    protected override Calculator<SecureBigInteger> Increment()
    {
        using var one = new SecureBigInteger(1);
        using var sum = this.Value + one;
        return sum;
    }

    /// <summary>
    /// Returns a new <see cref="SecureBigIntCalculator"/> instance whose value is one less
    /// than this instance. Does not mutate the current instance.
    /// </summary>
    /// <returns>A new instance equal to <c>this - 1</c>.</returns>
    protected override Calculator<SecureBigInteger> Decrement()
    {
        using var one = new SecureBigInteger(1);
        using var difference = this.Value - one;
        return difference;
    }

    /// <summary>
    /// Returns the absolute value of the current <see cref="SecureBigIntCalculator"/> object.
    /// </summary>
    /// <returns>The absolute value of this instance.</returns>
    /// <remarks>This instance is greater than or equal to zero, the return value will be this instance.
    /// This instance is lower than zero, the return value will be this instance multiply with minus one.
    /// See <see cref="Add"/> for the dispose-temporary-before-finalisation rationale.
    /// </remarks>
    public override Calculator<SecureBigInteger> Abs()
    {
        using var abs = this.Value.Abs();
        return abs;
    }

    /// <summary>
    /// Raises this <see cref="SecureBigIntCalculator"/> value to the power of a specified value.
    /// </summary>
    /// <param name="expo">The exponent to raise this <see cref="SecureBigIntCalculator"/> value by.
    /// Must be treated as public: <see cref="SecureBigInteger.Pow"/> is variable-time on the
    /// exponent value (iteration count is <c>O(log₂(expo))</c>). Callers must not pass
    /// secret-derived exponents through this method. The per-iteration arithmetic on the
    /// secret base remains constant-time on the public bit length.</param>
    /// <returns>The result of raising instance to the <paramref name="expo"/> power.</returns>
    /// <remarks>See <see cref="Add"/> for the dispose-temporary-before-finalisation rationale.</remarks>
    public override Calculator<SecureBigInteger> Pow(int expo)
    {
        using var power = this.Value.Pow(expo);
        return power;
    }

    /// <summary>
    /// Reduces this value modulo <c>2^<paramref name="mersenneExponent"/> - 1</c>
    /// using the constant-time fold algorithm in <see cref="SecureBigInteger.MersenneModulo"/>.
    /// </summary>
    /// <param name="mersenneExponent">Positive Mersenne exponent.</param>
    /// <exception cref="ArgumentOutOfRangeException">
    /// <paramref name="mersenneExponent"/> is not positive.
    /// </exception>
    /// <exception cref="ArgumentException">The current instance is negative.</exception>
    /// <remarks>See <see cref="Add"/> for the dispose-temporary-before-finalisation rationale.</remarks>
    public override Calculator<SecureBigInteger> MersenneModulo(int mersenneExponent)
    {
        using var reduced = this.Value.MersenneModulo(mersenneExponent);
        return reduced;
    }

    /// <summary>
    /// Gets the length of the byte representation of the <see cref="SecureBigIntCalculator"/>
    /// object — i.e. <c>ByteRepresentation.Length</c> without materialising the buffer.
    /// </summary>
    /// <remarks>
    /// Delegates to <see cref="SecureBigInteger.SerializedByteCount"/>, which computes
    /// the serialized two's-complement length analytically from the limb state. No
    /// <see cref="PinnedPoolArray{T}"/> allocation per access; the
    /// <c>Calculator.ByteCount == ByteRepresentation.Length</c> invariant relied on by
    /// <c>Share&lt;TNumber&gt;.GetCharCount</c> is preserved.
    /// </remarks>
    public override int ByteCount => this.Value.SerializedByteCount;

    /// <summary>
    /// Gets the byte representation of the <see cref="SecureBigIntCalculator"/> object.
    /// </summary>
    /// <remarks>
    /// Each access allocates a <b>fresh</b> <see cref="PinnedPoolArray{T}"/> via
    /// <see cref="SecureBigInteger.ToByteArray"/>. The caller takes ownership and is
    /// responsible for disposing the returned buffer — failing to dispose returns the
    /// underlying pool array on finalisation rather than promptly, leaving pinned
    /// plaintext reachable longer than necessary.
    /// </remarks>
    public override PinnedPoolArray<byte> ByteRepresentation => this.Value.ToByteArray();

    /// <summary>
    /// Gets a value indicating whether the current <see cref="SecureBigIntCalculator"/> object is zero (0).
    /// </summary>
    public override bool IsZero => this.Value.IsZero;

    /// <summary>
    /// Gets a value indicating whether the current <see cref="SecureBigIntCalculator"/> object is one (1).
    /// </summary>
    public override bool IsOne => this.Value.IsOne;

    /// <summary>
    /// Gets a value indicating whether the current <see cref="SecureBigIntCalculator"/> object is an even number.
    /// </summary>
    public override bool IsEven => this.Value.IsEven;

    /// <summary>
    /// Gets a number that indicates the sign (negative, positive, or zero) of the current <see cref="SecureBigIntCalculator"/> object.
    /// </summary>
    public override int Sign => this.Value.Sign;

    /// <summary>
    /// Converts the numeric value of the current <see cref="SecureBigIntCalculator"/> object to its equivalent string representation.
    /// </summary>
    /// <returns>The <see cref="System.String"/> representation of the current <see cref="SecureBigIntCalculator"/> value.</returns>
    public override string ToString() => this.Value.ToString();

    /// <inheritdoc/>
    /// <remarks>
    /// Returns <c>new SecureBigInteger(this.Value)</c> via the copy constructor so
    /// the caller owns an independent pinned-limb buffer. Required because
    /// <see cref="Dispose(bool)"/> disposes <see cref="Calculator{TNumber}.Value"/>
    /// directly — without this deep copy, the implicit <c>Secret&lt;SecureBigInteger&gt;
    /// → SecureBigInteger</c> cast would hand the caller a reference whose limb
    /// buffer is wiped and returned to the pool before they can read it.
    /// </remarks>
    protected internal override SecureBigInteger ExtractValue() => new SecureBigInteger(this.Value);

    /// <summary>
    /// Releases the resources used by the <see cref="SecureBigIntCalculator"/> instance.
    /// </summary>
    /// <param name="disposing">
    /// A boolean value indicating whether the method is being called from the explicit
    /// <see cref="IDisposable.Dispose"/> path (<see langword="true"/>) or the finalizer
    /// (<see langword="false"/>).
    /// </param>
    /// <remarks>
    /// Both paths wipe the wrapped <see cref="SecureBigInteger"/>. The standard
    /// "skip managed resources in the finalizer" guidance is rejected here for the
    /// same reason as <see cref="SecureBigInteger.Dispose()"/>: deferring the wipe
    /// until <see cref="SecureBigInteger"/>'s own finalizer eventually runs creates a
    /// non-deterministic window during which pinned plaintext stays reachable.
    /// <see cref="SecureBigInteger.Dispose()"/> is finalizer-safe and idempotent, so
    /// double-cascade (this finalizer plus <see cref="SecureBigInteger"/>'s own
    /// finalizer) short-circuits on the second call.
    /// </remarks>
    protected override void Dispose(bool disposing)
    {
        if (Interlocked.Exchange(ref this.disposed, 1) == 1)
        {
            return;
        }

        // Wipe pinned plaintext on both Dispose() and finalizer paths to close the
        // window between SecureBigIntCalculator finalisation and SecureBigInteger's
        // own finalizer. SecureBigInteger.Dispose() is finalizer-safe and idempotent.
        this.Value?.Dispose();

        base.Dispose(disposing);
    }
}