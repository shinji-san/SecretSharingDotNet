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
/// Inherits the threat-model boundaries of <see cref="SecureBigInteger"/>: protected
/// against passive memory disclosure and equality timing leaks, but the dispatched
/// arithmetic operators are variable-time. See the <c>SecureBigInteger</c> XML doc
/// remarks for the full breakdown and the constant-time-arithmetic future-work note.
/// </remarks>
public sealed class SecureBigIntCalculator : Calculator<SecureBigInteger>
{
    /// <summary>
    /// Indicates whether the instance has been disposed (<c>0</c> = live, <c>1</c> = disposed).
    /// Updated atomically via <see cref="Interlocked.Exchange(ref int, int)"/> so that
    /// concurrent <see cref="Dispose(bool)"/> calls cannot both reach the
    /// <c>this.Value.Dispose()</c> branch.
    /// </summary>
    private int disposed;

    /// <summary>
    /// Lazily-evaluated byte count matching <see cref="ToByteArray"/>'s output length —
    /// i.e. the canonical two's-complement size including any sign-padding sentinel.
    /// Mirrors <see cref="BigIntCalculator"/>'s approach so that consumers like
    /// <c>Share&lt;TNumber&gt;.GetCharCount</c> see the same length on both backends.
    /// </summary>
    private readonly Lazy<int> byteCountLazy;

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
    /// </param>
    public SecureBigIntCalculator(SecureBigInteger val) : base(val ?? 0)
    {
        this.byteCountLazy = this.InitializeByteCountLazy();
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="SecureBigIntCalculator"/> class.
    /// </summary>
    /// <param name="data">byte stream representation of a numeric value</param>
    /// <param name="length">length of the byte stream representation</param>
    public SecureBigIntCalculator(byte[] data, int length) : base(new SecureBigInteger(data, length))
    {
        this.byteCountLazy = this.InitializeByteCountLazy();
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
    public override Calculator<SecureBigInteger> Clone() => new SecureBigIntCalculator(new SecureBigInteger(this.Value));

    /// <summary>
    /// Determines whether this instance and an <paramref name="other"/> specified <see cref="Calculator{SecureBigInteger}"/> instance are equal.
    /// </summary>
    /// <param name="other">The <see cref="Calculator{SecureBigInteger}"/> instance to compare</param>
    /// <returns><see langword="true"/> if the value of the <paramref name="other"/> parameter is the same as the value of this instance; otherwise <see langword="false"/>.
    /// If <paramref name="other"/> is <see langword="null"/>, the method returns <see langword="false"/>.</returns>
    /// <remarks>
    /// This method performs a constant-time comparison of the underlying byte arrays to mitigate timing attacks.
    /// This is an important security feature for cryptographic and security-sensitive applications, as it prevents
    /// attackers from inferring information about the values based on timing differences.
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
    protected override Calculator<SecureBigInteger> Add(SecureBigInteger right) => this.Value + right;

    /// <summary>
    /// Subtracts the current <see cref="SecureBigIntCalculator"/> instance with the <paramref name="right"/>
    /// <see cref="SecureBigIntCalculator"/> instance.
    /// </summary>
    /// <param name="right">Right value to subtract (subtrahend).</param>
    /// <returns>The difference of the current <see cref="SecureBigIntCalculator"/> instance and the <paramref name="right"/>
    /// <see cref="SecureBigIntCalculator"/> instance.</returns>
    protected override Calculator<SecureBigInteger> Subtract(SecureBigInteger right) => this.Value - right;

    /// <summary>
    /// Multiplies the current <see cref="SecureBigIntCalculator"/> instance with the <paramref name="right"/>
    /// <see cref="SecureBigIntCalculator"/> instance.
    /// </summary>
    /// <param name="right">multiplicand</param>
    /// <returns>The product of the current <see cref="SecureBigIntCalculator"/> instance and the <paramref name="right"/>
    /// <see cref="SecureBigIntCalculator"/> instance.</returns>
    protected override Calculator<SecureBigInteger> Multiply(SecureBigInteger right) => this.Value * right;

    /// <summary>
    /// Divides the current <see cref="SecureBigIntCalculator"/> instance with the <paramref name="right"/>
    /// <see cref="SecureBigIntCalculator"/> instance.
    /// </summary>
    /// <param name="right">divisor</param>
    /// <returns>The quotient of the current <see cref="SecureBigIntCalculator"/> instance and the <paramref name="right"/>
    /// <see cref="SecureBigIntCalculator"/> instance.</returns>
    protected override Calculator<SecureBigInteger> Divide(SecureBigInteger right) => this.Value / right;

    /// <summary>
    /// The modulo operation
    /// </summary>
    /// <param name="right">divisor</param>
    /// <returns>The remainder as <see cref="SecureBigIntCalculator"/> instance.</returns>
    protected override Calculator<SecureBigInteger> Modulo(SecureBigInteger right) => this.Value % right;

    /// <summary>
    /// Returns a new <see cref="SecureBigIntCalculator"/> instance whose value is one greater
    /// than this instance. Does not mutate the current instance.
    /// </summary>
    /// <returns>A new instance equal to <c>this + 1</c>.</returns>
    protected override Calculator<SecureBigInteger> Increment()
    {
        using var one = new SecureBigInteger(1);
        return this.Value + one;
    }

    /// <summary>
    /// Returns a new <see cref="SecureBigIntCalculator"/> instance whose value is one less
    /// than this instance. Does not mutate the current instance.
    /// </summary>
    /// <returns>A new instance equal to <c>this - 1</c>.</returns>
    protected override Calculator<SecureBigInteger> Decrement()
    {
        using var one = new SecureBigInteger(1);
        return this.Value - one;
    }

    /// <summary>
    /// Returns the absolute value of the current <see cref="SecureBigIntCalculator"/> object.
    /// </summary>
    /// <returns>The absolute value of this instance.</returns>
    /// <remarks>This instance is greater than or equal to zero, the return value will be this instance.
    /// This instance is lower than zero, the return value will be this instance multiply with minus one.
    /// </remarks>
    public override Calculator<SecureBigInteger> Abs() => this.Value.Abs();

    /// <summary>
    /// Raises this <see cref="SecureBigIntCalculator"/> value to the power of a specified value.
    /// </summary>
    /// <param name="expo">The exponent to raise this <see cref="SecureBigIntCalculator"/> value by.</param>
    /// <returns>The result of raising instance to the <paramref name="expo"/> power.</returns>
    public override Calculator<SecureBigInteger> Pow(int expo) => this.Value.Pow(expo);

    /// <summary>
    /// Gets the number of elements of the byte representation of the <see cref="SecureBigIntCalculator"/> object.
    /// </summary>
    public override int ByteCount => this.byteCountLazy.Value;

    /// <summary>
    /// Builds the lazy producing <see cref="ByteCount"/>. Computes
    /// <c>this.Value.ToByteArray().Length</c> once on first access and caches it,
    /// so consumers that read <see cref="ByteCount"/> repeatedly (e.g.
    /// <c>Share&lt;TNumber&gt;.GetCharCount</c> on every formatting call) do not
    /// re-allocate a pinned buffer per call.
    /// </summary>
    private Lazy<int> InitializeByteCountLazy()
    {
        return new Lazy<int>(() =>
        {
            using var pinnedBytes = this.Value.ToByteArray();
            return pinnedBytes.Length;
        }, LazyThreadSafetyMode.ExecutionAndPublication);
    }

    /// <summary>
    /// Gets the byte representation of the <see cref="SecureBigIntCalculator"/> object.
    /// </summary>
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

    /// <summary>
    /// Releases the resources used by the <see cref="SecureBigIntCalculator"/> instance.
    /// </summary>
    /// <param name="disposing">
    /// A boolean value indicating whether the method is being called
    /// to release both managed and unmanaged resources (true) or only unmanaged resources (false).
    /// </param>
    protected override void Dispose(bool disposing)
    {
        if (Interlocked.Exchange(ref this.disposed, 1) == 1)
        {
            return;
        }

        if (disposing)
        {
            this.Value.Dispose();
        }

        // Release unmanaged resources here
        base.Dispose(disposing);
    }
}