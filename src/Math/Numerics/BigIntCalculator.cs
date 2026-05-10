// ----------------------------------------------------------------------------
// <copyright file="BigIntCalculator.cs" company="Private">
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
#if (!NET8_0_OR_GREATER && !NETSTANDARD2_1_OR_GREATER)
using Extension;
#endif
using System;
using System.Numerics;
#if (NET8_0_OR_GREATER || NETSTANDARD2_1_OR_GREATER)
using System.Security.Cryptography;
#endif
using System.Threading;

/// <summary>
/// <see cref="Calculator"/> implementation of <see cref="System.Numerics.BigInteger"/>
/// </summary>
public sealed class BigIntCalculator : Calculator<BigInteger>
{
    /// <summary>
    /// Lazily computes and gets the number of bytes allocated by the byte-array representation
    /// of the <see cref="BigIntCalculator"/> object. This property ensures the computation is
    /// performed only once and then cached for subsequent calls during the instance lifecycle.
    /// </summary>
    private readonly Lazy<int> byteCountLazy;

    /// <summary>
    /// Initializes a new instance of the <see cref="BigIntCalculator"/> class.
    /// </summary>
    /// <param name="val">Numeric value</param>
    public BigIntCalculator(BigInteger val) : base(val)
    {
        this.byteCountLazy = this.InitializeByteCountLazy();
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="BigIntCalculator"/> class.
    /// </summary>
    /// <param name="data">byte stream representation of a numeric value</param>
    /// <param name="length">length of the byte stream representation</param>
#if (NET8_0_OR_GREATER || NETSTANDARD2_1_OR_GREATER)
    public BigIntCalculator(byte[] data, int length) : base(new BigInteger(data.AsSpan(0, length)))
#else
    public BigIntCalculator(byte[] data, int length) : base(CreateBigInteger(data, length))
#endif
    {
        this.byteCountLazy = this.InitializeByteCountLazy();
    }

#if (!NET8_0_OR_GREATER && !NETSTANDARD2_1_OR_GREATER)
    public static BigInteger CreateBigInteger(byte[] buffer, int length)
    {
    if (buffer.Length == length)
    {
        return new BigInteger(buffer);
    }

    byte[] slice = new byte[length];
    Buffer.BlockCopy(buffer, 0, slice, 0, length);
    return new BigInteger(slice);
    }
#endif

    /// <summary>
    /// Finalizes an instance of the <see cref="BigIntCalculator"/> class.
    /// </summary>
    ~BigIntCalculator()
    {
        this.Dispose(false);
    }

    /// <summary>
    /// Returns a deep copy of the current <see cref="BigIntCalculator"/> instance.
    /// </summary>
    /// <returns>A new <see cref="Calculator{BigInteger}"/> with an independent
    /// <see cref="Lazy{T}"/> byte-count cache; mutating the clone's
    /// <see cref="Calculator{TNumber}.Value"/> does not affect the original's
    /// cached <see cref="ByteCount"/>.</returns>
    public override Calculator<BigInteger> Clone() => new BigIntCalculator(this.Value);

    /// <summary>
    /// Determines whether this instance and an <paramref name="other"/> specified <see cref="Calculator{BigInteger}"/> instance are equal.
    /// </summary>
    /// <param name="other">The <see cref="Calculator{BigInteger}"/> instance to compare</param>
    /// <returns><see langword="true"/> if the value of the <paramref name="other"/> parameter is the same as the value of this instance; otherwise <see langword="false"/>.
    /// If <paramref name="other"/> is <see langword="null"/>, the method returns <see langword="false"/>.</returns>
    /// <remarks>
    /// This method performs a constant-time comparison of the underlying byte arrays to mitigate timing attacks.
    /// This is an important security feature for cryptographic and security-sensitive applications, as it prevents
    /// attackers from inferring information about the values based on timing differences.
    /// </remarks>
    public override bool Equals(Calculator<BigInteger> other)
    {
        if (other is null)
        {
            return false;
        }

        byte[] valueLeft = null;
        byte[] valueRight = null;
        bool result;
        try
        {
            valueLeft = this.Value.ToByteArray();
            valueRight = other.Value.ToByteArray();
#if (NET8_0_OR_GREATER || NETSTANDARD2_1_OR_GREATER)
            result = CryptographicOperations.FixedTimeEquals(valueLeft, valueRight);
#else
            result = valueLeft.FixedTimeEquals(valueRight, valueLeft.Length, valueRight.Length);
#endif
        }
        finally
        {
            if (valueLeft != null)
            {
#if (NET8_0_OR_GREATER)
                Array.Clear(valueLeft);
#else
                Array.Clear(valueLeft, 0, valueLeft.Length);
#endif
            }

            if (valueRight != null)
            {
#if (NET8_0_OR_GREATER)
                Array.Clear(valueRight);
#else
                Array.Clear(valueRight, 0, valueRight.Length);
#endif
            }
        }

        return result;
    }

    /// <summary>
    /// This method represents the Greater Than operator.
    /// </summary>
    /// <param name="right">right-hand operand</param>
    /// <returns>This method returns <see langword="true"/> if this instance is greater than the <paramref name="right"/> instance, <see langword="false"/> otherwise.</returns>
    protected override bool GreaterThan(BigInteger right) => this.Value > right;

    /// <summary>
    /// This method represents the Lower Than operator.
    /// </summary>
    /// <param name="right">right-hand operand</param>
    /// <returns>This method returns <see langword="true"/> if this instance is less than the <paramref name="right"/> instance, <see langword="false"/> otherwise.</returns>
    protected override bool LowerThan(BigInteger right) => this.Value < right;

    /// <summary>
    /// This method represents the Greater Than Or Equal To operator.
    /// </summary>
    /// <param name="right">right-hand operand</param>
    /// <returns>This method returns <see langword="true"/> if this instance is greater than or equal to the <paramref name="right"/> instance, <see langword="false"/> otherwise.</returns>
    protected override bool EqualOrGreaterThan(BigInteger right) => this.Value >= right;

    /// <summary>
    /// This method represents the Lower Than Or Equal To operator.
    /// </summary>
    /// <param name="right">right-hand operand</param>
    /// <returns>This method returns <see langword="true"/> if this instance is less than or equal to the <paramref name="right"/> instance, <see langword="false"/> otherwise.</returns>
    protected override bool EqualOrLowerThan(BigInteger right) => this.Value <= right;

    /// <summary>
    /// Compares this instance to a second <see cref="Calculator{BigInteger}"/> and returns an integer that
    /// indicates whether the value of this instance is less than, equal to, or greater than the value of the specified object.
    /// </summary>
    /// <param name="other">The object to compare</param>
    /// <returns>A signed integer value that indicates the relationship of this instance to <paramref name="other"/>parameter</returns>
    public override int CompareTo(Calculator<BigInteger> other)
    {
        return this.Value.CompareTo(other?.Value ?? throw new ArgumentNullException(nameof(other)));
    }

    /// <summary>
    /// Adds the current <see cref="BigIntCalculator"/> instance with the <paramref name="right"/>
    /// <see cref="BigIntCalculator"/> instance.
    /// </summary>
    /// <param name="right">Right value to add (right summand).</param>
    /// <returns>The sum of the current <see cref="BigIntCalculator"/> instance and the <paramref name="right"/>
    /// <see cref="BigIntCalculator"/> instance.</returns>
    protected override Calculator<BigInteger> Add(BigInteger right) => this.Value + right;

    /// <summary>
    /// Subtracts the current <see cref="BigIntCalculator"/> instance with the <paramref name="right"/>
    /// <see cref="BigIntCalculator"/> instance.
    /// </summary>
    /// <param name="right">Right value to subtract (subtrahend).</param>
    /// <returns>The difference of the current <see cref="BigIntCalculator"/> instance and the <paramref name="right"/>
    /// <see cref="BigIntCalculator"/> instance.</returns>
    protected override Calculator<BigInteger> Subtract(BigInteger right) => this.Value - right;

    /// <summary>
    /// Multiplies the current <see cref="BigIntCalculator"/> instance with the <paramref name="right"/>
    /// <see cref="BigIntCalculator"/> instance.
    /// </summary>
    /// <param name="right">multiplicand</param>
    /// <returns>The product of the current <see cref="BigIntCalculator"/> instance and the <paramref name="right"/>
    /// <see cref="BigIntCalculator"/> instance.</returns>
    protected override Calculator<BigInteger> Multiply(BigInteger right) => this.Value * right;

    /// <summary>
    /// Divides the current <see cref="BigIntCalculator"/> instance with the <paramref name="right"/>
    /// <see cref="BigIntCalculator"/> instance.
    /// </summary>
    /// <param name="right">divisor</param>
    /// <returns>The quotient of the current <see cref="BigIntCalculator"/> instance and the <paramref name="right"/>
    /// <see cref="BigIntCalculator"/> instance.</returns>
    protected override Calculator<BigInteger> Divide(BigInteger right) => this.Value / right;

    /// <summary>
    /// The modulo operation
    /// </summary>
    /// <param name="right">divisor</param>
    /// <returns>The remainder as <see cref="BigIntCalculator"/> instance.</returns>
    protected override Calculator<BigInteger> Modulo(BigInteger right) => this.Value % right;

    /// <summary>
    /// The unary increment method increments this instance by 1.
    /// </summary>
    /// <returns>This <see cref="BigIntCalculator"/> instance plus <see cref="Calculator{BigInteger}.One"/></returns>
    protected override Calculator<BigInteger> Increment() => ++this.Clone().Value;

    /// <summary>
    /// The unary decrement method decrements this instance by 1.
    /// </summary>
    /// <returns>This <see cref="BigIntCalculator"/> instance minus <see cref="Calculator{BigInteger}.One"/></returns>
    protected override Calculator<BigInteger> Decrement() => --this.Clone().Value;

    /// <summary>
    /// Returns the absolute value of the current <see cref="BigIntCalculator"/> object.
    /// </summary>
    /// <returns>The absolute value of this instance.</returns>
    /// <remarks>This instance is greater than or equal to zero, the return value will be this instance.
    /// This instance is lower than zero, the return value will be this instance multiply with minus one.
    /// </remarks>
    public override Calculator<BigInteger> Abs() => BigInteger.Abs(this.Value);

    /// <summary>
    /// Raises this <see cref="BigIntCalculator"/> value to the power of a specified value.
    /// </summary>
    /// <param name="expo">The exponent to raise this <see cref="BigIntCalculator"/> value by.</param>
    /// <returns>The result of raising instance to the <paramref name="expo"/> power.</returns>
    public override Calculator<BigInteger> Pow(int expo) => BigInteger.Pow(this.Value, expo);

    /// <summary>
    /// Reduces this value modulo <c>2^<paramref name="mersenneExponent"/> - 1</c>
    /// with mathematical-modulo semantics for negative operands.
    /// </summary>
    /// <param name="mersenneExponent">Positive Mersenne exponent.</param>
    /// <exception cref="ArgumentOutOfRangeException">
    /// <paramref name="mersenneExponent"/> is not positive.
    /// </exception>
    /// <remarks>
    /// BCL <c>BigInteger.%</c> returns the same sign as the dividend, so an
    /// extra <c>+ modulus</c> step is required when the input is negative to
    /// produce the canonical non-negative representative in <c>[0, M_p - 1]</c>.
    /// </remarks>
    public override Calculator<BigInteger> MersenneModulo(int mersenneExponent)
    {
        if (mersenneExponent <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(mersenneExponent), mersenneExponent, string.Format(ErrorMessages.ValueLowerThanX, 1));
        }

        BigInteger modulus = (BigInteger.One << mersenneExponent) - BigInteger.One;
        BigInteger remainder = this.Value % modulus;
        if (remainder.Sign < 0)
        {
            remainder += modulus;
        }

        return new BigIntCalculator(remainder);
    }

    /// <summary>
    /// Gets the number of elements of the byte representation of the <see cref="BigIntCalculator"/> object.
    /// </summary>
    public override int ByteCount => this.byteCountLazy.Value;

    /// <summary>
    /// Gets the byte representation of the <see cref="BigIntCalculator"/> object.
    /// </summary>
    public override PinnedPoolArray<byte> ByteRepresentation
    {
        get
        {
            var byteArray = this.Value.ToByteArray();
            var pinnedPoolArray = new PinnedPoolArray<byte>(byteArray.Length);
            Array.Copy(byteArray, pinnedPoolArray.PoolArray, byteArray.Length);
            return pinnedPoolArray;
        }
    }

    /// <summary>
    /// Gets a value indicating whether the current <see cref="BigIntCalculator"/> object is zero (0).
    /// </summary>
    public override bool IsZero => this.Value.IsZero;

    /// <summary>
    /// Gets a value indicating whether the current <see cref="BigIntCalculator"/> object is one (1).
    /// </summary>
    public override bool IsOne => this.Value.IsOne;

    /// <summary>
    /// Gets a value indicating whether the current <see cref="BigIntCalculator"/> object is an even number.
    /// </summary>
    public override bool IsEven => this.Value % 2 == 0;

    /// <summary>
    /// Gets a number that indicates the sign (negative, positive, or zero) of the current <see cref="BigIntCalculator"/> object.
    /// </summary>
    public override int Sign => this.Value.Sign;

    /// <summary>
    /// Creates a lazily initialized instance to compute the byte count of the backing <see cref="BigInteger"/> value.
    /// </summary>
    /// <returns>A lazily initialized function that calculates the length of the byte array representing the <see cref="BigInteger"/> value.
    /// </returns>
    private Lazy<int> InitializeByteCountLazy()
    {
        return new(() =>
        {
            var byteArray = this.Value.ToByteArray();
            try
            {
                return byteArray.Length;
            }
            finally
            {
                Array.Clear(byteArray, 0, byteArray.Length);
            }
        }, LazyThreadSafetyMode.ExecutionAndPublication);
    }
}
