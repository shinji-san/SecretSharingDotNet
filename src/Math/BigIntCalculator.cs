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

namespace SecretSharingDotNet.Math;

using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Numerics;
using System.Runtime.CompilerServices;

/// <summary>
/// <see cref="Calculator"/> implementation of <see cref="System.Numerics.BigInteger"/>
/// </summary>
public sealed class BigIntCalculator : Calculator<BigInteger>
{
    /// <summary>
    /// Initializes a new instance of the <see cref="BigIntCalculator"/> class.
    /// </summary>
    /// <param name="val">Numeric value</param>
    public BigIntCalculator(BigInteger val) : base(val) { }

    /// <summary>
    /// Initializes a new instance of the <see cref="BigIntCalculator"/> class.
    /// </summary>
    /// <param name="data">byte stream representation of numeric value</param>
    public BigIntCalculator(byte[] data) : base(new BigInteger(data)) { }

    /// <summary>
    /// Determines whether this instance and an <paramref name="other"/> specified <see cref="Calculator{BigInteger}"/> instance are equal.
    /// </summary>
    /// <param name="other">The <see cref="Calculator{BigInteger}"/> instance to compare</param>
    /// <returns><see langword="true"/> if the value of the <paramref name="other"/> parameter is the same as the value of this instance; otherwise <see langword="false"/>.
    /// If <paramref name="other"/> is <see langword="null"/>, the method returns <see langword="false"/>.</returns>
    /// <remarks>This is a Slow Equal Implementation to avoid a timing attack. See the reference for more details:
    /// https://bryanavery.co.uk/cryptography-net-avoiding-timing-attack/</remarks>
    [MethodImpl(MethodImplOptions.NoOptimization)]
    public override bool Equals(Calculator<BigInteger> other)
    {
        var valueLeft = this.Value.ToByteArray();
        var valueRight = other?.Value.ToByteArray() ?? [];

        var diff = (uint)valueLeft.Length ^ (uint)valueRight.Length;
        for (var i = 0; i < valueLeft.Length && i < valueRight.Length; i++)
        {
            diff |= (uint)(valueLeft[i] ^ valueRight[i]);
        }

        return diff == 0;
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

    /// <inheritdoc />
    /// <exception cref="T:System.OverflowException">Unable to convert the current instance of <see cref="BigIntCalculator"/> class to <see cref="Int32"/>.</exception>
    public override int ToInt32() => (int)this.Value;

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
    /// Gets the number of elements of the byte representation of the <see cref="BigIntCalculator"/> object.
    /// </summary>
    public override int ByteCount => this.Value.ToByteArray().Length;

    /// <summary>
    /// Gets the byte representation of the <see cref="BigIntCalculator"/> object.
    /// </summary>
    public override IEnumerable<byte> ByteRepresentation => new ReadOnlyCollection<byte>(this.Value.ToByteArray());

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
    /// Returns the square root of the current <see cref="BigIntCalculator"/> object.
    /// </summary>
    /// <exception cref="T:System.ArithmeticException" accessor="get">NaN (value is lower than zero)</exception>
    public override Calculator<BigInteger> Sqrt()
    {
        if (this.Value == BigInteger.Zero)
        {
            return Zero;
        }

        if (this.Value < BigInteger.Zero)
        {
            throw new ArithmeticException("NaN");
        }

        int bitLength = Convert.ToInt32(Math.Ceiling(BigInteger.Log(this.Value, 2)));
        var root = BigInteger.One << (bitLength >> 1);
        bool IsSqrt(BigInteger n, BigInteger r) => n >= r * r && n < (r + 1) * (r + 1);
        while (!IsSqrt(this.Value, root))
        {
            root = root + this.Value / root >> 1;
        }

        return root;
    }

    /// <summary>
    /// Converts the numeric value of the current <see cref="BigIntCalculator"/> object to its equivalent string representation.
    /// </summary>
    /// <returns>The <see cref="System.String"/> representation of the current <see cref="BigIntCalculator"/> value.</returns>
    public override string ToString() => this.Value.ToString();
}