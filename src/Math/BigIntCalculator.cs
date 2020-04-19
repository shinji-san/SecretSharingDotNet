// ----------------------------------------------------------------------------
// <copyright file="BigIntCalculator.cs" company="Private">
// Copyright (c) 2019 All Rights Reserved
// </copyright>
// <author>Sebastian Walther</author>
// <date>04/20/2019 10:52:28 PM</date>
// ----------------------------------------------------------------------------

namespace SecretSharingDotNet.Math
{
    using System;
    using System.Collections.ObjectModel;
    using System.Numerics;

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
        /// This method represents the Greater Than operator.
        /// </summary>
        /// <param name="b">right-hand operand</param>
        /// <returns>This method returns <c>true</c> if this instance is greater than the <paramref name="b"/> instance, <c>false</c> otherwise.</returns>
        public override bool GreaterThan(BigInteger b) => this.Value > b;

        /// <summary>
        /// This method represents the Lower Than operator.
        /// </summary>
        /// <param name="b">right-hand operand</param>
        /// <returns>This method returns <c>true</c> if this instance is less than the <paramref name="b"/> instance, <c>false</c> otherwise.</returns>
        public override bool LowerThan(BigInteger b) => this.Value < b;

        /// <summary>
        /// This method represents the Greater Than Or Equal To operator.
        /// </summary>
        /// <param name="b">right-hand operand</param>
        /// <returns>This method returns <c>true</c> if this instance is greater than or equal to the <paramref name="b"/> instance, <c>false</c> otherwise.</returns>
        public override bool EqualOrGreaterThan(BigInteger b) => this.Value >= b;

        /// <summary>
        /// This method represents the Lower Than Or Equal To operator.
        /// </summary>
        /// <param name="b">right-hand operand</param>
        /// <returns>This method returns <c>true</c> if this instance is less than or equal to the <paramref name="b"/> instance, <c>false</c> otherwise.</returns>
        public override bool EqualOrLowerThan(BigInteger b) => this.Value <= b;

        /// <summary>
        /// Adds the current <see cref="BigIntCalculator"/> instance with the <paramref name="right"/>
        /// <see cref="BigIntCalculator"/> instance.
        /// </summary>
        /// <param name="right">Right value to add (right summand).</param>
        /// <returns>The sum of the current <see cref="BigIntCalculator"/> instance and the <paramref name="right"/>
        /// <see cref="BigIntCalculator"/> instance.</returns>
        public override Calculator<BigInteger> Add(BigInteger right) => this.Value + right;

        /// <summary>
        /// Subtracts the current <see cref="BigIntCalculator"/> instance with the <paramref name="b"/>
        /// <see cref="BigIntCalculator"/> instance.
        /// </summary>
        /// <param name="b">Right value to subtract (subtrahend).</param>
        /// <returns>The difference of the current <see cref="BigIntCalculator"/> instance and the <paramref name="b"/>
        /// <see cref="BigIntCalculator"/> instance.</returns>
        public override Calculator<BigInteger> Subtract(BigInteger b) => this.Value - b;

        /// <summary>
        /// Multiplies the current <see cref="BigIntCalculator"/> instance with the <paramref name="b"/>
        /// <see cref="BigIntCalculator"/> instance.
        /// </summary>
        /// <param name="b">multiplicand</param>
        /// <returns>The product of the current <see cref="BigIntCalculator"/> instance and the <paramref name="b"/>
        /// <see cref="BigIntCalculator"/> instance.</returns>
        public override Calculator<BigInteger> Multiply(BigInteger b) => this.Value * b;

        /// <summary>
        /// Divides the current <see cref="BigIntCalculator"/> instance with the <paramref name="b"/>
        /// <see cref="BigIntCalculator"/> instance.
        /// </summary>
        /// <param name="b">divisor</param>
        /// <returns>The quotient of the current <see cref="BigIntCalculator"/> instance and the <paramref name="b"/>
        /// <see cref="BigIntCalculator"/> instance.</returns>
        public override Calculator<BigInteger> Division(BigInteger b) => this.Value / b;

        /// <summary>
        /// The modulo operation
        /// </summary>
        /// <param name="b">divisor</param>
        /// <returns>The remainder as <see cref="BigIntCalculator"/> instance.</returns>
        public override Calculator<BigInteger> Modulo(BigInteger b) => this.Value % b;

        /// <summary>
        /// The unary increment method increments this instance by 1.
        /// </summary>
        /// <returns>This <see cref="BigIntCalculator"/> instance plus <see cref="Calculator{BigInteger}.One"/></returns>
        public override Calculator<BigInteger> Increase() => ++this.Clone().Value;

        /// <summary>
        /// The unary decrement method decrements this instance by 1.
        /// </summary>
        /// <returns>This <see cref="BigIntCalculator"/> instance minus <see cref="Calculator{BigInteger}.One"/></returns>
        public override Calculator<BigInteger> Decrease() => --this.Clone().Value;

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
        public override ReadOnlyCollection<byte> ByteRepresentation => new ReadOnlyCollection<byte>(this.Value.ToByteArray());

        /// <summary>
        /// Gets a value indicating whether or not the current <see cref="BigIntCalculator"/> object is zero (0).
        /// </summary>
        public override bool IsZero => this.Value.IsZero;

        /// <summary>
        /// Gets a value indicating whether or not the current <see cref="BigIntCalculator"/> object is one (1).
        /// </summary>
        public override bool IsOne => this.Value.IsOne;

        /// <summary>
        /// Gets a value indicating whether or not the current <see cref="BigIntCalculator"/> object is an even number.
        /// </summary>
        public override bool IsEven => this.Value % 2 == 0;

        /// <summary>
        /// Gets a number that indicates the sign (negative, positive, or zero) of the current <see cref="BigIntCalculator"/> object.
        /// </summary>
        public override int Sign => this.Value.Sign;

        /// <summary>
        /// Returns the square root of the current <see cref="BigIntCalculator"/> object.
        /// </summary>
        public override Calculator<BigInteger> Sqrt 
        {
            get 
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
                BigInteger root = BigInteger.One << (bitLength >> 1);
                bool isSqrt(BigInteger n, BigInteger r) => n >= r * r && n < (r + 1) * (r + 1);
                while (!isSqrt(this.Value, root))
                {
                    root = (root + (this.Value / root)) >> 1;
                }

                return root;
            }
        }
    }
}