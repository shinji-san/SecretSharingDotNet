// <copyright file="Calculator`1.cs" company="Private">
// Copyright (c) 2022 All Rights Reserved
// </copyright>
// <author>Sebastian Walther</author>
// <date>07/21/2022 05:23:42 PM</date>
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

namespace SecretSharingDotNet.Math
{
    using System;
    using System.Collections.Generic;
    using System.Collections.ObjectModel;

    /// <summary>
    /// This class represents the calculator strategy pattern to decouple Shamir's Secret Sharing
    /// implementation from the concrete numeric data type like BigInteger.
    /// </summary>
    /// <typeparam name="TNumber">Numeric data type</typeparam>
    public abstract class Calculator<TNumber> : Calculator, IEquatable<Calculator<TNumber>>, IComparable, IComparable<Calculator<TNumber>>
    {
        /// <summary>
        /// Saves a dictionary of constructors of number data types derived from the <see cref="Calculator{TNumber}"/> class.
        /// </summary>
        private static readonly ReadOnlyDictionary<Type, Func<TNumber, Calculator<TNumber>>> ChildCtors = new ReadOnlyDictionary<Type, Func<TNumber, Calculator<TNumber>>>(GetDerivedCtors<TNumber, Calculator<TNumber>>());

        /// <summary>
        /// Initializes a new instance of the <see cref="Calculator{TNumber}"/> class.
        /// </summary>
        /// <param name="val">Numeric value</param>
        protected Calculator(TNumber val) => this.Value = val;

        /// <summary>
        /// Adds the current <see cref="Calculator{TNumber}"/> instance with the <paramref name="right"/> 
        /// <see cref="Calculator{TNumber}"/> instance.
        /// </summary>
        /// <param name="right">Right value to add (right summand).</param>
        /// <returns>The sum of the current <see cref="Calculator{TNumber}"/> instance and the <paramref name="right"/> 
        /// <see cref="Calculator{TNumber}"/> instance.</returns>
        public abstract Calculator<TNumber> Add(TNumber right);

        /// <summary>
        /// Subtracts the current <see cref="Calculator{TNumber}"/> instance with the <paramref name="right"/> 
        /// <see cref="Calculator{TNumber}"/> instance.
        /// </summary>
        /// <param name="right">Right value to subtract (subtrahend).</param>
        /// <returns>The difference of the current <see cref="Calculator{TNumber}"/> instance and the <paramref name="right"/> 
        /// <see cref="Calculator{TNumber}"/> instance.</returns>
        public abstract Calculator<TNumber> Subtract(TNumber right);

        /// <summary>
        /// Multiplies the current <see cref="Calculator{TNumber}"/> instance with the <paramref name="right"/> 
        /// <see cref="Calculator{TNumber}"/> instance.
        /// </summary>
        /// <param name="right">multiplicand</param>
        /// <returns>The product of the current <see cref="Calculator{TNumber}"/> instance and the <paramref name="right"/> 
        /// <see cref="Calculator{TNumber}"/> instance.</returns>
        public abstract Calculator<TNumber> Multiply(TNumber right);

        /// <summary>
        /// Divides the current <see cref="Calculator{TNumber}"/> instance with the <paramref name="right"/> 
        /// <see cref="Calculator{TNumber}"/> instance.
        /// </summary>
        /// <param name="right">divisor</param>
        /// <returns>The quotient of the current <see cref="Calculator{TNumber}"/> instance and the <paramref name="right"/> 
        /// <see cref="Calculator{TNumber}"/> instance.</returns>
        public abstract Calculator<TNumber> Divide(TNumber right);

        /// <summary>
        /// The modulo operation
        /// </summary>
        /// <param name="right">divisor</param>
        /// <returns>The remainder</returns>
        public abstract Calculator<TNumber> Modulo(TNumber right);

        /// <summary>
        /// The unary increment method increments this instance by 1.
        /// </summary>
        /// <returns>This <see cref="Calculator{TNumber}"/> instance plus <see cref="Calculator{TNumber}.One"/></returns>
        public abstract Calculator<TNumber> Increment();

        /// <summary>
        /// The unary decrement method decrements this instance by 1.
        /// </summary>
        /// <returns>This <see cref="Calculator{TNumber}"/> instance minus <see cref="Calculator{TNumber}.One"/></returns>
        public abstract Calculator<TNumber> Decrement();

        /// <summary>
        /// Returns the absolute value of the current <see cref="Calculator{TNumber}"/> object.
        /// </summary>
        /// <returns>The absolute value of this instance.</returns>
        public abstract Calculator<TNumber> Abs();

        /// <summary>
        /// Power (mathematical)
        /// </summary>
        /// <param name="expo">The exponent.</param>
        /// <returns>The result of raising instance to the <paramref name="expo"/> power.</returns>
        public abstract Calculator<TNumber> Pow(int expo);

        /// <summary>
        /// Returns the square root of the current <see cref="Calculator{TNumber}"/>.
        /// </summary>
        public abstract Calculator<TNumber> Sqrt { get; }

        /// <summary>
        /// This method represents the Greater Than operator.
        /// </summary>
        /// <param name="right">right-hand operand</param>
        /// <returns>This method returns <see langword="true"/> if this instance is greater than the <paramref name="right"/> instance, <see langword="false"/> otherwise.</returns>
        public abstract bool GreaterThan(TNumber right);

        /// <summary>
        /// This method represents the Greater Than Or Equal To operator.
        /// </summary>
        /// <param name="right">right-hand operand</param>
        /// <returns>This method returns <see langword="true"/> if this instance is greater than or equal to the <paramref name="right"/> instance, <see langword="false"/> otherwise.</returns>
        public abstract bool EqualOrGreaterThan(TNumber right);

        /// <summary>
        /// This method represents the Lower Than operator.
        /// </summary>
        /// <param name="right">right-hand operand</param>
        /// <returns>This method returns <see langword="true"/> if this instance is less than the <paramref name="right"/> instance, <see langword="false"/> otherwise.</returns>
        public abstract bool LowerThan(TNumber right);

        /// <summary>
        /// This method represents the Lower Than Or Equal To operator.
        /// </summary>
        /// <param name="right">right-hand operand</param>
        /// <returns>This method returns <see langword="true"/> if this instance is less than or equal to the <paramref name="right"/> instance, <see langword="false"/> otherwise.</returns>
        public abstract bool EqualOrLowerThan(TNumber right);

        /// <summary>
        /// Greater than operator
        /// </summary>
        /// <param name="left">The 1st operand</param>
        /// <param name="right">The 2nd operand</param>
        /// <returns>Returns <see langword="true"/> if its 1st operand is greater than its 2nd operand, otherwise <see langword="false"/>.</returns>
        public static bool operator >(Calculator<TNumber> left, Calculator<TNumber> right) => !(left is null) && !(right is null) && left.GreaterThan(right.Value);

        /// <summary>
        /// Less than operator
        /// </summary>
        /// <param name="left">The 1st operand</param>
        /// <param name="right">The 2nd operand</param>
        /// <returns>Returns <see langword="true"/> if its 1st operand is less than its 2nd operand, otherwise <see langword="false"/>.</returns>
        public static bool operator <(Calculator<TNumber> left, Calculator<TNumber> right) => !(left is null) && !(right is null) && left.LowerThan(right.Value);

        /// <summary>
        /// Greater than or equal operator
        /// </summary>
        /// <param name="left">The 1st operand</param>
        /// <param name="right">The 2nd operand</param>
        /// <returns>Returns <see langword="true"/> if its 1st operand is greater than or equal to its 2nd operand, otherwise <see langword="false"/>.</returns>
        public static bool operator >=(Calculator<TNumber> left, Calculator<TNumber> right) => !(left is null) && !(right is null) && left.EqualOrGreaterThan(right.Value);

        /// <summary>
        /// Less than or equal operator
        /// </summary>
        /// <param name="left">The 1st operand</param>
        /// <param name="right">The 2nd operand</param>
        /// <returns>Returns <see langword="true"/> if its 1st operand is less than or equal to its 2nd operand, otherwise <see langword="false"/>.</returns>
        public static bool operator <=(Calculator<TNumber> left, Calculator<TNumber> right) => !(left is null) && !(right is null) && left.EqualOrLowerThan(right.Value);

        /// <summary>
        /// Addition operation
        /// </summary>
        /// <param name="left">The 1st summand</param>
        /// <param name="right">The 2nd summand</param>
        /// <returns>The sum</returns>
        public static Calculator<TNumber> operator +(Calculator<TNumber> left, Calculator<TNumber> right) => !(right is null) ? left?.Add(right.Value) ?? throw new ArgumentNullException(nameof(left)) : throw new ArgumentNullException(nameof(right));

        /// <summary>
        /// Subtraction operation
        /// </summary>
        /// <param name="left">The minuend</param>
        /// <param name="right">The subtrahend</param>
        /// <returns>The difference</returns>
        public static Calculator<TNumber> operator -(Calculator<TNumber> left, Calculator<TNumber> right) => !(right is null) ? left?.Subtract(right.Value) ?? throw new ArgumentNullException(nameof(left)) : throw new ArgumentNullException(nameof(right));

        /// <summary>
        /// Multiplication operation
        /// </summary>
        /// <param name="left">multiplier</param>
        /// <param name="right">multiplicand</param>
        /// <returns>The product</returns>
        public static Calculator<TNumber> operator *(Calculator<TNumber> left, Calculator<TNumber> right) => !(right is null) ? left?.Multiply(right.Value) ?? throw new ArgumentNullException(nameof(left)) : throw new ArgumentNullException(nameof(right));

        /// <summary>
        /// Divide operation
        /// </summary>
        /// <param name="left">dividend</param>
        /// <param name="right">divisor</param>
        /// <returns>The quotient</returns>
        public static Calculator<TNumber> operator /(Calculator<TNumber> left, Calculator<TNumber> right) => !(right is null) ? left?.Divide(right.Value) ?? throw new ArgumentNullException(nameof(left)) : throw new ArgumentNullException(nameof(right));

        /// <summary>
        /// Modulo operation
        /// </summary>
        /// <param name="left">dividend</param>
        /// <param name="right">divisor</param>
        /// <returns>The remainder</returns>
        public static Calculator<TNumber> operator %(Calculator<TNumber> left, Calculator<TNumber> right) => !(right is null) ? left?.Modulo(right.Value) ?? throw new ArgumentNullException(nameof(left)) : throw new ArgumentNullException(nameof(right));

        /// <summary>
        /// Increment operator
        /// </summary>
        /// <param name="number">The operand</param>
        /// <returns>The unary increment operator increments the operand <paramref name="number"/> by 1</returns>
        public static Calculator<TNumber> operator ++(Calculator<TNumber> number) => number?.Increment();

        /// <summary>
        /// Decrement operator
        /// </summary>
        /// <param name="number">The operand</param>
        /// <returns>The unary decrement operator decrements the operand <paramref name="number"/> by 1.</returns>
        public static Calculator<TNumber> operator --(Calculator<TNumber> number) => number?.Decrement();

        /// <summary>
        /// Equality operator
        /// </summary>
        /// <param name="left">The left operand</param>
        /// <param name="right">The right operand</param>
        /// <returns>Returns <see langword="true"/> if its operands are equal, otherwise <see langword="false"/>.</returns>
        public static bool operator ==(Calculator<TNumber> left, Calculator<TNumber> right)
        {
            if ((object)left == null || (object)right == null)
            {
                return Equals(left, right);
            }

            return left.Equals(right);
        }

        /// <summary>
        /// Inequality operator
        /// </summary>
        /// <param name="left">The left operand</param>
        /// <param name="right">The right operand</param>
        /// <returns>Returns <see langword="true"/> if its operands are not equal, otherwise <see langword="false"/>.</returns>
        public static bool operator !=(Calculator<TNumber> left, Calculator<TNumber> right)
        {
            if ((object)left == null || (object)right == null)
            {
                return !Equals(left, right);
            }

            return !left.Equals(right);
        }

        /// <summary>
        /// Casts the <see cref="Calculator{TNumber}"/> instance to an <typeparamref name="TNumber"/> instance.
        /// </summary>
        /// <param name="calculatorInstance">A data type from basic class <see cref="Calculator{TNumber}"/>.</param>
        public static implicit operator TNumber(Calculator<TNumber> calculatorInstance) => !(calculatorInstance is null) ? calculatorInstance.Value : default;

        /// <summary>
        /// Casts the <typeparamref name="TNumber"/> instance to an <see cref="Calculator{TNumber}"/> instance.
        /// </summary>
        /// <param name="number">Numeric data type (An integer data type).</param>
        public static implicit operator Calculator<TNumber>(TNumber number)
        {
            try
            {
                return ChildCtors[typeof(TNumber)](number);
            }
            catch (KeyNotFoundException)
            {
                throw new NotSupportedException(string.Format(ErrorMessages.DataTypeNotSupported, typeof(TNumber).Name));
            }
        }

        /// <summary>
        /// Determines whether this instance and an<paramref name="other"/> specified <see cref="Calculator{TNumber}"/> instance are equal.
        /// </summary>
        /// <param name="other">The <see cref="Calculator{TNumber}"/> instance to compare</param>
        /// <returns><see langword="true"/> if the value of the <paramref name="other"/> parameter is the same as the value of this instance; otherwise <see langword="false"/>.
        /// If <paramref name="other"/> is <see langword="null"/>, the method returns <see langword="false"/>.</returns>
        public bool Equals(Calculator<TNumber> other)
        {
            return other != null && this.Value.Equals(other.Value);
        }

        /// <summary>
        /// Returns a value that indicates whether the current instance and a specified object have the same value.
        /// </summary>
        /// <param name="obj">The object to compare.</param>
        /// <returns><see langword="true"/> if the <paramref name="obj"/> argument is a <see cref="Calculator{TNumber}"/> object,
        /// and its value is equal to the value of the current <see cref="Calculator{TNumber}"/> instance; otherwise, <see langword="false"/>.</returns>
        public override bool Equals(object obj)
        {
            if (obj == null)
            {
                return false;
            }

            var calculator = obj as Calculator<TNumber>;
            return calculator != null && this.Equals(calculator);
        }

        /// <summary>
        /// Returns the hash code for the current <see cref="Calculator{TNumber}"/> object.
        /// </summary>
        /// <returns>A 32-bit signed integer hash code.</returns>
        public override int GetHashCode() => this.Value.GetHashCode();

        /// <summary>
        /// Compares this instance to a specified object and returns an integer that
        /// indicates whether the value of this instance is less than, equal to, or greater than the value of the specified object.
        /// </summary>
        /// <param name="obj">The object to compare</param>
        /// <returns>A signed integer that indicates the relationship of the current instance to the <paramref name="obj"/> parameter</returns>
        public virtual int CompareTo(object obj)
        {
            switch (obj)
            {
                case null:
                    return 1;
                case TNumber number:
                    return this.CompareTo(number);
                default:
                    throw new ArgumentException();
            }
        }

        /// <summary>
        /// Gets or sets the numeric value
        /// </summary>
        public TNumber Value { get; set; }

        /// <summary>
        /// Gets a value that represents the number zero (0).
        /// </summary>
        public static Calculator<TNumber> Zero { get; } = default(TNumber);

        /// <summary>
        /// Gets a value that represents the number one (1).
        /// </summary>
        public static Calculator<TNumber> One { get; } = Zero.Increment();

        /// <summary>
        /// Gets a value that represents the number two (2).
        /// </summary>
        /// <returns></returns>
        public static Calculator<TNumber> Two { get; } = One.Increment();

        /// <summary>
        /// A shallow copy of the current <see cref="Calculator{TNumber}"/> instance.
        /// </summary>
        /// <returns></returns>
        public Calculator<TNumber> Clone() => this.MemberwiseClone() as Calculator<TNumber>;

        /// <summary>
        /// Compares this instance to a second <see cref="Calculator{TNumber}"/> and returns an integer that indicates whether the value of this instance is less than, equal to, or greater than the value of the specified object.
        /// </summary>
        /// <param name="other">The object to compare.</param>
        /// <returns>A signed integer that indicates the relationship of the current instance to the <paramref name="other"/> parameter</returns>
        public abstract int CompareTo(Calculator<TNumber> other);

        /// <summary>
        /// Converts the numeric value of the current <see cref="Calculator{TNumber}"/> object to its equivalent string representation.
        /// </summary>
        /// <returns>The string representation of the current <see cref="Calculator{TNumber}"/> value.</returns>
        public override string ToString() => this.Value.ToString();
    }
}
