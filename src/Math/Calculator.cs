// ----------------------------------------------------------------------------
// <copyright file="Calculator.cs" company="Private">
// Copyright (c) 2019 All Rights Reserved
// </copyright>
// <author>Sebastian Walther</author>
// <date>04/20/2019 10:52:28 PM</date>
// ----------------------------------------------------------------------------

namespace SecretSharingDotNet.Math
{
    using System.Collections.Generic;
    using System.Collections.ObjectModel;
    using System.Linq;
    using System.Reflection;
    using System;

    /// <summary>
    /// This class represents the calculator strategy pattern to decouple Shamir's Secret Sharing
    /// implementation from the concret numeric data type like <see cref="System.Numerics.BigInteger"/>.
    /// </summary>
    public abstract class Calculator
    {
        /// <summary>
        /// Gets the number of elements of the byte representation of the <see cref="Calculator"/> object.
        /// </summary>
        public abstract int ByteCount { get; }

        /// <summary>
        /// Gets the byte representation of the <see cref="Calculator"/> object.
        /// </summary>
        public abstract ReadOnlyCollection<byte> ByteRepresentation { get; }

        /// <summary>
        /// Gets a value indicating whether or not the current <see cref="Calculator"/> object is zero.
        /// </summary>
        public abstract bool IsZero { get; }

        /// <summary>
        /// Gets a value indicating whether or not the current <see cref="Calculator"/> object is one.
        /// </summary>
        public abstract bool IsOne { get; }

        /// <summary>
        /// Gets a value indicating whether or not the current <see cref="Calculator"/> object is an even number.
        /// </summary>
        public abstract bool IsEven { get; }

        /// <summary>
        /// Gets a number that indicates the sign (negative, positive, or zero) of the current <see cref="Calculator"/> object.
        /// </summary>
        public abstract int Sign { get; }

        /// <summary>
        /// Returns the square root of the current <see cref="Calculator"/>.
        /// </summary>
        public abstract double Sqrt { get; }
    }

    /// <summary>
    /// This class represents the calculator strategy pattern to decouple Shamir's Secret Sharing
    /// implementation from the concret numeric data type like BigInteger.
    /// </summary>
    /// <typeparam name="TNumber">Numeric data type</typeparam>
    public abstract class Calculator<TNumber> : Calculator, IEquatable<Calculator<TNumber>>
    {
        /// <summary>
        /// Saves the numeric value
        /// </summary>
        private TNumber value;

        /// <summary>
        /// 
        /// </summary>
        private static readonly Dictionary<Type, Type> ChildTypes = GetDerivedNumberTypes ();

        /// <summary>
        /// Initializes a new instance of the <see cref="Calculator{TNumber}"/> class.
        /// </summary>
        /// <param name="val">Numeric value</param>
        protected Calculator (TNumber val) => this.value = val;

        /// <summary>
        /// Adds the current <see cref="Calculator{TNumber}"/> instance with the <paramref name="right"/> 
        /// <see cref="Calculator{TNumber}"/> instance.
        /// </summary>
        /// <param name="right">Right value to add (right summand).</param>
        /// <returns>The sum of the current <see cref="Calculator{TNumber}"/> instance and the <paramref name="right"/> 
        /// <see cref="Calculator{TNumber}"/> instance.</returns>
        public abstract Calculator<TNumber> Add (TNumber right);

        /// <summary>
        /// Subtracts the current <see cref="Calculator{TNumber}"/> instance with the <paramref name="right"/> 
        /// <see cref="Calculator{TNumber}"/> instance.
        /// </summary>
        /// <param name="right">Right value to subtract (subtrahend).</param>
        /// <returns>The difference of the current <see cref="Calculator{TNumber}"/> instance and the <paramref name="right"/> 
        /// <see cref="Calculator{TNumber}"/> instance.</returns>
        public abstract Calculator<TNumber> Subtract (TNumber right);

        /// <summary>
        /// Multiplies the current <see cref="Calculator{TNumber}"/> instance with the <paramref name="right"/> 
        /// <see cref="Calculator{TNumber}"/> instance.
        /// </summary>
        /// <param name="right">multiplicand</param>
        /// <returns>The product of the current <see cref="Calculator{TNumber}"/> instance and the <paramref name="right"/> 
        /// <see cref="Calculator{TNumber}"/> instance.</returns>
        public abstract Calculator<TNumber> Multiply (TNumber right);

        /// <summary>
        /// Divides the current <see cref="Calculator{TNumber}"/> instance with the <paramref name="right"/> 
        /// <see cref="Calculator{TNumber}"/> instance.
        /// </summary>
        /// <param name="right">divisor</param>
        /// <returns>The quotient of the current <see cref="Calculator{TNumber}"/> instance and the <paramref name="right"/> 
        /// <see cref="Calculator{TNumber}"/> instance.</returns>
        public abstract Calculator<TNumber> Division (TNumber right);

        /// <summary>
        /// 
        /// </summary>
        /// <param name="right"></param>
        /// <returns></returns>
        public abstract Calculator<TNumber> Modulo (TNumber right);

        /// <summary>
        /// 
        /// </summary>
        /// <returns></returns>
        public abstract Calculator<TNumber> Increase ();

        /// <summary>
        /// 
        /// </summary>
        /// <returns></returns>
        public abstract Calculator<TNumber> Decrease ();

        /// <summary>
        /// 
        /// </summary>
        /// <returns></returns>
        public abstract Calculator<TNumber> Abs ();

        /// <summary>
        /// Power (mathematical)
        /// </summary>
        /// <param name="expo">The exponent.</param>
        /// <returns></returns>
        public abstract Calculator<TNumber> Pow (int expo);

        /// <summary>
        /// 
        /// </summary>
        /// <param name="right"></param>
        /// <returns></returns>
        public abstract bool GreaterThan (TNumber right);

        /// <summary>
        /// 
        /// </summary>
        /// <param name="right"></param>
        /// <returns></returns>
        public abstract bool EqualOrGreaterThan (TNumber right);

        /// <summary>
        /// 
        /// </summary>
        /// <param name="right"></param>
        /// <returns></returns>
        public abstract bool LowerThan (TNumber right);

        /// <summary>
        /// 
        /// </summary>
        /// <param name="right"></param>
        /// <returns></returns>
        public abstract bool EqualOrLowerThan (TNumber right);

        /// <summary>
        /// Greater than operator
        /// </summary>
        /// <param name="a">The 1st operand</param>
        /// <param name="b">The 2nd operand</param>
        /// <returns>Returns <c>true</c> if its 1st operand is greater than its 2nd operand, otherwise <c>false</c>.</returns>
        public static bool operator > (Calculator<TNumber> a, Calculator<TNumber> b) => a.GreaterThan (b.Value);

        /// <summary>
        /// Less than operator
        /// </summary>
        /// <param name="a">The 1st operand</param>
        /// <param name="b">The 2nd operand</param>
        /// <returns>Returns <c>true</c> if its 1st operand is less than its 2nd operand, otherwise <c>false</c>.</returns>
        public static bool operator < (Calculator<TNumber> a, Calculator<TNumber> b) => a.LowerThan (b.Value);

        /// <summary>
        /// Greater than or equal operator
        /// </summary>
        /// <param name="a">The 1st operand</param>
        /// <param name="b">The 2nd operand</param>
        /// <returns>Returns <c>true</c> if its 1st operand is greater than or equal to its 2nd operand, otherwise <c>false</c>.</returns>
        public static bool operator >= (Calculator<TNumber> a, Calculator<TNumber> b) => a.EqualOrGreaterThan (b.Value);

        /// <summary>
        /// Less than or equal operator
        /// </summary>
        /// <param name="a">The 1st operand</param>
        /// <param name="b">The 2nd operand</param>
        /// <returns>Returns <c>true</c> if its 1st operand is less than or equal to its 2nd operand, otherwise <c>false</c>.</returns>
        public static bool operator <= (Calculator<TNumber> a, Calculator<TNumber> b) => a.EqualOrLowerThan (b.Value);

        /// <summary>
        /// Addition operation
        /// </summary>
        /// <param name="a">The 1st summand</param>
        /// <param name="b">The 2nd summand</param>
        /// <returns>The sum</returns>
        public static Calculator<TNumber> operator + (Calculator<TNumber> a, Calculator<TNumber> b) => a.Add (b.Value);

        /// <summary>
        /// Subtraction operation
        /// </summary>
        /// <param name="a">The minuend</param>
        /// <param name="b">The subtrahend</param>
        /// <returns>The difference</returns>
        public static Calculator<TNumber> operator - (Calculator<TNumber> a, Calculator<TNumber> b) => a.Subtract (b.Value);

        /// <summary>
        /// Multiplication operation
        /// </summary>
        /// <param name="a">multiplier</param>
        /// <param name="b">multiplicand</param>
        /// <returns>The product</returns>
        public static Calculator<TNumber> operator * (Calculator<TNumber> a, Calculator<TNumber> b) => a.Multiply (b.Value);

        /// <summary>
        /// Division operation
        /// </summary>
        /// <param name="a">dividend</param>
        /// <param name="b">divisor</param>
        /// <returns>The quotient</returns>
        public static Calculator<TNumber> operator / (Calculator<TNumber> a, Calculator<TNumber> b) => a.Division (b.Value);

        /// <summary>
        /// 
        /// </summary>
        /// <param name="a"></param>
        /// <param name="b"></param>
        /// <returns></returns>
        public static Calculator<TNumber> operator % (Calculator<TNumber> a, Calculator<TNumber> b) => a.Modulo (b.Value);

        /// <summary>
        /// Increment operator
        /// </summary>
        /// <param name="a">The operand</param>
        /// <returns>The unary increment operator increments the operand <paramref name="a"/> by 1</returns>
        public static Calculator<TNumber> operator ++ (Calculator<TNumber> a) => a.Increase ();

        /// <summary>
        /// Decrement operator
        /// </summary>
        /// <param name="a">The operand</param>
        /// <returns>The unary decrement operator decrements the operand <paramref name="a"/> by 1.</returns>
        public static Calculator<TNumber> operator -- (Calculator<TNumber> a) => a.Decrease ();

        /// <summary>
        /// Equality operator
        /// </summary>
        /// <param name="left">The left operand</param>
        /// <param name="right">The right operand</param>
        /// <returns>Returns <c>true</c> if its operands are equal, otherwise <c>false</c>.</returns>
        public static bool operator == (Calculator<TNumber> left, Calculator<TNumber> right)
        {
            if (((object) left) == null || ((object) right) == null)
            {
                return object.Equals (left, right);
            }

            return left.Equals (right);
        }

        /// <summary>
        /// Inequality operator
        /// </summary>
        /// <param name="left">The left operand</param>
        /// <param name="right">The right operand</param>
        /// <returns>Returns <c>true</c> if its operands are not equal, otherwise <c>false</c>.</returns>
        public static bool operator != (Calculator<TNumber> left, Calculator<TNumber> right)
        {
            if (((object) left) == null || ((object) right) == null)
            {
                return !object.Equals (left, right);
            }

            return !left.Equals (right);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="a"></param>
        public static implicit operator TNumber (Calculator<TNumber> a) => a.Value;

        /// <summary>
        /// 
        /// </summary>
        /// <param name="a"></param>
        /// <typeparam name="TNumber">Numeric data type (An integer data type)</typeparam>
        public static implicit operator Calculator<TNumber> (TNumber a)
        {
            try
            {
                return Activator.CreateInstance (ChildTypes[typeof (TNumber)], a) as Calculator<TNumber>;
            }
            catch (KeyNotFoundException)
            {
                throw new NotSupportedException ($"Generic Data Type '{typeof(TNumber).Name}' not supported!");
            }
        }

        /// <summary>
        /// 
        /// </summary>
        /// <returns></returns>
        private static Dictionary<Type, Type> GetDerivedNumberTypes ()
        {
            Assembly asm = Assembly.GetAssembly (typeof (Calculator));
            var listOfClasses = asm.GetTypes ().Where (x => x.IsSubclassOf (typeof (Calculator)) && !x.IsGenericType);
            return listOfClasses.ToDictionary (x => x.BaseType.GetGenericArguments () [0]);
        }

        /// <summary>
        /// Determines whether this instance and an<paramref name="other"/> specified <see cref="Calculator{TNumber}"/> instance are equal.
        /// </summary>
        /// <param name="other">The <see cref="Calculator{TNumber}"/> instance to compare</param>
        /// <returns>c>true</c> if the value of the <paramref name="other"/> parameter is the same as the value of this instance; otherwise <c>false</c>.
        /// If <paramref name="other"/>  is <c>null</c>, the method returns <c>false</c>.</returns>
        public bool Equals (Calculator<TNumber> other)
        {
            if (other == null)
            {
                return false;
            }

            return this.Value.Equals (other.Value);
        }

        /// <summary>
        /// Returns a value that indicates whether the current instance and a specified object have the same value.
        /// </summary>
        /// <param name="obj">The object to compare.</param>
        /// <returns><c>true</c> if the <paramref name="obj"/> argument is a <see cref="Calculator{TNumber}"/> object,
        /// and its value is equal to the value of the current <see cref="Calculator{TNumber}"/> instance; otherwise, <c>false</c>.</returns>
        public override bool Equals (object obj)
        {
            if (obj == null)
            {
                return false;
            }

            var calculator = obj as Calculator<TNumber>;
            return calculator == null ? false : this.Equals (calculator);
        }

        /// <summary>
        /// Returns the hash code for the current <see cref="Calculator{TNumber}"/> object.
        /// </summary>
        /// <returns>A 32-bit signed integer hash code.</returns>
        public override int GetHashCode () => this.Value.GetHashCode ();

        /// <summary>
        /// Gets or sets the numeric value
        /// </summary>
        public TNumber Value
        {
            get { return this.value; }
            set { this.value = value; }
        }

        /// <summary>
        /// Gets a value that represents the number zero (0).
        /// </summary>
        public static Calculator<TNumber> Zero => default (TNumber);

        /// <summary>
        /// Gets a value that represents the number one (1).
        /// </summary>
        public static Calculator<TNumber> One => Zero.Increase ();

        /// <summary>
        /// Gets a value that represents the number two (2).
        /// </summary>
        /// <returns></returns>
        public static Calculator<TNumber> Two => One.Increase ();

        /// <summary>
        /// A shallow copy of the current <see cref="Calculator{TNumber}/"> instance.
        /// </summary>
        /// <returns></returns>
        public Calculator<TNumber> Clone () => this.MemberwiseClone () as Calculator<TNumber>;

        /// <summary>
        /// Creates a new instance of the <see cref="Calculator{TNumber}/"> class.
        /// </summary>
        /// <param name="data">byte array representation of the <see cref="TNumber"/></param>
        /// <returns></returns>
        public static Calculator<TNumber> Create (byte[] data)
        {
            return Activator.CreateInstance (ChildTypes[typeof (TNumber)], data) as Calculator<TNumber>;
        }

        /// <summary>
        /// Converts the numeric value of the current <see cref="Calculator{TNumber}"/> object to its equivalent string representation.
        /// </summary>
        /// <returns>The string representation of the current <see cref="Calculator{TNumber}"/> value.</returns>
        public override string ToString () => this.Value.ToString ();
    }
}