// ----------------------------------------------------------------------------
// <copyright file="FinitePoint.cs" company="Private">
// Copyright (c) 2019 All Rights Reserved
// </copyright>
// <author>Sebastian Walther</author>
// <date>04/20/2019 10:52:28 PM</date>
// ----------------------------------------------------------------------------

#region License
// ----------------------------------------------------------------------------
// Copyright 2019 Sebastian Walther
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

namespace SecretSharingDotNet.Cryptography
{
    using Math;
    using System;
    using System.Collections.Generic;
    using System.Collections.ObjectModel;
    using System.Globalization;
    using System.Linq;
    using System.Text;

    /// <summary>
    /// Represents the support point of the polynomial
    /// </summary>
    /// <typeparam name="TNumber">Numeric data type (An integer type)</typeparam>
    public struct FinitePoint<TNumber> : IEquatable<FinitePoint<TNumber>>, IComparable<FinitePoint<TNumber>>
    {
        /// <summary>
        /// Saves the X coordinate
        /// </summary>
        private readonly Calculator<TNumber> x;

        /// <summary>
        /// Saves the Y coordinate
        /// </summary>
        private readonly Calculator<TNumber> y;

        /// <summary>
        /// Initializes a new instance of the <see cref="FinitePoint{TNumber}"/> struct.
        /// </summary>
        /// <param name="x">X coordinate as known as share index</param>
        /// <param name="polynomial">Polynomial</param>
        /// <param name="prime">The prime number given by the security level.</param>
        public FinitePoint(Calculator<TNumber> x, ICollection<Calculator<TNumber>> polynomial, Calculator<TNumber> prime)
        {
            this.x = x ?? throw new ArgumentNullException(nameof(x));
            this.y = Evaluate(polynomial ?? throw new ArgumentNullException(nameof(polynomial)), this.x, prime ?? throw new ArgumentNullException(nameof(prime)));
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="FinitePoint{TNumber}"/> struct.
        /// </summary>
        /// <param name="x">X coordinate</param>
        /// <param name="y">Y coordinate</param>
        private FinitePoint(Calculator<TNumber> x, Calculator<TNumber> y)
        {
            this.x = x;
            this.y = y;
        }

        /// <summary>
        /// Gets the X coordinate
        /// </summary>
        public Calculator<TNumber> X => this.x;

        /// <summary>
        /// Gets the Y coordinate
        /// </summary>
        public Calculator<TNumber> Y => this.y;

        /// <summary>
        /// 
        /// </summary>
        /// <param name="left"></param>
        /// <param name="right"></param>
        /// <returns></returns>
        public static bool operator ==(FinitePoint<TNumber> left, FinitePoint<TNumber> right) => left.Equals(right);

        /// <summary>
        /// 
        /// </summary>
        /// <param name="left"></param>
        /// <param name="right"></param>
        /// <returns></returns>
        public static bool operator !=(FinitePoint<TNumber> left, FinitePoint<TNumber> right) => !left.Equals(right);

        /// <summary>
        /// 
        /// </summary>
        /// <param name="left"></param>
        /// <param name="right"></param>
        /// <returns></returns>
        public static bool operator >(FinitePoint<TNumber> left, FinitePoint<TNumber> right) => left.CompareTo(right) == 1;

        /// <summary>
        /// 
        /// </summary>
        /// <param name="left"></param>
        /// <param name="right"></param>
        /// <returns></returns>
        public static bool operator <(FinitePoint<TNumber> left, FinitePoint<TNumber> right) => left.CompareTo(right) == -1;

        /// <summary>
        /// 
        /// </summary>
        /// <param name="left"></param>
        /// <param name="right"></param>
        /// <returns></returns>
        public static bool operator >=(FinitePoint<TNumber> left, FinitePoint<TNumber> right) => left.CompareTo(right) >= 0;

        /// <summary>
        /// 
        /// </summary>
        /// <param name="left"></param>
        /// <param name="right"></param>
        /// <returns></returns>
        public static bool operator <=(FinitePoint<TNumber> left, FinitePoint<TNumber> right) => left.CompareTo(right) <= 0;

        /// <summary>
        /// 
        /// </summary>
        /// <param name="other"></param>
        /// <returns></returns>
        public int CompareTo(FinitePoint<TNumber> other)
        {
            return ((this.X * this.X + this.Y * this.Y).Sqrt - (other.X * other.X + other.Y * other.Y).Sqrt).Sign;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="other"></param>
        /// <returns></returns>
        public bool Equals(FinitePoint<TNumber> other)
        {
            return this.X.Equals(other.X) && this.Y.Equals(other.Y);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="obj"></param>
        /// <returns></returns>
        public override bool Equals(object obj)
        {
            if (obj == null)
            {
                return false;
            }

            return this.Equals((FinitePoint<TNumber>)obj);
        }

        /// <summary>
        /// Returns the hash code for the current <see cref="FinitePoint{TNumber}"/> structure.
        /// </summary>
        /// <returns>A 32-bit signed integer hash code.</returns>
        public override int GetHashCode() => this.X.GetHashCode() ^ this.y.GetHashCode();

        /// <summary>
        /// Returns the string representation of the <see cref="FinitePoint{TNumber}"/> structure.
        /// </summary>
        /// <returns></returns>
        public override string ToString () => string.Format (CultureInfo.InvariantCulture, "x={0}; y={1}", this.x, this.y);

        /// <summary>
        /// Evaluates polynomial (coefficient tuple) at x, used to generate a shamir pool.
        /// </summary>
        /// <param name="polynomial"></param>
        /// <param name="x"></param>
        /// <param name="prime">Mersenne prime greater or equal 5</param>
        /// <returns></returns>
        private static Calculator<TNumber> Evaluate(ICollection<Calculator<TNumber>> polynomial, Calculator<TNumber> x, Calculator<TNumber> prime)
        {
            Calculator<TNumber> accum = Calculator<TNumber>.Zero;
            foreach (Calculator<TNumber> coeff in polynomial.Reverse<Calculator<TNumber>>())
            {
                accum = (accum * x + coeff) % prime;
            }

            return accum;
        }
    }
}