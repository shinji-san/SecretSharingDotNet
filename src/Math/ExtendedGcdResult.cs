// ----------------------------------------------------------------------------
// <copyright file="ExtendedGcdResult.cs" company="Private">
// Copyright (c) 2022 All Rights Reserved
// </copyright>
// <author>Sebastian Walther</author>
// <date>08/20/2022 02:32:46 PM</date>
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
    using System.Linq;

    /// <summary>
    /// Represents the result of the extended greatest common divisor computation.
    /// </summary>
    /// <typeparam name="TNumber">Numeric data type</typeparam>
    public readonly struct ExtendedGcdResult<TNumber> : IExtendedGcdResult<TNumber>, IEquatable<ExtendedGcdResult<TNumber>>
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="ExtendedGcdResult{TNumber}"/> struct.
        /// </summary>
        /// <param name="gcd">Greatest common divisor</param>
        /// <param name="coefficients">Bézout coefficients</param>
        /// <param name="quotients">Quotients by the gcd</param>
        public ExtendedGcdResult(Calculator<TNumber> gcd, IList<Calculator<TNumber>> coefficients, IList<Calculator<TNumber>> quotients)
        {
            this.GreatestCommonDivisor = gcd ?? throw new ArgumentNullException(nameof(gcd));
            this.BezoutCoefficients = new ReadOnlyCollection<Calculator<TNumber>>(coefficients);
            this.Quotients = new ReadOnlyCollection<Calculator<TNumber>>(quotients);
        }

        /// <inheritdoc />
        public Calculator<TNumber> GreatestCommonDivisor { get; }

        /// <inheritdoc />
        public ReadOnlyCollection<Calculator<TNumber>> BezoutCoefficients { get; }

        /// <inheritdoc />
        public ReadOnlyCollection<Calculator<TNumber>> Quotients { get; }

        /// <summary>
        /// Equality operator
        /// </summary>
        /// <param name="left">The left operand</param>
        /// <param name="right">The right operand</param>
        /// <returns>Returns <see langword="true"/> if its operands are equal, otherwise <see langword="false"/>.</returns>
        public static bool operator ==(ExtendedGcdResult<TNumber> left, ExtendedGcdResult<TNumber> right) => left.Equals(right);

        /// <summary>
        /// Inequality operator
        /// </summary>
        /// <param name="left">The left operand</param>
        /// <param name="right">The right operand</param>
        /// <returns>Returns <see langword="true"/> if its operands are not equal, otherwise <see langword="false"/>.</returns>
        public static bool operator !=(ExtendedGcdResult<TNumber> left, ExtendedGcdResult<TNumber> right) => !left.Equals(right);

        /// <summary>
        /// Determines whether this structure and an<paramref name="other"/> specified <see cref="ExtendedGcdResult{TNumber}"/> structure have the same value.
        /// </summary>
        /// <param name="other">The <see cref="ExtendedGcdResult{TNumber}"/> structure to compare</param>
        /// <returns><see langword="true"/> if the value of the <paramref name="other"/> parameter is the same as the value of this structure; otherwise <see langword="false"/>.</returns>
        public bool Equals(ExtendedGcdResult<TNumber> other) => this.Quotients.SequenceEqual(other.Quotients) &&
                                                                this.BezoutCoefficients.SequenceEqual(other.BezoutCoefficients) &&
                                                                this.GreatestCommonDivisor == other.GreatestCommonDivisor;

        /// <summary>
        /// Determines whether the specified object is equal to the current <see cref="ExtendedGcdResult{TNumber}"/> structure.
        /// </summary>
        /// <param name="obj">The object to compare with the current <see cref="ExtendedGcdResult{TNumber}"/> structure.</param>
        /// <returns><see langword="true"/> if the specified object is equal to the current <see cref="ExtendedGcdResult{TNumber}"/> structure; otherwise <see langword="false"/>.</returns>
        public override bool Equals(object obj)
        {
            return obj != null && this.Equals((ExtendedGcdResult<TNumber>)obj);
        }

        /// <summary>
        /// Returns the hash code for the current <see cref="ExtendedGcdResult{TNumber}"/> structure.
        /// </summary>
        /// <returns>A 32-bit signed integer hash code.</returns>
        public override int GetHashCode()
        {
            int hashCode = this.GreatestCommonDivisor.GetHashCode();
            if (this.BezoutCoefficients != null)
            {
                hashCode = this.BezoutCoefficients.Aggregate(hashCode, (current, coefficient) => current ^ coefficient.GetHashCode());
            }

            if (this.Quotients != null)
            {
                hashCode = this.Quotients.Aggregate(hashCode, (current, quotient) => current ^ quotient.GetHashCode());
            }

            return hashCode;
        }
    }
}
