// ----------------------------------------------------------------------------
// <copyright file="ExtendedGcdResult.cs" company="Private">
// Copyright (c) 2019 All Rights Reserved
// </copyright>
// <author>Sebastian Walther</author>
// <date>04/20/2019 10:52:28 PM</date>
// ----------------------------------------------------------------------------

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
    public readonly struct ExtendedGcdResult<TNumber> : IEquatable<ExtendedGcdResult<TNumber>>
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

        /// <summary>
        /// Gets the greatest common divisor
        /// </summary>
        public Calculator<TNumber> GreatestCommonDivisor { get; }

        /// <summary>
        /// Gets the Bézout coefficients 
        /// </summary>
        public ReadOnlyCollection<Calculator<TNumber>> BezoutCoefficients { get; }

        /// <summary>
        /// Gets the quotients by the gcd
        /// </summary>
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