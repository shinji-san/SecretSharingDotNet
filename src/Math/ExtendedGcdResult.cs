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
    public struct ExtendedGcdResult<TNumber> : IEquatable<ExtendedGcdResult<TNumber>>
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="ExtendedGcdResult{TNumber}"/> struct.
        /// </summary>
        /// <param name="gcd">Greatest common divisor</param>
        /// <param name="coeff">Bézout coefficients</param>
        /// <param name="quot">Quotients by the gcd</param>
        public ExtendedGcdResult (Calculator<TNumber> gcd, IList<Calculator<TNumber>> coeff, IList<Calculator<TNumber>> quot)
        {
            this.GreatestCommonDivisor = gcd ??
                throw new System.ArgumentNullException (nameof (gcd));
            this.BezoutCoefficients = new ReadOnlyCollection<Calculator<TNumber>> (coeff);
            this.Quotients = new ReadOnlyCollection<Calculator<TNumber>> (quot);
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
        /// Determines whether this structure and an<paramref name="other"/> specified <see cref="ExtendedGcdResult{TNumber}"/> structure have the same value.
        /// </summary>
        /// <param name="other">The <see cref="ExtendedGcdResult{TNumber}"/> structure to compare</param>
        /// <returns><c>true</c> if the value of the <paramref name="other"/> parameter is the same as the value of this structure; otherwise <c>false</c>.</returns>
        public bool Equals (ExtendedGcdResult<TNumber> other) => this.Quotients.SequenceEqual (other.Quotients) &&
        this.BezoutCoefficients.SequenceEqual (other.BezoutCoefficients) &&
        this.GreatestCommonDivisor == this.GreatestCommonDivisor;

        /// <summary>
        /// Determines whether the specified object is equal to the current <see cref="ExtendedGcdResult{TNumber}"/> structure.
        /// </summary>
        /// <param name="obj">The object to compare with the current <see cref="ExtendedGcdResult{TNumber}"/> structure.</param>
        /// <returns><c>true</c> if the specified object is equal to the current <see cref="ExtendedGcdResult{TNumber}"/> structure; otherwise <c>false</c>.</returns>
        public override bool Equals (object obj)
        {
            if (obj == null)
            {
                return false;
            }

            return this.Equals ((ExtendedGcdResult<TNumber>) obj);
        }

        /// <summary>
        /// Returns the hash code for the current <see cref="ExtendedGcdResult{TNumber}"/> structure.
        /// </summary>
        /// <returns>A 32-bit signed integer hash code.</returns>
        public override int GetHashCode ()
        {
            int hashCode = this.GreatestCommonDivisor.GetHashCode ();
            if (this.BezoutCoefficients != null)
            {
                foreach (var coefficient in this.BezoutCoefficients)
                {
                    hashCode ^= coefficient.GetHashCode ();
                }
            }

            if (this.Quotients != null)
            {
                foreach (var quotient in this.Quotients)
                {
                    hashCode ^= quotient.GetHashCode ();
                }
            }

            return hashCode;
        }
    }
}