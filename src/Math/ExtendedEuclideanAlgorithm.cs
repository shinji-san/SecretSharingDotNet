// ----------------------------------------------------------------------------
// <copyright file="ExtendedEuclideanAlgorithm.cs" company="Private">
// Copyright (c) 2019 All Rights Reserved
// </copyright>
// <author>Sebastian Walther</author>
// <date>04/20/2019 10:52:28 PM</date>
// ----------------------------------------------------------------------------

namespace SecretSharingDotNet.Math
{
    /// <summary>
    /// Extended Euclidean algorithm implementation
    /// </summary>
    /// <typeparam name="TNumber">Numeric data type (An integer type)</typeparam>
    public class ExtendedEuclideanAlgorithm<TNumber> : IExtendedGcdAlgorithm<TNumber>
    {
        /// <summary>
        /// Computes, in addition to the greatest common divisor of integers <paramref name="a"/> and <paramref name="b"/>, also the coefficients of Bézout's identity.
        /// </summary>
        /// <param name="a">An integer</param>
        /// <param name="b">An integer</param>
        /// <returns>For details: <see cref="ExtendedGcdResult{TNumber}"/></returns>
        /// <remarks>
        /// https://en.wikipedia.org/wiki/Modular_multiplicative_inverse#Computation 
        /// https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm#Example
        /// </remarks>
        public ExtendedGcdResult<TNumber> Compute (Calculator<TNumber> a, Calculator<TNumber> b)
        {
            var x = Calculator<TNumber>.Zero;
            var last_x = Calculator<TNumber>.One;
            var y = Calculator<TNumber>.One;
            var last_y = Calculator<TNumber>.Zero;
            var r = b;
            var last_r = a;
            while (r != Calculator<TNumber>.Zero)
            {
                checked
                {
                    var quotient = last_r / r;

                    var tmpR = r;
                    r = last_r - quotient * r;
                    last_r = tmpR;

                    var tmpX = x;
                    x = last_x - quotient * x;
                    last_x = tmpX;

                    var tmpY = y;
                    y = last_y - quotient * y;
                    last_y = tmpY;
                }
            }

            var coeff = new Calculator<TNumber>[] { last_x, last_y };
            var quot = new Calculator<TNumber>[] { x, y };
            return new ExtendedGcdResult<TNumber>(last_r, coeff, quot);
        }
    }
}