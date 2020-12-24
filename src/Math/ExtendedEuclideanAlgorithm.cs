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
        public ExtendedGcdResult<TNumber> Compute(Calculator<TNumber> a, Calculator<TNumber> b)
        {
            var x = Calculator<TNumber>.Zero;
            var lastX = Calculator<TNumber>.One;
            var y = Calculator<TNumber>.One;
            var lastY = Calculator<TNumber>.Zero;
            var r = b;
            var lastR = a;
            while (r != Calculator<TNumber>.Zero)
            {
                checked
                {
                    var quotient = lastR / r;

                    var tmpR = r;
                    r = lastR - quotient * r;
                    lastR = tmpR;

                    var tmpX = x;
                    x = lastX - quotient * x;
                    lastX = tmpX;

                    var tmpY = y;
                    y = lastY - quotient * y;
                    lastY = tmpY;
                }
            }

            var coefficient = new[] { lastX, lastY };
            var quot = new[] { x, y };
            return new ExtendedGcdResult<TNumber>(lastR, coefficient, quot);
        }
    }
}
