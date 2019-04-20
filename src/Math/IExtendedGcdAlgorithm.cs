// ----------------------------------------------------------------------------
// <copyright file="IExtendedGcdAlgorithm.cs" company="Private">
// Copyright (c) 2019 All Rights Reserved
// </copyright>
// <author>Sebastian Walther</author>
// <date>04/20/2019 10:52:28 PM</date>
// ----------------------------------------------------------------------------

namespace SecretSharingDotNet.Math
{
    /// <summary>
    /// Provides mechanism to compute the extended greatest common divisor
    /// including Bézout coefficients.
    /// </summary>
    /// <typeparam name="TNumber">Numeric data type (An integer type)</typeparam>
    public interface IExtendedGcdAlgorithm<TNumber>
    {
        /// <summary>
        /// Computes, in addition to the greatest common divisor of integers <paramref name="a"/> and <paramref name="b"/>, also the coefficients of Bézout's identity.
        /// </summary>
        /// <param name="a">An integer</param>
        /// <param name="b">An integer</param>
        /// <returns>For details: <see cref="ExtendedGcdResult{TNumber}"/></returns>
        ExtendedGcdResult<TNumber> Compute(Calculator<TNumber> a, Calculator<TNumber> b);
    }
}