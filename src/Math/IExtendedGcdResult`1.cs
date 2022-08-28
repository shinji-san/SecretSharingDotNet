// ----------------------------------------------------------------------------
// <copyright file="IExtendedGcdResult`1.cs" company="Private">
// Copyright (c) 2022 All Rights Reserved
// </copyright>
// <author>Sebastian Walther</author>
// <date>08/20/2022 01:20:59 AM</date>
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
    using System.Collections.ObjectModel;

    /// <summary>
    /// Represents the result of the extended greatest common divisor computation.
    /// </summary>
    /// <typeparam name="TNumber">Numeric data type</typeparam>
    public interface IExtendedGcdResult<TNumber>
    {
        /// <summary>
        /// Gets the greatest common divisor
        /// </summary>
        Calculator<TNumber> GreatestCommonDivisor { get; }

        /// <summary>
        /// Gets the Bézout coefficients
        /// </summary>
        ReadOnlyCollection<Calculator<TNumber>> BezoutCoefficients { get; }

        /// <summary>
        /// Gets the quotients by the gcd
        /// </summary>
        ReadOnlyCollection<Calculator<TNumber>> Quotients { get; }
    }
}
