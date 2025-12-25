// ----------------------------------------------------------------------------
// <copyright file="ShareExtensions.cs" company="Private">
// Copyright (c) 2025 All Rights Reserved
// </copyright>
// <author>Sebastian Walther</author>
// <date>12/24/2025 10:44:47 PM</date>
// ----------------------------------------------------------------------------

#region License
// ----------------------------------------------------------------------------
// Copyright 2025 Sebastian Walther
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

namespace SecretSharingDotNet.Extension;

using Cryptography;
using System;
using System.Collections.Generic;
using System.Linq;

/// <summary>
/// Provides extension methods for working with shares.
/// </summary>
public static class ShareExtensions
{
    /// <summary>
    /// Converts a collection of shares to an array of <see cref="FinitePoint{TNumber}"/>.
    /// </summary>
    /// <param name="shares">The collection of shares to convert.</param>
    /// <returns>An array of finite points.</returns>
    public static FinitePoint<TNumber>[] ToFinitePoints<TNumber>(this IEnumerable<Share<TNumber>> shares)
    {
        if (shares is null)
        {
            throw new ArgumentNullException(nameof(shares));
        }

        return shares.Select(s => new FinitePoint<TNumber>(s.Index, s.Value)).ToArray();
    }

    /// <summary>
    /// Converts a collection of <see cref="FinitePoint{T}"/> to an array of shares.
    /// </summary>
    /// <param name="points">The collection of finite points to convert.</param>
    /// <returns>An array of shares.</returns>
    public static Share<TNumber>[] ToShares<TNumber>(this IEnumerable<FinitePoint<TNumber>> points)
    {
        if (points is null)
        {
            throw new ArgumentNullException(nameof(points));
        }
        return points.Select(p => new Share<TNumber>(p.X, p.Y)).ToArray();
    }
}