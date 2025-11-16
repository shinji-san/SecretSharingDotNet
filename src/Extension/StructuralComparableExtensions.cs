// ----------------------------------------------------------------------------
// <copyright file="StructuralComparableExtensions.cs" company="Private">
// Copyright (c) 2022 All Rights Reserved
// </copyright>
// <author>Sebastian Walther</author>
// <date>02/02/2022 06:54:22 PM</date>
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

namespace SecretSharingDotNet.Extension;

using System.Collections;

/// <summary>
/// Provides extension methods for structural comparison in objects implementing <see cref="IStructuralComparable"/>.
/// </summary>
internal static class StructuralComparableExtensions
{
    /// <summary>
    ///  Compares instance <paramref name="a"/> with instance <paramref name="b"/> and returns an indication of their relative values.
    /// </summary>
    /// <typeparam name="TStructural">A data type which implements <see cref="IStructuralComparable"/></typeparam>
    /// <param name="a">The current object to compare with the <paramref name="b"/> instance</param>
    /// <param name="b">The object to compare with the current instance</param>
    /// <returns>-1 if the <paramref name="a"/> instance (current) precedes <paramref name="b"/>, 0 the <paramref name="a"/> instance
    /// and <paramref name="b"/> instance are equal and 1 if the <paramref name="a"/> instance follows <paramref name="b"/>.</returns>
    internal static int CompareTo<TStructural>(this TStructural a, TStructural b)
        where TStructural : IStructuralComparable => a.CompareTo(b, StructuralComparisons.StructuralComparer);
}