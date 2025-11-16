// ----------------------------------------------------------------------------
// <copyright file="Extensions.cs" company="Private">
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

using System;
using System.Collections;

/// <summary>
/// Helper class which contains extension methods
/// </summary>
internal static class Extensions
{
    /// <summary>
    ///  Compares instance <paramref name="a"/> with instance <paramref name="b"/> and returns an indication of their relative values.
    /// </summary>
    /// <typeparam name="TStructural">A data type which implements <see cref="IStructuralComparable"/></typeparam>
    /// <param name="a">The current object to compare with the <paramref name="b"/> instance</param>
    /// <param name="b">The object to compare with the current instance</param>
    /// <returns>-1 if the <paramref name="a"/> instance (current) precedes <paramref name="b"/>, 0 the <paramref name="a"/> instance
    /// and <paramref name="b"/> instance are equal and 1 if the <paramref name="a"/> instance follows <paramref name="b"/>.</returns>
    public static int CompareTo<TStructural>(this TStructural a, TStructural b)
        where TStructural : IStructuralComparable => a.CompareTo(b, StructuralComparisons.StructuralComparer);

    /// <summary>
    /// Creates a new array (destination array) which is a subset of the original array (source array).
    /// </summary>
    /// <typeparam name="TArray">Data type of the array</typeparam>
    /// <param name="array">source array</param>
    /// <param name="index">start index</param>
    /// <param name="count">number of elements to copy to new subset array</param>
    /// <returns>An array that contains the specified number of elements from the <paramref name="index"/> of the <paramref name="array"/>.</returns>
    public static TArray[] Subset<TArray>(this TArray[] array, int index, int count)
    {
        if (array == null)
        {
            throw new ArgumentNullException(nameof(array));
        }

        if (array.Length == 0)
        {
            throw new ArgumentException(ErrorMessages.EmptyCollection, nameof(array));
        }

        if (index < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(index), index, string.Format(ErrorMessages.ValueLowerThanX, 0));
        }

        if (count < 1)
        {
            throw new ArgumentOutOfRangeException(nameof(count), count, string.Format(ErrorMessages.ValueLowerThanX, 1));
        }

        var subset = new TArray[count];
        Array.Copy(array,index, subset, 0, count);
        return subset;
    }
}