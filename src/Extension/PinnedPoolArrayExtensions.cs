// ----------------------------------------------------------------------------
// <copyright file="PinnedPoolArrayExtensions.cs" company="Private">
// Copyright (c) 2026 All Rights Reserved
// </copyright>
// <author>Sebastian Walther</author>
// <date>01/18/2026 04:17:58 AM</date>
// ----------------------------------------------------------------------------

#region License

// ----------------------------------------------------------------------------
// Copyright 2026 Sebastian Walther
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

using Cryptography.SecureArray;
using System;
using System.Runtime.CompilerServices;

internal static class PinnedPoolArrayExtensions
{
    /// <summary>
    /// Creates a new array (destination array) which is a subset of the original array (source array).
    /// </summary>
    /// <typeparam name="TArray">Data type of the array</typeparam>
    /// <param name="array">source array</param>
    /// <param name="index">start index</param>
    /// <param name="count">number of elements to copy to a new subset array</param>
    /// <returns>An array that contains the specified number of elements from the <paramref name="index"/> of the <paramref name="array"/>.</returns>
    /// <remarks>
    /// <para>
    /// If the post-allocation write throws, the pinned buffer is disposed before the
    /// exception is rethrown — no reference to a partially-filled buffer escapes.
    /// </para>
    /// </remarks>
    internal static PinnedPoolArray<TArray> Subset<TArray>(this PinnedPoolArray<TArray> array, int index, int count)
        where TArray : unmanaged
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
            throw new ArgumentOutOfRangeException(nameof(index), index,
                string.Format(ErrorMessages.ValueLowerThanX, 0));
        }

        if (count < 1)
        {
            throw new ArgumentOutOfRangeException(nameof(count), count,
                string.Format(ErrorMessages.ValueLowerThanX, 1));
        }

        var subset = new PinnedPoolArray<TArray>(count);
        try
        {
            Array.Copy(array.PoolArray, index, subset.PoolArray, 0, count);
        }
        catch
        {
            subset.Dispose();
            throw;
        }

        return subset;
    }

    [MethodImpl(MethodImplOptions.NoOptimization | MethodImplOptions.NoInlining)]
    internal static bool FixedTimeEquals(this PinnedPoolArray<byte> valueLeft, PinnedPoolArray<byte> valueRight)
    {
        return valueLeft.PoolArray.FixedTimeEquals(valueRight.PoolArray, valueLeft.Length, valueRight.Length);
    }
}