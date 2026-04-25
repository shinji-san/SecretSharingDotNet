// ----------------------------------------------------------------------------
// <copyright file="CountedEqualityComparer`1.cs" company="Private">
// Copyright (c) 2026 All Rights Reserved
// </copyright>
// <author>Sebastian Walther</author>
// <date>01/29/2026 09:32:26 PM</date>
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

namespace SecretSharingDotNet.Cryptography.SecureArray;

using System;
using System.Collections;
using System.Collections.Generic;

/// <summary>
/// An element comparer that additionally carries the number of elements to compare.
/// Pass this instance into <see cref="IStructuralEquatable.Equals(object, IEqualityComparer)"/>.
/// </summary>
/// <typeparam name="T">Element type.</typeparam>
public sealed class CountedEqualityComparer<T> : ICountedEqualityComparer<T>
{
    /// <summary>
    /// The element comparer used to compare individual elements of type <typeparamref name="T"/>.
    /// This comparer is utilized within the implementation of equality checks and hash code generation
    /// for comparing elements based on the logic defined in the associated <see cref="IEqualityComparer{T}"/>.
    /// </summary>
    private readonly IEqualityComparer<T> elementComparer;

    /// <summary>
    /// Creates a new instance.
    /// </summary>
    /// <param name="count">Number of elements to compare.</param>
    /// <param name="elementComparer">Optional element comparer; defaults to <see cref="EqualityComparer{T}.Default"/>.</param>
    /// <exception cref="ArgumentOutOfRangeException">Thrown when <paramref name="count"/> is negative.</exception>
    public CountedEqualityComparer(int count, IEqualityComparer<T> elementComparer = null)
    {
        if (count < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(count), string.Format(ErrorMessages.ValueLowerThanX, 0));
        }

        this.Count = count;
        this.elementComparer = elementComparer ?? EqualityComparer<T>.Default;
    }

    /// <inheritdoc />
    public int Count { get; }

    /// <inheritdoc />
    public bool Equals(T x, T y) => this.elementComparer.Equals(x, y);

    /// <inheritdoc />
    public int GetHashCode(T obj) => this.elementComparer.GetHashCode(obj);

    /// <summary>
    /// Determines whether the specified objects are equal.
    /// </summary>
    /// <param name="x">The first object to compare.</param>
    /// <param name="y">The second object to compare.</param>
    /// <returns><see langword="true"/> if the specified objects are equal; otherwise, <see langword="false"/>.</returns>
    /// <exception cref="ArgumentException">
    /// Thrown when the types of <paramref name="x"/> or <paramref name="y"/> do not match the expected type.
    /// </exception>
    bool IEqualityComparer.Equals(object x, object y)
    {
        if (x is null || y is null)
        {
            return x is null && y is null;
        }

        if (x is not T firstElement || y is not T secondElement)
        {
            throw new ArgumentException(string.Format(ErrorMessages.ComparerExpectedTypeX, typeof(T).FullName));
        }

        return this.Equals(firstElement, secondElement);
    }

    /// <summary>
    /// Computes the hash code for the specified object.
    /// </summary>
    /// <param name="obj">The object for which the hash code is to be computed.</param>
    /// <returns>The hash code of the specified object.</returns>
    /// <exception cref="ArgumentException">
    /// Thrown when <paramref name="obj"/> is not of the expected type <typeparamref name="T"/>.
    /// </exception>
    int IEqualityComparer.GetHashCode(object obj)
    {
        if (obj is not T value)
        {
            throw new ArgumentException(string.Format(ErrorMessages.ComparerExpectedTypeX, typeof(T).FullName));
        }

        return this.GetHashCode(value);
    }
}