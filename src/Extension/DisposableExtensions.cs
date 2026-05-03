// ----------------------------------------------------------------------------
// <copyright file="DisposableExtensions.cs" company="Private">
// Copyright (c) 2026 All Rights Reserved
// </copyright>
// <author>Sebastian Walther</author>
// <date>05/03/2026 00:00:00 AM</date>
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

using System;
using System.Collections.Generic;

/// <summary>
/// Provides extension methods for disposing collections of <see cref="IDisposable"/> elements.
/// </summary>
internal static class DisposableExtensions
{
    /// <summary>
    /// Disposes every non-<see langword="null"/> element in <paramref name="source"/>. Works on
    /// any enumerable — arrays, <see cref="List{T}"/>,
    /// <see cref="System.Collections.ObjectModel.ReadOnlyCollection{T}"/>, etc. A
    /// <see langword="null"/> <paramref name="source"/> is treated as empty so callers can
    /// safely invoke this on partially populated state (for example, an allocation loop
    /// aborted by an exception, or a default-initialised struct whose collection fields are
    /// still <see langword="null"/>).
    /// </summary>
    /// <typeparam name="T">An element type implementing <see cref="IDisposable"/>.</typeparam>
    /// <param name="source">The collection whose elements will be disposed.</param>
    public static void DisposeAll<T>(this IEnumerable<T> source) where T : IDisposable
    {
        if (source is null)
        {
            return;
        }

        foreach (var item in source)
        {
            item?.Dispose();
        }
    }
}