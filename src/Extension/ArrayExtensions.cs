// ----------------------------------------------------------------------------
// <copyright file="ArrayExtensions.cs" company="Private">
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
using System.Runtime.CompilerServices;

/// <summary>
/// Provides extension methods for array operations.
/// </summary>
internal static class ArrayExtensions
{
    /// <summary>
    /// Compares two byte arrays for equality in a way that resists timing attacks.
    /// </summary>
    /// /// <param name="valueLeft">The first byte array to compare.</param>
    /// <param name="valueRight">The second byte array to compare.</param>
    /// <param name="lengthLeft">The length of the first byte array to compare.</param>
    /// <param name="lengthRight">The length of the second byte array to compare.</param>
    /// <returns>
    /// <see langword="true"/> if the two byte arrays are equal in length and content; otherwise, <see langword="false"/>.
    /// </returns>
    /// <remarks>This is a Slow Equal Implementation to avoid a timing attack. See the reference for more details:
    /// https://bryanavery.co.uk/cryptography-net-avoiding-timing-attack/</remarks>
    [MethodImpl(MethodImplOptions.NoOptimization | MethodImplOptions.NoInlining)]
    internal static bool FixedTimeEquals(this byte[] valueLeft, byte[] valueRight, int lengthLeft, int lengthRight)
    {
        var diff = (uint)(lengthLeft ^ lengthRight);
        var maxLength = Math.Max(lengthLeft, lengthRight);
        for (var i = 0; i < maxLength; i++)
        {
            var byteLeft = i < lengthLeft ? valueLeft[i] : (byte)0;
            var byteRight = i < lengthRight ? valueRight[i] : (byte)0;
            diff |= (uint)(byteLeft ^ byteRight);
        }

        return diff == 0;
    }
}