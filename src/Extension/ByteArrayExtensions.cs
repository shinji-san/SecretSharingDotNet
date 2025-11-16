// ----------------------------------------------------------------------------
// <copyright file="ByteArrayExtensions.cs" company="Private">
// Copyright (c) 2025 All Rights Reserved
// </copyright>
// <author>Sebastian Walther</author>
// <date>11/16/2025 02:39:29 AM</date>
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

using System.Runtime.CompilerServices;

/// <summary>
/// Provides extension methods for byte array operations.
/// </summary>
internal static class ByteArrayExtensions
{
    /// <summary>
    /// Compares two byte arrays for equality in a way that resists timing attacks.
    /// </summary>
    /// <param name="valueLeft">The first byte array to compare.</param>
    /// <param name="valueRight">The second byte array to compare.</param>
    /// <returns>
    /// <see langword="true"/> if the two byte arrays are equal in length and content; otherwise, <see langword="false"/>.
    /// </returns>
    /// <remarks>This is a Slow Equal Implementation to avoid a timing attack. See the reference for more details:
    /// https://bryanavery.co.uk/cryptography-net-avoiding-timing-attack/</remarks>
    [MethodImpl(MethodImplOptions.NoOptimization | MethodImplOptions.NoInlining)]
    internal static bool FixedTimeEquals(this byte[] valueLeft, byte[] valueRight)
    {
        valueLeft ??= [];
        valueRight ??= [];
        var diff = (uint)valueLeft.Length ^ (uint)valueRight.Length;
        int maxLength = System.Math.Max(valueLeft.Length, valueRight.Length);
        for (var i = 0; i < maxLength; i++)
        {
            byte byteLeft = i < valueLeft.Length ? valueLeft[i] : (byte)0;
            byte byteRight = i < valueRight.Length ? valueRight[i] : (byte)0;
            diff |= (uint)(byteLeft ^ byteRight);
        }

        return diff == 0;
    }
}