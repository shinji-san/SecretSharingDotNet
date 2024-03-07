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

namespace SecretSharingDotNet.Helper;

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

#if NET6_0_OR_GREATER
    /// <summary>
    /// Extends the byte array to a length that is a multiple of the size of an unsigned integer (UInt32).
    /// </summary>
    /// <param name="byteArray">The byte array representing a big integer.</param>
    /// <returns>A span of bytes with the length extended to a multiple of the size of UInt32.</returns>
    public static Span<byte> ExtendToMultipleOfUInt(this Span<byte> byteArray)
    {
        int newLength = (byteArray.Length + sizeof(uint) - 1) / sizeof(uint) * sizeof(uint);
        byte[] extendedArray = new byte[newLength];
        byteArray.CopyTo(extendedArray);
        return new Span<byte>(extendedArray);
    }

    /// <summary>
    /// Trims trailing zeroes from the provided span of bytes.
    /// </summary>
    /// <param name="bytes">The span of bytes from which to trim trailing zeroes.</param>
    /// <returns>A span of bytes with trailing zeroes removed.</returns>
    public static Span<byte> TrimTrailingZeroes(this Span<byte> bytes)
    {
        int length = bytes.Length;
        for (int i = bytes.Length - 1; i >= 0; i--)
        {
            if (bytes[i] == 0)
            {
                length--;
            }
            else
            {
                break;
            }
        }

        return bytes[..length];
    }

    /// <summary>
    /// Applies two's complement to the given byte array, returning a new array
    /// where each byte is the bitwise complement of the original with an increment of 1.
    /// </summary>
    /// <param name="bytes">The byte array to which the two's complement is to be applied.</param>
    /// <returns>A new byte array that represents the two's complement of the input byte array.</returns>
    public static Span<byte> ApplyTwoComplement(this Span<byte> bytes)
    {
        byte[] complementArray = new byte[bytes.Length];
        for (int i = 0; i < bytes.Length; i++)
        {
            complementArray[i] = (byte)~bytes[i];
        }

        bool carry = true;
        for (int i =0; i < complementArray.Length; i++)
        {
            if (!carry)
            {
                continue;
            }

            if (complementArray[i] == byte.MaxValue)
            {
                complementArray[i] = 0;
            }
            else
            {
                complementArray[i]++;
                carry = false;
            }
        }

        return complementArray;
    }

    /// <summary>
    /// Reverses the two's complement representation of a byte sequence and returns the original byte array.
    /// </summary>
    /// <param name="complementArray">The byte array in two's complement form.</param>
    /// <returns>A byte array representing the original binary number before two's complement was applied.</returns>
    public static Span<byte> ReverseTwoComplement(this Span<byte> complementArray)
    {
        byte[] originalArray = new byte[complementArray.Length];
        bool borrow = true;
        for (int i = 0; i < complementArray.Length; i++)
        {
            if (borrow)
            {
                if (complementArray[i] == 0)
                {
                    originalArray[i] = byte.MaxValue;
                }
                else
                {
                    originalArray[i] = (byte)(complementArray[i] - 1);
                    borrow = false;
                }
            }
            else
            {
                originalArray[i] = complementArray[i];
            }
        }
        for(int i = 0; i < complementArray.Length; i++)
        {
            originalArray[i] = (byte)~originalArray[i];
        }

        return originalArray;
    }
#endif
}