// ----------------------------------------------------------------------------
// <copyright file="SecureBigInteger.cs" company="Private">
// Copyright (c) 2024 All Rights Reserved
// </copyright>
// <author>Sebastian Walther</author>
// <date>04/01/2024 07:34:00 PM</date>
// ----------------------------------------------------------------------------

#region License

// ----------------------------------------------------------------------------
// Copyright 2024 Sebastian Walther
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

#if NET6_0_OR_GREATER
namespace SecretSharingDotNet.Math;

using System;
using System.Buffers.Binary;
using System.Numerics;
using System.Runtime.InteropServices;
using System.Text;
using Helper;
using System.Globalization;

/// <summary>
/// Represents a secure big integer.
/// </summary>
public sealed class SecureBigInteger :
    IDisposable,
    IComparable,
    IComparable<SecureBigInteger>,
    IEquatable<SecureBigInteger>,
    ICloneable
{
    /// <summary>
    /// Represents the length of the internal representation of the <see cref="SecureBigInteger"/>.
    /// </summary>
    private readonly int length;

    /// <summary>
    /// Represents the number of digits in the internal representation of the <see cref="SecureBigInteger"/>.
    /// </summary>
    private readonly int digitsLength;

    /// <summary>
    /// Pointer to the array of unsigned integers representing the digits of the <see cref="SecureBigInteger"/>.
    /// </summary>
    private readonly unsafe uint* digitsPtr;

    /// <summary>
    /// Indicates whether the <see cref="SecureBigInteger"/> is negative.
    /// </summary>
    private bool isNegative;

    /// <summary>
    /// A handle used to pin the array of digits in memory, preventing garbage collection
    /// and ensuring safe access to the native pointer.
    /// </summary>
    private GCHandle digitsHandle;

    /// <summary>
    /// Holds a collection of disposable resources and ensures their disposal when the owning object is disposed.
    /// </summary>
    private readonly CompositeDisposable compositeDisposable = CompositeDisposableContext.Current.Value;

    /// <summary>
    /// Indicates whether the <see cref="SecureBigInteger"/> instance has been disposed.
    /// </summary>
    private bool disposed;

    /// <summary>
    /// Initializes a new instance of the <see cref="SecureBigInteger"/> class.
    /// </summary>
    /// <param name="digits">The pointer to the digits.</param>
    /// <param name="digitsHandle">The handle to the digits.</param>
    /// <param name="length">The length of the digits without trailing zeros.</param>
    /// <param name="digitsLength">The length of the digit unsigned integer array.</param>
    /// <param name="isNegative">A value indicating whether the big integer is negative.</param>
    /// <remarks>
    /// The handle must be pinned to prevent the garbage collector from moving the object in memory.
    /// </remarks>
    private unsafe SecureBigInteger(uint* digits, GCHandle digitsHandle, int length, int digitsLength, bool isNegative = false)
    {
        this.digitsPtr = digits;
        this.length = length;
        this.digitsLength = digitsLength;
        this.digitsHandle = digitsHandle;
        this.isNegative = !this.IsZero && isNegative;
        this.compositeDisposable?.Add(this);
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="SecureBigInteger"/> class.
    /// </summary>
    /// <param name="bytes">The byte representation of the <see cref="SecureBigInteger"/>.</param>
    public unsafe SecureBigInteger(Span<byte> bytes)
    {
        var x = (bytes[^1] & 0x80) != 0 ? bytes.ReverseTwoComplement() : bytes;
        
        var extendToMultipleOfUInt = x.ExtendToMultipleOfUInt();
        uint[] digits = new uint[(extendToMultipleOfUInt.Length + 3) / 4];
        this.digitsHandle = GCHandle.Alloc(digits, GCHandleType.Pinned);
        this.digitsPtr = (uint*)this.digitsHandle.AddrOfPinnedObject();
        for (int i = 0; i < extendToMultipleOfUInt.Length; i += 4)
        {
            digits[i / 4] = BinaryPrimitives.ReadUInt32LittleEndian(extendToMultipleOfUInt.Slice(i, 4));
        }
        
        int newLength = digits.Length;
        while (newLength > 1 && digits[newLength - 1] == 0)
        {
            newLength--;
        }
        this.length = newLength;
        this.digitsLength = digits.Length;
        this.isNegative = (bytes[^1] & 0x80) != 0;
        this.compositeDisposable?.Add(this);
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="SecureBigInteger"/> class.
    /// </summary>
    /// <param name="value">The value of the big integer as a 32-bit signed integer.</param>
    public unsafe SecureBigInteger(int value)
    {
        uint[] digits = new uint[1];
        digits[0] = (uint)Math.Abs((long)value);
        this.digitsHandle = GCHandle.Alloc(digits, GCHandleType.Pinned);
        this.digitsPtr = (uint*)this.digitsHandle.AddrOfPinnedObject();
        this.length = digits.Length;
        this.digitsLength = digits.Length;
        this.isNegative = value < 0;
        this.compositeDisposable?.Add(this);
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="SecureBigInteger"/> class.
    /// </summary>
    /// <param name="value">The value of the big integer as a 32-bit unsigned integer.</param>
    [CLSCompliant(false)]
    public unsafe SecureBigInteger(uint value)
    {
        uint[] digits = new uint[1];
        digits[0] = value;
        this.digitsHandle = GCHandle.Alloc(digits, GCHandleType.Pinned);
        this.digitsPtr = (uint*)this.digitsHandle.AddrOfPinnedObject();
        this.length = digits.Length;
        this.digitsLength = digits.Length;
        this.isNegative = false;
        this.compositeDisposable?.Add(this);
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="SecureBigInteger"/> class.
    /// </summary>
    /// <param name="value">The value of the big integer as a 64-bit unsigned integer.</param>
    [CLSCompliant(false)]
    public unsafe SecureBigInteger(ulong value)
    {
        int maxLength = (uint)(value >> 32) == 0 ? 1 : 2;
        uint[] digits = new uint[maxLength];
        digits[0] = (uint)value;
        if (maxLength == 2)
        {
            digits[1] = (uint)(value >> 32);
        }
        this.digitsHandle = GCHandle.Alloc(digits, GCHandleType.Pinned);
        this.digitsPtr = (uint*)this.digitsHandle.AddrOfPinnedObject();
        this.length = digits.Length;
        this.digitsLength = digits.Length;
        this.isNegative = false;
        this.compositeDisposable?.Add(this);
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="SecureBigInteger"/> class.
    /// </summary>
    /// <param name="value">The value of the big integer as a 64-bit signed integer.</param>
    public unsafe SecureBigInteger(long value)
    {
        int maxLength = (uint)(value >> 32) == 0 ? 1 : 2;
        uint[] digits = new uint[maxLength];
        digits[0] = (uint)Math.Abs(value);
        if (maxLength == 2)
        {
            digits[1] = (uint)(Math.Abs(value) >> 32);
        }
        this.digitsHandle = GCHandle.Alloc(digits, GCHandleType.Pinned);
        this.digitsPtr = (uint*)this.digitsHandle.AddrOfPinnedObject();
        this.length = digits.Length;
        this.digitsLength = digits.Length;
        this.isNegative = value < 0;
        this.compositeDisposable?.Add(this);
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="SecureBigInteger"/> class.
    /// </summary>
    /// <param name="value">The value of the big integer as a <see cref="BigInteger"/>.</param>
    public SecureBigInteger(BigInteger value) : this(value.ToByteArray())
    {
    }

    /// <summary>
    /// Finalizes an instance of the <see cref="SecureBigInteger"/> class.
    /// </summary>
    ~SecureBigInteger()
    {
        this.Dispose(false);
    }
    
    /// <summary>
    /// Gets a value indicating whether the object has been disposed.
    /// </summary>
    public bool IsDisposed => this.disposed;

    /// <summary>
    /// Gets the sign of the secure big integer.
    /// Returns 0 if the value is zero,–1 if negative, and 1 if positive.
    /// </summary>
    public int Sign => this.IsZero ? 0 : (this.isNegative ? -1 : 1);
    
    /// <summary>
    /// Gets a value indicating whether the big integer is even.
    /// </summary>
    public unsafe bool IsEven => (this.digitsPtr[0] & 1) == 0;

    /// <summary>
    /// Gets a value indicating whether the big integer is odd.
    /// </summary>
    public unsafe bool IsOdd => (this.digitsPtr[0] & 1) == 1;

    /// <summary>
    /// Gets a value indicating whether the <see cref="SecureBigInteger"/> is zero.
    /// </summary>
    /// <remarks>
    /// The IsZero property returns true if all the digits of the <see cref="SecureBigInteger"/> are zero; otherwise, false.
    /// </remarks>
    public unsafe bool IsZero
    {
        get
        {
            for (int i = 0; i < this.length; ++i)
            {
                if (this.digitsPtr[i] != 0)
                {
                    return false;
                }
            }

            return true;
        }
    }

    /// <summary>
    /// Gets a value indicating whether the <see cref="SecureBigInteger"/> is one.
    /// </summary>
    public unsafe bool IsOne
    {
        get
        {
            for (int i = 1; i < this.length; ++i)
            {
                if (this.digitsPtr[i] != 0)
                {
                    return false;
                }
            }

            return this.digitsPtr[0] == 1 && !this.isNegative;
        }
    }

    /// <summary>
    /// Gets a value representing zero value of <see cref="SecureBigInteger"/>.
    /// </summary>
    public static unsafe SecureBigInteger Zero
    {
        get
        {
            uint[] zeroDigits = [0];
            var zeroHandle = GCHandle.Alloc(zeroDigits, GCHandleType.Pinned);
            return new SecureBigInteger((uint*)zeroHandle.AddrOfPinnedObject(), zeroHandle, 1, zeroDigits.Length);
        }
    }

    /// <summary>
    /// Gets a value representing one value of <see cref="SecureBigInteger"/>.
    /// </summary>
    public static unsafe SecureBigInteger One
    {
        get
        {
            uint[] oneDigits = [1];
            var oneHandle = GCHandle.Alloc(oneDigits, GCHandleType.Pinned);
            return new SecureBigInteger((uint*)oneHandle.AddrOfPinnedObject(), oneHandle, 1, oneDigits.Length);
        }
    }
    
    /// <summary>
    /// Gets a value indicating whether the current instance represents a negative one (-1).
    /// </summary>
    private unsafe bool IsNegativeOne
    {
        get
        {
            for (int i = 1; i < this.length; ++i)
            {
                if (this.digitsPtr[i] != 0)
                {
                    return false;
                }
            }

            return this.digitsPtr[0] == 1 && this.isNegative;
        }
    }

    /// <summary>
    /// Gets the total number of bytes used to represent the <see cref="SecureBigInteger"/>.
    /// </summary>
    private int ByteCount => this.length * sizeof(uint);

    /// <summary>
    /// Converts the current <see cref="SecureBigInteger"/> instance to an array of bytes in little-endian format.
    /// </summary>
    /// <returns>An array of bytes representing the value of the current <see cref="SecureBigInteger"/> instance.</returns>
    public unsafe Span<byte> ToByteSpan()
    {
        var bytes = new Span<byte>(new byte[this.ByteCount]);
        for (int i = 0; i < this.length; i++)
        {
            BinaryPrimitives.WriteUInt32LittleEndian(bytes[(i * sizeof(uint))..], this.digitsPtr[i]);
        }

        var trimTrailingZeroes = bytes.TrimTrailingZeroes();
        return !this.IsZero && this.isNegative ? trimTrailingZeroes.ApplyTwoComplement() : trimTrailingZeroes;
    }

    /// <summary>
    /// Raises the current <see cref="SecureBigInteger"/> to the specified exponent.
    /// </summary>
    /// <param name="exponent">The exponent to which the current instance is raised. Must be greater than or equal to zero.</param>
    /// <returns>A new <see cref="SecureBigInteger"/> instance representing the result of the current instance raised to the specified exponent.</returns>
    /// <exception cref="ArgumentOutOfRangeException">Thrown when the exponent is less than zero.</exception>
    public SecureBigInteger Pow(int exponent)
    {
        switch (exponent)
        {
            case < 0:
                throw new ArgumentOutOfRangeException(nameof(exponent), "The exponent must be greater than or equal to zero.");
            case 0:
                return One;
            case 1:
                return this.Clone() as SecureBigInteger;
        }

        var result = One;
        var baseValue = this.Clone() as SecureBigInteger;
        bool resultIsNegative = this.isNegative && (exponent % 2 != 0);
        try
        {
            while (exponent > 0)
            {
                if ((exponent & 1) == 1)
                {
                    var tempResult = result * baseValue;
                    result.Dispose();
                    result = tempResult;
                }

                exponent >>= 1;
                var tempBaseValue = baseValue * baseValue;
                baseValue?.Dispose();
                baseValue = tempBaseValue;
            }
        }
        finally
        {
            baseValue?.Dispose();
        }
        
        result.isNegative = resultIsNegative;
        return result;
    }

    /// <summary>
    /// Computes the square root of the current <see cref="SecureBigInteger"/> instance.
    /// </summary>
    /// <returns>A new <see cref="SecureBigInteger"/> instance representing the square root of the current instance.</returns>
    public SecureBigInteger SquareRoot()
    {
        var x0 = this.Clone() as SecureBigInteger;
        using SecureBigInteger two = 2;
        var x1 = (x0 + this / x0) / two;
        
        while (x1 < x0)
        {
            x0?.Dispose();
            x0 = x1;
            x1 = (x0 + this / x0) / two;
        }

        x1.Dispose();
        return x0;
    }

    /// <summary>
    /// Returns the absolute value of the current <see cref="SecureBigInteger"/> instance.
    /// </summary>
    /// <returns>A new <see cref="SecureBigInteger"/> representing the absolute value of the current instance.</returns>
    public SecureBigInteger Abs()
    {
        var secureBigInteger = this.Clone() as SecureBigInteger;
        secureBigInteger!.isNegative = false;
        return secureBigInteger;
    }

    /// <inheritdoc />
    public unsafe object Clone()
    {
        uint[] myDigits = new uint[this.length];
        var myDigitsHandle = GCHandle.Alloc(myDigits, GCHandleType.Pinned);
        for (int i = 0; i < this.length; i++)
        {
            myDigits[i] = this.digitsPtr[i];
        }

        uint* myDigitsPtr = (uint*)myDigitsHandle.AddrOfPinnedObject();
        return new SecureBigInteger(myDigitsPtr, myDigitsHandle, this.length, this.length, this.isNegative);
    }

    /// <summary>
    /// Compares the current instance with another <see cref="SecureBigInteger"/> and returns an integer that indicates
    /// whether the current instance precedes, follows, or occurs in the same position in the sort order as the other <see cref="SecureBigInteger"/>.
    /// </summary>
    /// <param name="other">The <see cref="SecureBigInteger"/> to compare with the current instance.</param>
    /// <returns>
    /// A value that indicates the relative order of the objects being compared. The return value has these meanings:
    /// Less than zero: This instance precedes <paramref name="other"/> in the sort order.
    /// Zero: This instance occurs in the same position in the sort order as <paramref name="other"/>.
    /// Greater than zero: This instance follows <paramref name="other"/> in the sort order.
    /// </returns>
    public unsafe int CompareTo(SecureBigInteger other)
    {
        if (other is null)
        {
            return 1;
        }
        
        if (this.isNegative && !other.isNegative)
        {
            return -1;
        }
        
        if (!this.isNegative && other.isNegative)
        {
            return 1;
        }

        if (this.length > other.length)
        {
            return 1;
        }

        if (this.length < other.length)
        {
            return -1;
        }

        for (int i = this.length - 1; i >= 0; i--)
        {
            if (this.digitsPtr[i] > other.digitsPtr[i])
            {
                return 1;
            }

            if (this.digitsPtr[i] < other.digitsPtr[i])
            {
                return -1;
            }
        }

        return 0;
    }

    /// <summary>
    /// Compares the current instance with another object of the same type and returns an integer that indicates whether the current instance
    /// precedes, follows, or occurs in the same position in the sort order as the other object.
    /// </summary>
    /// <param name="obj">The object to compare with the current instance.</param>
    /// <returns>A value that indicates the relative order of the objects being compared.</returns>
    public int CompareTo(object obj)
    {
        return obj switch
        {
            null => 1,
            SecureBigInteger otherBigInt => this.CompareTo(otherBigInt),
            _ => throw new ArgumentException("Object is not a SecureBigInteger", nameof(obj))
        };
    }

    /// <summary>
    /// Computes the hash code for the <see cref="SecureBigInteger"/> object.
    /// </summary>
    /// <returns>The computed hash code.</returns>
    public override unsafe int GetHashCode()
    {
        unchecked
        {
            int hashCode = this.length;
            hashCode = (hashCode * 397) ^ this.digitsLength;
            hashCode = (hashCode * 397) ^ unchecked((int)(long)this.digitsPtr);
            return hashCode;
        }
    }
    
    /// <summary>
    /// Determines whether the current instance of <see cref="SecureBigInteger"/> is equal to another object.
    /// </summary>
    /// <param name="obj">The object to compare with the current instance.</param>
    /// <returns>
    /// Returns <see langword="true"/> if the current instance is equal to the other object; otherwise, <see langword="false"/>.
    /// </returns>
    public override bool Equals(object obj)
    {
        return ReferenceEquals(this, obj) || obj is SecureBigInteger otherBigInt && this.Equals(otherBigInt);
    }

    /// <summary>
    /// Determines whether the current instance of <see cref="SecureBigInteger"/> is equal to another <see cref="SecureBigInteger"/>.
    /// </summary>
    /// <param name="other">The <see cref="SecureBigInteger"/> to compare with the current instance.</param>
    /// <returns>
    /// <see langword="true"/> if the current instance is equal to the other <see cref="SecureBigInteger"/>; otherwise, <see langword="false"/>.
    /// </returns>
    public bool Equals(SecureBigInteger other)
    {
        if (other is null)
        {
            return false;
        }
        
        unsafe
        {
            if (this.length != other.length)
            {
                return false;
            }

            for (long i = 0; i < this.length; i++)
            {
                if (this.digitsPtr[i] != other.digitsPtr[i])
                {
                    return false;
                }
            }
        }

        return this.isNegative == other.isNegative;
    }

    /// <summary>
    /// Releases the resources used by the <see cref="SecureBigInteger"/> object.
    /// </summary>
    public void Dispose()
    {
        this.Dispose(true);
        GC.SuppressFinalize(this);
    }

    /// <summary>
    /// Parses the string representation of a number into a <see cref="SecureBigInteger"/> using the specified culture-specific format.
    /// </summary>
    /// <param name="value">The string representation of the number to parse.</param>
    /// <param name="cultureInfo">An object that supplies culture-specific formatting information.</param>
    /// <returns>A <see cref="SecureBigInteger"/> that represents the parsed value.</returns>
    /// <remarks>Todo: Fast, secure implementation</remarks>
    public static SecureBigInteger Parse(string value, CultureInfo cultureInfo)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new ArgumentNullException(nameof(value));
        }


        var bigInteger = BigInteger.Parse(value, NumberStyles.Integer, cultureInfo);
        return new SecureBigInteger(bigInteger);
    }

    /// <summary>
    /// Adds two <see cref="SecureBigInteger"/> instances.
    /// </summary>
    /// <param name="left">The left operand.</param>
    /// <param name="right">The right operand.</param>
    /// <returns>The result of adding <paramref name="left"/> and <paramref name="right"/>.</returns>
    public static SecureBigInteger operator +(SecureBigInteger left, SecureBigInteger right)
    {
        SecureBigInteger result;
        if (left.isNegative == right.isNegative)
        {
            result = left.Add(right);
            result.isNegative = !result.IsZero && left.isNegative;
            return result;
        }

        if (left.LessThan(right))
        {
            result = right.Subtract(left);
            result.isNegative = !result.IsZero && right.isNegative;
            return result;
        }

        result = left.Subtract(right);
        result.isNegative = !result.IsZero && left.isNegative;
        return result;
    }

    /// <summary>
    /// Subtracts one <see cref="SecureBigInteger"/> from another.
    /// </summary>
    /// <param name="left">The minuend.</param>
    /// <param name="right">The subtrahend.</param>
    /// <returns>A new <see cref="SecureBigInteger"/> that contains the result of the subtraction.</returns>
    public static SecureBigInteger operator -(SecureBigInteger left, SecureBigInteger right)
    {
        SecureBigInteger result;
        if (left.isNegative == right.isNegative)
        {
            if (right.GreaterThan(left))
            {
                result = right.Subtract(left);
                result.isNegative = !result.IsZero && !right.isNegative;
                return result;
            }

            result = left.Subtract(right);
            result.isNegative = !result.IsZero && left.isNegative;
            return result;
        }

        result = left.Add(right);
        result.isNegative = !result.IsZero && left.isNegative;
        return result;
    } 

    /// <summary>
    /// Multiplies two <see cref="SecureBigInteger" /> values.
    /// </summary>
    /// <param name="left">The left operand.</param>
    /// <param name="right">The right operand.</param>
    /// <returns>The product of the two <see cref="SecureBigInteger" /> values.</returns>
    public static SecureBigInteger operator *(SecureBigInteger left, SecureBigInteger right) => left.Multiply(right);

    /// <summary>
    /// Divides one <see cref="SecureBigInteger"/> value by another.
    /// </summary>
    /// <param name="left">The <see cref="SecureBigInteger"/> to be divided.</param>
    /// <param name="right">The <see cref="SecureBigInteger"/> that divides.</param>
    /// <returns>The result of dividing <paramref name="left"/> by <paramref name="right"/>.</returns>
    public static SecureBigInteger operator /(SecureBigInteger left, SecureBigInteger right) => left.Divide(right);

    /// <summary>
    /// Performs the modulus operation on two <see cref="SecureBigInteger"/> objects.
    /// </summary>
    /// <param name="left">The <see cref="SecureBigInteger"/> to be divided.</param>
    /// <param name="right">The <see cref="SecureBigInteger"/> to divide by.</param>
    /// <returns>The remainder after dividing <paramref name="left"/> by <paramref name="right"/>.</returns>
    public static SecureBigInteger operator %(SecureBigInteger left, SecureBigInteger right) => left.Modulo(right);

    /// <summary>
    /// Increments the given <see cref="SecureBigInteger"/> by one.
    /// </summary>
    /// <param name="value">The <see cref="SecureBigInteger"/> to be incremented.</param>
    /// <returns>A new <see cref="SecureBigInteger"/> that is the result of the increment operation.</returns>
    public static SecureBigInteger operator ++(SecureBigInteger value)
    {
        try
        {
            using var one = One;
            return value + one;
        }
        finally
        {
            value.Dispose();
        }
    }

    /// <summary>
    /// Decrements the value of a <see cref="SecureBigInteger"/> by one.
    /// </summary>
    /// <param name="value">The value to be decremented.</param>
    /// <returns>A new <see cref="SecureBigInteger"/> that is one less than the input value.</returns>
    public static SecureBigInteger operator --(SecureBigInteger value)
    {
        try
        {
            using var one = One;
            return value - one;
        }
        finally
        {
            value.Dispose();
        }
    }

    /// <summary>
    /// Performs a right shift operation on a <see cref="SecureBigInteger"/> instance.
    /// </summary>
    /// <param name="left">The <see cref="SecureBigInteger"/> instance to shift.</param>
    /// <param name="right">The number of positions to shift right.</param>
    /// <returns>A new <see cref="SecureBigInteger"/> representing the result of the shift operation.</returns>
    public static SecureBigInteger operator >> (SecureBigInteger left, int right) => left.RightShift(right);

    /// <summary>
    /// Shifts the bits of a <see cref="SecureBigInteger"/> instance to the left.
    /// </summary>
    /// <param name="left">The instance of <see cref="SecureBigInteger"/> to be shifted.</param>
    /// <param name="right">The number of positions to shift to the left.</param>
    /// <returns>A new instance of <see cref="SecureBigInteger"/> with the bits shifted to the left.</returns>
    public static SecureBigInteger operator <<(SecureBigInteger left, int right) => left.LeftShift(right);

    /// <summary>
    /// Determines whether the specified <see cref="SecureBigInteger"/> instances are equal.
    /// </summary>
    /// <param name="left">The first <see cref="SecureBigInteger"/> to compare.</param>
    /// <param name="right">The second <see cref="SecureBigInteger"/> to compare.</param>
    /// <returns>
    /// <see langword="true"/> if the specified <see cref="SecureBigInteger"/> instances are equal; otherwise, <see langword="false"/>.
    /// </returns>
    public static bool operator ==(SecureBigInteger left, SecureBigInteger right) => Equals(left, right);

    /// <summary>
    /// Determines whether two specified <see cref="SecureBigInteger"/> objects aren't equal.
    /// </summary>
    /// <param name="left">The first <see cref="SecureBigInteger"/> to compare.</param>
    /// <param name="right">The second <see cref="SecureBigInteger"/> to compare.</param>
    /// <returns>
    /// <see langword="true"/> if the value of <paramref name="left"/> is different from the value of <paramref name="right"/>; otherwise, <see langword="false"/>.
    /// </returns>
    public static bool operator !=(SecureBigInteger left, SecureBigInteger right) => !Equals(left, right);

    /// <summary>
    /// Compares two <see cref="SecureBigInteger"/> instances to determine if the left instance is greater than the right instance.
    /// </summary>
    /// <param name="left">The left <see cref="SecureBigInteger"/> instance.</param>
    /// <param name="right">The right <see cref="SecureBigInteger"/> instance.</param>
    /// <returns>
    /// <see langword="true"/> if the left instance is greater than the right instance; otherwise, <see langword="false"/>.
    /// </returns>
    public static bool operator >(SecureBigInteger left, SecureBigInteger right)
    {
        if (left.isNegative && !right.isNegative)
        {
            return false;
        }
        
        if (!left.isNegative && right.isNegative)
        {
            return true;
        }
        
        if (left.isNegative && right.isNegative)
        {
            return left.LessThan(right);
        }

        return left.GreaterThan(right);
    }

    /// <summary>
    /// Compares two <see cref="SecureBigInteger"/> objects to determine whether the left instance is less than the right instance.
    /// </summary>
    /// <param name="left">The first <see cref="SecureBigInteger"/> to compare.</param>
    /// <param name="right">The second <see cref="SecureBigInteger"/> to compare.</param>
    /// <returns>
    /// <see langword="true"/> if the left instance is less than the right instance; otherwise, <see langword="false"/>.
    /// </returns>
    public static bool operator <(SecureBigInteger left, SecureBigInteger right)
    {
        if (left.isNegative && !right.isNegative)
        {
            return true;
        }
        
        if (!left.isNegative && right.isNegative)
        {
            return false;
        }
        
        if (left.isNegative && right.isNegative)
        {
            return left.GreaterThan(right);
        }

        return left.LessThan(right);
    }

    /// <summary>
    /// Determines if the left <see cref="SecureBigInteger"/> is greater than or equal to the right <see cref="SecureBigInteger"/>.
    /// </summary>
    /// <param name="left">The left operand, represented as a <see cref="SecureBigInteger"/>.</param>
    /// <param name="right">The right operand, represented as a <see cref="SecureBigInteger"/>.</param>
    /// <returns>
    /// <see langword="true"/> if the left <see cref="SecureBigInteger"/> is greater than or equal to the right <see cref="SecureBigInteger"/>; otherwise, <see langword="false"/>.
    /// </returns>
    public static bool operator >=(SecureBigInteger left, SecureBigInteger right) => left.GreaterThanOrEqual(right);

    /// <summary>
    /// Determines whether the first <see cref="SecureBigInteger"/> is less than or equal to the second <see cref="SecureBigInteger"/>.
    /// </summary>
    /// <param name="left">The first <see cref="SecureBigInteger"/> to compare.</param>
    /// <param name="right">The second <see cref="SecureBigInteger"/> to compare.</param>
    /// <returns>
    /// <see langword="true"/> if the first <see cref="SecureBigInteger"/> is less than or equal to the second; otherwise, <see langword="false"/>.
    /// </returns>
    public static bool operator <=(SecureBigInteger left, SecureBigInteger right) => left.LessThanOrEqual(right);

    /// <summary>
    /// Defines an implicit conversion of an <see cref="int"/> to a <see cref="SecureBigInteger"/>.
    /// </summary>
    /// <param name="value">The integer value to convert.</param>
    public static implicit operator SecureBigInteger(int value) => new SecureBigInteger(value);

    /// <summary>
    /// Defines an explicit conversion from <see cref="SecureBigInteger"/> to <see cref="int"/>.
    /// </summary>
    /// <param name="value">The <see cref="SecureBigInteger"/> instance to convert.</param>
    /// <returns>The converted 32-bit signed integer.</returns>
    /// <exception cref="OverflowException">
    /// Thrown when the <see cref="SecureBigInteger"/> value is too large to be represented as a 32-bit signed integer.
    /// </exception>
    public static unsafe explicit operator int(SecureBigInteger value)
    {
        if (value.length > 1)
        {
            throw new OverflowException("The value is too large to be converted to an integer.");
        }

        return Convert.ToInt32(value.digitsPtr[0]);
    }

    #region String Conversion
    /// <inheritdoc />
    /// <remarks>Todo: Implement a more efficient and secure conversion. Only for testing purposes.</remarks>
    public override unsafe string ToString()
    {
        var binaryStringBuilder = new StringBuilder();
        for (int i = this.length - 1; i >= 0; i--)
        {
            string binaryChunk = Convert.ToString(this.digitsPtr[i], 2).PadLeft(32, '0');
            binaryStringBuilder.Append(binaryChunk);
        }

        string result = BinaryToDecimal(binaryStringBuilder);
        return this.isNegative ? "-" + result : result;
    }

    private static string BinaryToDecimal(StringBuilder binaryStringBuilder)
    {
        string total = "0";
        for (int i = binaryStringBuilder.Length - 1; i >= 0; i--)
        {
            if (binaryStringBuilder[i] == '1')
            {
                total = AddStrings(total, PowerOfTwo(binaryStringBuilder.Length - 1 - i));
            }
        }

        return total;
    }

    private static string AddStrings(string num1, string num2)
    {
        var stringBuilder = new StringBuilder();
        int carry = 0;
        int i = num1.Length - 1;
        int j = num2.Length - 1;
        while (i >= 0 || j >= 0 || carry > 0)
        {
            int sum = carry;
            if (i >= 0)
            {
                sum += num1[i--] - '0';
            }

            if (j >= 0)
            {
                sum += num2[j--] - '0';
            }

            stringBuilder.Insert(0, sum % 10);
            carry = sum / 10;
        }

        return stringBuilder.ToString();
    }

    private static string PowerOfTwo(int power)
    {
        string result = "1";
        for (int i = 0; i < power; i++)
        {
            result = AddStrings(result, result);
        }

        return result;
    }

    #endregion

    /// <summary>
    /// Releases the unmanaged resources used by the <see cref="SecureBigInteger"/> and optionally releases the managed
    /// resources.
    /// </summary>
    /// <param name="disposing"><see langword="true"/> to release both managed and unmanaged resources;
    /// <see langword="false"/> to release only unmanaged resources.</param>
    private unsafe void Dispose(bool disposing)
    {
        if (this.disposed)
        {
            return;
        }

        if (disposing)
        {
            // Dispose managed resources.
        }

        this.isNegative = false;
        for (int i = 0; i < this.digitsLength; i++)
        {
            this.digitsPtr[i] = 0;
        }

        if (this.digitsHandle.IsAllocated)
        {
            this.digitsHandle.Free();
            this.digitsHandle = default;
        }

        this.disposed = true;
    }

    /// <summary>
    /// Adds two <see cref="SecureBigInteger"/> together and returns a new SecureBigInteger containing the sum.
    /// </summary>
    /// <param name="other">The <see cref="SecureBigInteger"/> to be added.</param>
    /// <returns>A new <see cref="SecureBigInteger"/> that is the sum of the current <see cref="SecureBigInteger"/> and
    /// the specified <see cref="SecureBigInteger"/>.</returns>
    private unsafe SecureBigInteger Add(SecureBigInteger other)
    {
        int maxLen = Math.Max(this.length, other.length);
        
        uint[] result = new uint[maxLen + 1];
        var resultDigitsHandle = GCHandle.Alloc(result, GCHandleType.Pinned);
        ulong carry = 0;
        
        for (long index = 0; index < maxLen || carry != 0; ++index)
        {
            ulong sum = carry;
            if (index < this.length)
            {
                sum += this.digitsPtr[index];
            }
        
            if (index < other.length)
            {
                sum += other.digitsPtr[index];
            }
        
            carry = sum >> 32;
            result[index] = (uint)sum;
        }

        int newLength = maxLen + 1;
        while (newLength > 1 && result[newLength - 1] == 0)
        {
            newLength--;
        }
        
        uint* resultPtr = (uint*)resultDigitsHandle.AddrOfPinnedObject();
        return new SecureBigInteger(resultPtr, resultDigitsHandle, newLength, result.Length);
    }

    /// <summary>
    /// Subtracts the value of another <see cref="SecureBigInteger"/> from this instance.
    /// </summary>
    /// <param name="other">The <see cref="SecureBigInteger"/> to subtract.</param>
    /// <returns>A new <see cref="SecureBigInteger"/> containing the result of the subtraction.</returns>
    /// <exception cref="InvalidOperationException">Thrown when attempting to subtract a larger number from a smaller one.</exception>
    private unsafe SecureBigInteger Subtract(SecureBigInteger other)
    {
        int maxLen = Math.Max(this.length, other.length);
        
        uint[] result = new uint[maxLen];
        var resultDigitsHandle = GCHandle.Alloc(result, GCHandleType.Pinned);
        ulong borrow = 0;
        
        for (long index = 0; index < maxLen; ++index)
        {
            ulong diff;
            ulong val1 = index < this.length ? this.digitsPtr[index] : 0;
            ulong val2 = index < other.length ? other.digitsPtr[index] : 0;
        
            if (val1 < val2 + borrow)
            {
                diff = uint.MaxValue - val2 - borrow + val1 + 1;
                borrow = 1;
            }
            else
            {
                diff = val1 - val2 - borrow;
                borrow = 0;
            }
        
            result[index] = (uint)diff;
        }
        
        if (borrow != 0)
        {
            throw new InvalidOperationException("Cannot subtract a larger number from a smaller one.");
        }
        
        int newLength = maxLen;
        while (newLength > 1 && result[newLength - 1] == 0)
        {
            newLength--;
        }
        
        uint* resultPtr = (uint*)resultDigitsHandle.AddrOfPinnedObject();
        return new SecureBigInteger(resultPtr, resultDigitsHandle, newLength, result.Length);
    }

    /// <summary>
    /// Multiplies the current <see cref="SecureBigInteger"/> instance with another <see cref="SecureBigInteger"/> instance.
    /// </summary>
    /// <param name="other">The <see cref="SecureBigInteger"/> instance to multiply with.</param>
    /// <returns>A new <see cref="SecureBigInteger"/> instance representing the product of the multiplication.</returns>
    private unsafe SecureBigInteger Multiply(SecureBigInteger other)
    {
        if (this.IsZero || other.IsZero)
        {
            return Zero;
        }
        
        if (this.IsOne || this.IsNegativeOne)
        {
            var secureBigInteger = other.Clone() as SecureBigInteger;
            secureBigInteger!.isNegative = this.isNegative ^ other.isNegative;
            return secureBigInteger;
        }
        
        if (other.IsOne || other.IsNegativeOne)
        {
            var secureBigInteger = this.Clone() as SecureBigInteger;
            secureBigInteger!.isNegative = this.isNegative ^ other.isNegative;
            return secureBigInteger;
        }

        int maxLen = this.length + other.length;

        uint[] result = new uint[maxLen];
        var resultDigitsHandle = GCHandle.Alloc(result, GCHandleType.Pinned);

        for (long i = 0; i < this.length; ++i)
        {
            ulong carry = 0;
            for (long j = 0; j < other.length; ++j)
            {
                ulong product = (ulong)this.digitsPtr[i] * (ulong)other.digitsPtr[j] + carry + result[i + j];
                result[i + j] = (uint)product;
                carry = product >> 32;
            }

            result[i + other.length] = (uint)carry;
        }

        int newLength = maxLen;
        while (newLength > 1 && result[newLength - 1] == 0)
        {
            newLength--;
        }

        uint* resultPtr = (uint*)resultDigitsHandle.AddrOfPinnedObject();
        return new SecureBigInteger(resultPtr, resultDigitsHandle, newLength, result.Length,
            this.isNegative ^ other.isNegative);
    }

    /// <summary>
    /// Right-shifts the current <see cref="SecureBigInteger"/> by the specified number of bits.
    /// </summary>
    /// <param name="shift">The number of bits to right-shift the current SecureBigInteger.</param>
    /// <returns>
    /// A new <see cref="SecureBigInteger"/> that is the result of right-shifting the current SecureBigInteger by the specified number of bits.
    /// </returns>
    /// <exception cref="ArgumentOutOfRangeException">Thrown when the shift value is less than zero.</exception>
    private unsafe SecureBigInteger RightShift(int shift)
    {
        if (shift < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(shift),
                "The shift value must be greater than or equal to zero.");
        }

        int shift32 = shift / 32;
        int shiftMod32 = shift % 32;
        int newLength = this.length - shift32;
        if (shiftMod32 != 0)
        {
            newLength++;
        }

        uint[] result = new uint[newLength];
        var resultDigitsHandle = GCHandle.Alloc(result, GCHandleType.Pinned);

        for (long i = 0; i < newLength; i++)
        {
            result[i] = this.digitsPtr[i + shift32] >> shiftMod32;
            if (i + 1 < newLength && shiftMod32 != 0)
            {
                result[i] |= this.digitsPtr[i + shift32 + 1] << (32 - shiftMod32);
            }
        }

        uint* resultPtr = (uint*)resultDigitsHandle.AddrOfPinnedObject();
        return new SecureBigInteger(resultPtr, resultDigitsHandle, newLength, result.Length, this.isNegative);
    }

    /// <summary>
    /// Shifts the bits of the <see cref="SecureBigInteger"/> to the left by the specified amount.
    /// </summary>
    /// <param name="shift">The number of bits to shift.</param>
    /// <returns>
    /// A new <see cref="SecureBigInteger"/> that represents the result of the left shift operation.
    /// </returns>
    /// <exception cref="ArgumentOutOfRangeException">Thrown when the shift value is less than zero.</exception>
    private unsafe SecureBigInteger LeftShift(int shift)
    {
        if (shift < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(shift),
                "The shift value must be greater than or equal to zero.");
        }

        if (shift == 0 || this.IsZero)
        {
            return this.Clone() as SecureBigInteger;
        }

        int digitShift = shift / 32;
        int bitShift = shift % 32;

        uint[] result = new uint[this.length + digitShift + 1];
        var resultDigitsHandle = GCHandle.Alloc(result, GCHandleType.Pinned);
        ulong carry = 0;

        for (int i = 0; i < this.length; ++i)
        {
            ulong temp = ((ulong)this.digitsPtr[i] << bitShift) | carry;
            result[i + digitShift] = (uint)temp;
            carry = temp >> 32;
        }

        if (carry != 0)
        {
            result[this.length + digitShift] = (uint)carry;
        }

        int newLength = result.Length;
        while (newLength > 1 && result[newLength - 1] == 0)
        {
            newLength--;
        }

        uint* resultPtr = (uint*)resultDigitsHandle.AddrOfPinnedObject();
        return new SecureBigInteger(resultPtr, resultDigitsHandle, newLength, result.Length, this.isNegative);
    }

    /// <summary>
    /// Divides the current <see cref="SecureBigInteger"/> by the specified <see cref="SecureBigInteger"/> and returns the quotient.
    /// </summary>
    /// <param name="other">The <see cref="SecureBigInteger"/> to divide by.</param>
    /// <returns>
    /// The quotient obtained by dividing the current <see cref="SecureBigInteger"/> by the specified <see cref="SecureBigInteger"/>.
    /// </returns>
    /// <exception cref="DivideByZeroException">Thrown when the divisor is zero.</exception>
    private unsafe SecureBigInteger Divide(SecureBigInteger other)
    {
        if (other.IsZero)
        {
            throw new DivideByZeroException("Cannot divide by zero.");
        }

        if (this.IsZero)
        {
            return Zero;
        }

        if (other.IsOne || other.IsNegativeOne)
        {
            var secureBigInteger = this.Clone() as SecureBigInteger;
            secureBigInteger!.isNegative = this.isNegative ^ other.isNegative;
            return secureBigInteger;
        }

        if (this.IsOne || this.IsNegativeOne)
        {
            return Zero;
        }

        SecureBigInteger thisAbsolute = null;
        SecureBigInteger otherAbsolute = null;
        try
        {
            thisAbsolute = this.Abs();
            otherAbsolute = other.Abs();
            if (thisAbsolute == otherAbsolute)
            {
                var result = One;
                result.isNegative = this.isNegative ^ other.isNegative;
                return result;
            }
        }
        finally
        {
            thisAbsolute?.Dispose();
            otherAbsolute?.Dispose();
        }

        var temp1 = Zero;
        var bitLength = this.length * 32;
        uint[] quotient = new uint[this.length];
        var quotientDigitsHandle = GCHandle.Alloc(quotient, GCHandleType.Pinned);
        for (var i = bitLength - 1; i >= 0; i--)
        {
            var temp2 = temp1 << 1;
            temp1.digitsPtr[0] = temp2.digitsPtr[0] |= this.digitsPtr[i / 32] >> i % 32 & 1;

            if (temp2.LessThan(other))
            {
                temp2.Dispose();
                continue;
            }

            temp1.Dispose();
            temp1 = temp2.Subtract(other);
            temp2.Dispose();
            quotient[i / 32] |= (uint)(1 << (i % 32));
        }

        int newLength = quotient.Length;
        while (newLength > 1 && quotient[newLength - 1] == 0)
        {
            newLength--;
        }

        uint* quotientPtr = (uint*)quotientDigitsHandle.AddrOfPinnedObject();
        return new SecureBigInteger(quotientPtr, quotientDigitsHandle, newLength, quotient.Length, this.isNegative ^ other.isNegative);
    }

    /// <summary>
    /// Computes the remainder of the division of the current <see cref="SecureBigInteger"/> by the specified <see cref="SecureBigInteger"/>.
    /// </summary>
    /// <param name="other">The <see cref="SecureBigInteger"/> to divide by.</param>
    /// <returns>The remainder of the division.</returns>
    /// <exception cref="DivideByZeroException">Thrown when the divisor is zero.</exception>
    private unsafe SecureBigInteger Modulo(SecureBigInteger other)
    {
        if (other.IsZero)
        {
            throw new DivideByZeroException("Cannot divide by zero.");
        }

        if (this.IsZero)
        {
            return Zero;
        }

        if (other.IsOne || other.IsNegativeOne)
        {
            return Zero;
        }

        var secureBigInteger = other.Clone() as SecureBigInteger;
        secureBigInteger!.isNegative = false;

        var temp1 = Zero;
        var bitLength = this.length * 32;
        for (var i = bitLength - 1; i >= 0; i--)
        {
            var temp2 = temp1 << 1;
            temp2.digitsPtr[0] |= this.digitsPtr[i / 32] >> i % 32 & 1;

            temp1.Dispose();
            if (temp2.GreaterThanOrEqual(secureBigInteger))
            {
                temp1 = temp2 - secureBigInteger;
                temp2.Dispose();
            }
            else
            {
                temp1 = temp2;
            }
        }

        secureBigInteger.Dispose();
        temp1.isNegative = !temp1.IsZero && this.isNegative;
        return temp1;
    }
    
    /// <summary>
    /// Determines whether the current <see cref="SecureBigInteger"/> is less than or equal to the specified <see cref="SecureBigInteger"/>.
    /// </summary>
    /// <param name="other">The <see cref="SecureBigInteger"/> to compare with the current instance.</param>
    /// <returns>
    /// <see langword="true"/> if the current instance is less than or equal to the specified instance; otherwise, <see langword="false"/>.
    /// </returns>
    private bool LessThanOrEqual(SecureBigInteger other)
    {
        return this < other || this.Equals(other);
    }

    /// <summary>
    /// Determines whether this <see cref="SecureBigInteger"/> instance is less than the specified <see cref="SecureBigInteger"/>.
    /// </summary>
    /// <param name="other">The <see cref="SecureBigInteger"/> instance to compare with this instance.</param>
    /// <returns>
    /// <see langword="true"/> if this instance is less than the specified <see cref="SecureBigInteger"/>; otherwise, <see langword="false"/>
    /// </returns>
    private unsafe bool LessThan(SecureBigInteger other)
    {
        if (this.length < other.length)
        {
            return true;
        }

        if (this.length > other.length)
        {
            return false;
        }

        for (long i = this.length - 1; i >= 0; i--)
        {
            if (this.digitsPtr[i] < other.digitsPtr[i])
            {
                return true;
            }

            if (this.digitsPtr[i] > other.digitsPtr[i])
            {
                return false;
            }
        }

        return false;
    }

    /// <summary>
    /// Determines whether the current secure big integer is greater than or equal to the specified secure big integer.
    /// </summary>
    /// <param name="other">The secure big integer to compare with the current secure big integer.</param>
    /// <returns>
    /// <see langword="true"/> if the current secure big integer is greater than or equal to the specified secure big integer; otherwise, <see langword="false"/>.
    /// </returns>
    private bool GreaterThanOrEqual(SecureBigInteger other)
    {
        return this > other || this.Equals(other);
    }

    /// <summary>
    /// Determines whether this instance is greater than the specified SecureBigInteger.
    /// </summary>
    /// <param name="other">The SecureBigInteger to compare with this instance.</param>
    /// <return>
    /// <see langword="true"/> if this instance is greater than the specified SecureBigInteger; otherwise, <see langword="false"/>.
    /// </return>
    private unsafe bool GreaterThan(SecureBigInteger other)
    {
        if (this.length > other.length)
        {
            return true;
        }

        if (this.length < other.length)
        {
            return false;
        }

        for (long i = this.length - 1; i >= 0; i--)
        {
            if (this.digitsPtr[i] > other.digitsPtr[i])
            {
                return true;
            }

            if (this.digitsPtr[i] < other.digitsPtr[i])
            {
                return false;
            }
        }

        return false;
    }
}
#endif
