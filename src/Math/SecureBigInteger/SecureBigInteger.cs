// ----------------------------------------------------------------------------
// <copyright file="SecureBigInteger.cs" company="Private">
// Copyright (c) 2025 All Rights Reserved
// </copyright>
// <author>Sebastian Walther</author>
// <date>12/06/2025 08:07:21 PM</date>
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

namespace SecretSharingDotNet.Math.SecureBigInteger;

#if (!NET8_0_OR_GREATER && !NETSTANDARD2_1_OR_GREATER)
using Extension;
#endif
using Cryptography;
using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
#if (NET8_0_OR_GREATER || NETSTANDARD2_1_OR_GREATER)
using System.Security.Cryptography;
#endif
using System.Text;
using System.Threading;

/// <summary>
/// Represents a secure arbitrary-precision integer with support for basic arithmetic operations.
/// The internal data is securely cleared from memory when the instance is disposed.
/// </summary>
public sealed class SecureBigInteger : IDisposable, IEquatable<SecureBigInteger>, IComparable<SecureBigInteger>
{
    // Todo: Data is Little-Endian Byte-Array
    /// <summary>
    /// The byte array representing the absolute value of the integer.
    /// </summary>
    private PinnedPoolArray<byte> data;

    /// <summary>
    /// The actual length of the data in the <see cref="data"/> array.
    /// </summary>
    private int Length
    {
        get => this.data.Length;
        set => this.data.Length = value;
    } 

    /// <summary>
    /// Indicates whether the current instance represents a negative value.
    /// </summary>
    private bool isNegative;

    /// <summary>
    /// Indicates whether the current instance has been disposed.
    /// </summary>
    private int disposed;

    /// <summary>
    /// Initializes a new instance of the <see cref="SecureBigInteger"/> class with the value zero.
    /// </summary>
    public SecureBigInteger()
    {
        this.data = new PinnedPoolArray<byte>(1);
        this.data[0] = 0;
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="SecureBigInteger"/> class from an <see cref="int"/> value.
    /// </summary>
    /// <param name="value">The <see cref="int"/> value to initialize from.</param>
    public SecureBigInteger(int value)
    {
        switch (value)
        {
            case 0:
                this.data = new PinnedPoolArray<byte>(1);
                this.data[0] = 0;
                break;
            case int.MinValue:
                this.isNegative = true;
                var intSize = sizeof(int);
                this.data = new PinnedPoolArray<byte>(intSize);
                this.data[0] = 0;
                this.data[1] = 0;
                this.data[2] = 0;
                this.data[3] = 128;
                break;
            default:
                this.isNegative = value < 0;
                var absoluteValue = (uint)(this.isNegative ? -(long)value : value);
                if (absoluteValue == 0)
                {
                    this.data = new PinnedPoolArray<byte>(1);
                    this.data[0] = 0;
                    break;
                }

                int byteCount = 0;
                uint temp = absoluteValue;
                while (temp > 0)
                {
                    byteCount++;
                    temp >>= 8;
                }

                this.data = new PinnedPoolArray<byte>(byteCount);
                for (int i = 0; i < byteCount; i++)
                {
                    this.data[i] = (byte)(absoluteValue & 0xFF);
                    absoluteValue >>= 8;
                }

                break;
        }
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="SecureBigInteger"/> class from a <see cref="long"/> value.
    /// </summary>
    /// <param name="value">The <see cref="long"/> value to initialize from.</param>
    public SecureBigInteger(long value)
    {
        switch (value)
        {
            case 0:
                this.data = new PinnedPoolArray<byte>(1);
                this.data[0] = 0;
                break;
            case long.MinValue:
                this.isNegative = true;
                var longSize = sizeof(long);
                this.data = new PinnedPoolArray<byte>(longSize);
                this.data[0] = 0;
                this.data[1] = 0;
                this.data[2] = 0;
                this.data[3] = 0;
                this.data[4] = 0;
                this.data[5] = 0;
                this.data[6] = 0;
                this.data[7] = 128;
                break;
            default:
                this.isNegative = value < 0;
                ulong absoluteValue = (ulong)(this.isNegative ? -value : value);
                if (absoluteValue == 0)
                {
                    this.data = new PinnedPoolArray<byte>(1);
                    this.data[0] = 0;
                    break;
                }

                int byteCount = 0;
                ulong temp = absoluteValue;
                while (temp > 0)
                {
                    byteCount++;
                    temp >>= 8;
                }

                this.data = new PinnedPoolArray<byte>(byteCount);
                for (int i = 0; i < byteCount; i++)
                {
                    this.data[i] = (byte)(absoluteValue & 0xFF);
                    absoluteValue >>= 8;
                }

                break;
        }
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="SecureBigInteger"/> class by copying another instance.
    /// </summary>
    /// <param name="other">The <see cref="SecureBigInteger"/> instance to copy.</param>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="other"/> is <see langword="null"/>.</exception>
    public SecureBigInteger(SecureBigInteger other)
    {
        if (other is null)
        {
            throw new ArgumentNullException(nameof(other));
        }

        other.ThrowIfDisposed();
        this.data = new PinnedPoolArray<byte>(other.Length);
        Array.Copy(other.data.PoolArray, this.data.PoolArray, other.Length);
        this.isNegative = other.isNegative;
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="SecureBigInteger"/> class from a byte array and a sign flag.
    /// </summary>
    /// <param name="data">The byte array representing the absolute value.</param>
    /// <param name="isNegative">Indicates whether the value is negative.</param>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="data"/> is <see langword="null"/>.</exception>
    public SecureBigInteger(byte[] data, bool isNegative) : this(data ?? throw new ArgumentNullException(nameof(data)),
        data.Length, isNegative)
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="SecureBigInteger"/> class from a byte array and a sign flag.
    /// </summary>
    /// <param name="data">The byte array representing the absolute value.</param>
    /// <param name="length">The length of the data to consider from the byte array.</param>
    /// <param name="isNegative">Indicates whether the value is negative.</param>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="data"/> is <see langword="null"/>.</exception>
    public SecureBigInteger(byte[] data, int length, bool isNegative)
    {
        if (data is null)
        {
            throw new ArgumentNullException(nameof(data));
        }

        this.data = new PinnedPoolArray<byte>(length);
        Array.Copy(data, this.data.PoolArray, length);
        this.isNegative = isNegative;
        this.TrimLeadingZerosInPlace();
        if (this.IsZeroInternal())
        {
            this.isNegative = false;
        }
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="SecureBigInteger"/> class from a byte array, which contains
    /// the serialized representation.
    /// </summary>
    /// <param name="data">The byte array containing the serialized representation.</param>
    /// <exception cref="EndOfStreamException">Thrown if the byte array is incomplete or corrupted.</exception>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="data"/> is <see langword="null"/>.</exception>
    public SecureBigInteger(byte[] data) : this(data ?? throw new ArgumentNullException(nameof(data)), data.Length)
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="SecureBigInteger"/> class from a byte array, which contains
    /// the serialized representation.
    /// </summary>
    /// <param name="data">The byte array containing the serialized representation.</param>
    /// <param name="length">The length of the byte array containing the serialized representation.</param>
    /// <exception cref="EndOfStreamException">Thrown if the byte array is incomplete or corrupted.</exception>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="data"/> is <see langword="null"/>.</exception>
    public SecureBigInteger(byte[] data, int length)
    {
        if (data is null)
        {
            throw new ArgumentNullException(nameof(data));
        }

        var isNegativeRepresentation = IsNegativeRepresentation(data, length);
        this.isNegative = isNegativeRepresentation;
        var trimmedLength = GetActualLength(data, length);
        this.data = new PinnedPoolArray<byte>(trimmedLength);
        if (isNegativeRepresentation)
        {
            using var normalizedData = TwosComplement(data, this.Length);
            Array.Copy(normalizedData.PoolArray, this.data.PoolArray, this.Length);
        }
        else
        {
            Array.Copy(data, this.data.PoolArray, this.Length);
        }
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="SecureBigInteger"/> class from its string representation.
    /// </summary>
    /// <param name="value">The string representation of the integer.</param>
    /// <exception cref="ArgumentException"><paramref name="value"/> is null or whitespace.</exception>
    /// <exception cref="FormatException">Thrown if <paramref name="value"/> contains invalid characters.</exception>
#if (NET8_0_OR_GREATER || NETSTANDARD2_1_OR_GREATER)
    public SecureBigInteger(ReadOnlySpan<char> value)
    {
        if (value.IsEmpty || value.IsWhiteSpace())
        {
            throw new ArgumentException("Der Wert darf nicht leer sein", nameof(value));
        }
#else
    public SecureBigInteger(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new ArgumentException("Der Wert darf nicht leer sein", nameof(value));
        }
#endif
        value = value.Trim();
        this.isNegative = value[0] == '-';
        if (this.isNegative || value[0] == '+')
        {
#if (NET8_0_OR_GREATER || NETSTANDARD2_1_OR_GREATER)
            value = value[1..];
#else
            value = value.Substring(1);
#endif
        }

        var result = new SecureBigInteger(0);
        using var ten = new SecureBigInteger(10);

        foreach (char c in value)
        {
            if (!char.IsDigit(c))
            {
                throw new FormatException($"Ungültiges Zeichen in Zahl: {c}");
            }

            int digit = c - DigitOffset;

            // result = result * 10 + digit
            var temp1 = MultiplyUnsigned(result, ten);
            result.Dispose();

            var digitBytes = new SecureBigInteger(digit);
            result = AddUnsigned(temp1, digitBytes);
            temp1.Dispose();
            digitBytes.Dispose();
        }

        this.data = new PinnedPoolArray<byte>(result.Length);
        Array.Copy(result.data.PoolArray, this.data.PoolArray, result.Length);
        result.Dispose();

        if (this.IsZeroInternal())
        {
            this.isNegative = false;
        }
    }

    /// <summary>
    /// Finalizes an instance of the <see cref="SecureBigInteger"/> class.
    /// </summary>
    ~SecureBigInteger()
    {
        this.Dispose(false);
    }

    /// <summary>
    /// The character offset used to convert between numeric digits and their character representations.
    /// This value is typically set to '0' to align with ASCII encoding, where the character '0' has
    /// the numeric code 48. It is used internally for parsing and formatting numeric values.
    /// </summary>
    private static char DigitOffset => '0';

    /// <summary>
    /// Gets the number of bytes used to represent the internal data of the SecureBigInteger.
    /// </summary>
    public int ByteCount
    {
        get
        {
            this.ThrowIfDisposed();
            return this.Length;
        }
    }

    /// <summary>
    /// Gets a value indicating whether the current <see cref="SecureBigInteger"/> instance represents the value zero.
    /// </summary>
    public bool IsZero
    {
        get
        {
            this.ThrowIfDisposed();
            return this.IsZeroInternal();
        }
    }

    /// <summary>
    /// Gets a value indicating whether the current <see cref="SecureBigInteger"/> instance represents the value one.
    /// </summary>
    public bool IsOne
    {
        get
        {
            this.ThrowIfDisposed();
            return !this.isNegative && this.Length == 1 && this.data[0] == 1;
        }
    }

    /// <summary>
    /// Gets the sign of the current <see cref="SecureBigInteger"/> instance.
    /// </summary>
    public int Sign
    {
        get
        {
            this.ThrowIfDisposed();
            if (this.IsZeroInternal())
            {
                return 0;
            }

            return this.isNegative ? -1 : 1;
        }
    }

    /// <summary>
    /// Adds two <see cref="SecureBigInteger"/> instances.
    /// </summary>
    /// <param name="left">1st summand</param>
    /// <param name="right">2nd summand</param>
    /// <returns>sum</returns>
    /// <exception cref="ArgumentNullException"><paramref name="left"/> or <paramref name="right"/> is null.</exception>
    public static SecureBigInteger Add(SecureBigInteger left, SecureBigInteger right)
    {
        if (left is null)
        {
            throw new ArgumentNullException(nameof(left));
        }

        if (right is null)
        {
            throw new ArgumentNullException(nameof(right));
        }

        left.ThrowIfDisposed();
        right.ThrowIfDisposed();

        SecureBigInteger result;
        if (left.isNegative == right.isNegative)
        {
            result = AddUnsigned(left, right);
            result.isNegative = left.isNegative;
            return result;
        }

        var comparison = CompareUnsigned(left, right);
        switch (comparison)
        {
            case 0:
                return new SecureBigInteger(0);
            case > 0:
                result = SubtractUnsigned(left, right);
                result.isNegative = left.isNegative;
                break;
            default:
                result = SubtractUnsigned(right, left);
                result.isNegative = right.isNegative;
                break;
        }

        return result;
    }

    /// <summary>
    /// Subtracts two <see cref="SecureBigInteger"/> instances.
    /// </summary>
    /// <param name="minuend">minuend</param>
    /// <param name="subtrahend">subtrahend</param>
    /// <returns>difference</returns>
    /// <exception cref="ArgumentNullException"><paramref name="minuend"/> or <paramref name="subtrahend"/> is null.</exception>
    public static SecureBigInteger Subtract(SecureBigInteger minuend, SecureBigInteger subtrahend)
    {
        if (minuend is null)
        {
            throw new ArgumentNullException(nameof(minuend));
        }

        if (subtrahend is null)
        {
            throw new ArgumentNullException(nameof(subtrahend));
        }

        minuend.ThrowIfDisposed();
        subtrahend.ThrowIfDisposed();

        using var negRight = subtrahend.Negate();
        return Add(minuend, negRight);
    }

    /// <summary>
    /// Multiplies two <see cref="SecureBigInteger"/> instances.
    /// </summary>
    /// <param name="multiplicand">multiplicand</param>
    /// <param name="multiplier">multiplier</param>
    /// <returns>product</returns>
    /// <exception cref="ArgumentNullException"><paramref name="multiplicand"/> or
    /// <paramref name="multiplier"/> is null.</exception>
    public static SecureBigInteger Multiply(SecureBigInteger multiplicand, SecureBigInteger multiplier)
    {
        if (multiplicand is null)
        {
            throw new ArgumentNullException(nameof(multiplicand));
        }

        if (multiplier is null)
        {
            throw new ArgumentNullException(nameof(multiplier));
        }

        multiplicand.ThrowIfDisposed();
        multiplier.ThrowIfDisposed();

        if (multiplicand.IsZeroInternal() || multiplier.IsZeroInternal())
        {
            return new SecureBigInteger(0);
        }

        var result = MultiplyUnsigned(multiplicand, multiplier);
        result.isNegative = multiplicand.isNegative != multiplier.isNegative;

        return result;
    }

    /// <summary>
    /// Divides two <see cref="SecureBigInteger"/> instances.
    /// </summary>
    /// <param name="dividend">dividend</param>
    /// <param name="divisor">divisor</param>
    /// <returns>quotient</returns>
    /// <exception cref="ArgumentNullException"><paramref name="dividend"/> or
    /// <paramref name="divisor"/> is null.</exception>
    /// <exception cref="DivideByZeroException"></exception>
    public static SecureBigInteger Divide(SecureBigInteger dividend, SecureBigInteger divisor)
    {
        if (dividend is null)
        {
            throw new ArgumentNullException(nameof(dividend));
        }

        if (divisor is null)
        {
            throw new ArgumentNullException(nameof(divisor));
        }

        dividend.ThrowIfDisposed();
        divisor.ThrowIfDisposed();

        if (divisor.IsZeroInternal())
        {
            throw new DivideByZeroException("Division by zero is not allowed");
        }

        if (dividend.IsZeroInternal())
        {
            return new SecureBigInteger(0);
        }

        var quotient = DivideUnsigned(dividend, divisor, out _);
        quotient.isNegative = dividend.isNegative != divisor.isNegative;

        return quotient;
    }

    /// <summary>
    /// Computes the remainder of the division of two <see cref="SecureBigInteger"/> instances.
    /// </summary>
    /// <param name="dividend">dividend</param>
    /// <param name="divisor">divisor</param>
    /// <returns>remainder</returns>
    /// <exception cref="ArgumentNullException"><paramref name="dividend"/> or
    /// <paramref name="divisor"/> is null.</exception>
    /// <exception cref="DivideByZeroException"></exception>
    public static SecureBigInteger Remainder(SecureBigInteger dividend, SecureBigInteger divisor)
    {
        if (dividend is null)
        {
            throw new ArgumentNullException(nameof(dividend));
        }

        if (divisor is null)
        {
            throw new ArgumentNullException(nameof(divisor));
        }

        dividend.ThrowIfDisposed();
        divisor.ThrowIfDisposed();

        if (divisor.IsZeroInternal())
        {
            throw new DivideByZeroException("Division by zero is not allowed");
        }

        if (dividend.IsZeroInternal())
        {
            return new SecureBigInteger(0);
        }

        DivideUnsigned(dividend, divisor, out var remainder);
        remainder.isNegative = dividend.isNegative;
        return remainder;
    }

    /// <summary>
    /// Computes the square of the current <see cref="SecureBigInteger"/> instance.
    /// </summary>
    /// <returns></returns>
    public SecureBigInteger Square()
    {
        this.ThrowIfDisposed();
        return Multiply(this, this);
    }

    /// <summary>
    /// Computes the square root of the current <see cref="SecureBigInteger"/> instance.
    /// </summary>
    /// <returns></returns>
    /// <exception cref="InvalidOperationException"></exception>
    public SecureBigInteger Sqrt()
    {
        this.ThrowIfDisposed();

        if (this.isNegative)
        {
            throw new InvalidOperationException("Square root of negative numbers is not defined");
        }

        if (this.IsZeroInternal() || this.IsOne)
        {
            return new SecureBigInteger(this);
        }

        // Newton-Raphson: x_{n+1} = (x_n + a/x_n) / 2
        var bitLength = GetBitLength(this);
        var next = ShiftRight(this, (bitLength - 1) / 2);
        using var two = new SecureBigInteger(2);
        while (true)
        {
            using var temp1 = Divide(this, next);
            using var temp2 = Add(next, temp1);
            using var newNext = Divide(temp2, two);
            if (newNext >= next)
            {
                break;
            }

            next.Dispose();
            next = new SecureBigInteger(newNext);
        }

        return next;
    }

    /// <summary>
    /// Computes the n-th root of the current <see cref="SecureBigInteger"/> instance.
    /// </summary>
    /// <param name="n"></param>
    /// <returns></returns>
    /// <exception cref="ArgumentException"></exception>
    /// <exception cref="InvalidOperationException"></exception>
    public SecureBigInteger NthRoot(int n)
    {
        this.ThrowIfDisposed();

        if (n <= 0)
        {
            throw new ArgumentException("The root exponent must be positive", nameof(n));
        }

        if (n % 2 == 0 && this.isNegative)
        {
            throw new InvalidOperationException("Even root of negative numbers is not defined.");
        }

        if (this.IsZeroInternal())
        {
            return new SecureBigInteger(0);
        }

        switch (n)
        {
            case 1:
                return new SecureBigInteger(this);
            case 2:
                return this.Sqrt();
        }

        // Newton-Raphson: x_{n+1} = ((k-1)*x_n + a/x_n^(k-1)) / k
        using var absThis = this.Abs();
        var bitLength = GetBitLength(absThis);

        if (n >= bitLength && bitLength > 1)
        {
            var retVal = new SecureBigInteger(1);
            if (this.isNegative && n % 2 == 1)
            {
                retVal.isNegative = true;
            }

            return retVal;
        }

        var targetBit = bitLength / n + 1;
        var byteCount = targetBit / 8 + 1;
        byte[] initialGuessData = new byte[byteCount];
        SetBit(initialGuessData, targetBit);

        var next = new SecureBigInteger(initialGuessData, false);
        using var nValue = new SecureBigInteger(n);
        using var nMinus1 = new SecureBigInteger(n - 1);

        while (true)
        {
            using var powered = next.Pow(n - 1);
            using var divided = Divide(absThis, powered);
            using var temp1 = Multiply(next, nMinus1);
            using var temp2 = Add(temp1, divided);
            using var newNext = Divide(temp2, nValue);
            if (newNext >= next)
            {
                break;
            }

            next.Dispose();
            next = new SecureBigInteger(newNext);
        }

        if (this.isNegative && n % 2 == 1)
        {
            next.isNegative = true;
        }

        return next;
    }

    /// <summary>
    /// Computes the absolute value of the current <see cref="SecureBigInteger"/> instance.
    /// </summary>
    /// <returns></returns>
    public SecureBigInteger Abs()
    {
        this.ThrowIfDisposed();
        var secureBigInteger = new SecureBigInteger(this);
        secureBigInteger.isNegative = false;
        return secureBigInteger;
    }

    /// <summary>
    /// Computes the negation of the current <see cref="SecureBigInteger"/> instance.
    /// </summary>
    /// <returns>Negated value</returns>
    public SecureBigInteger Negate()
    {
        this.ThrowIfDisposed();
        if (this.IsZeroInternal())
        {
            return new SecureBigInteger(0);
        }

        var secureBigInteger = new SecureBigInteger(this);
        secureBigInteger.isNegative = !this.isNegative;
        return secureBigInteger;
    }

    /// <summary>
    /// Computes the power of the current <see cref="SecureBigInteger"/> instance raised to the specified exponent.
    /// </summary>
    /// <param name="exponent">The exponent to raise the current instance to.</param>
    /// <returns></returns>
    /// <exception cref="ArgumentException">Thrown if the exponent is negative.</exception>
    public SecureBigInteger Pow(int exponent)
    {
        this.ThrowIfDisposed();

        switch (exponent)
        {
            case < 0:
                throw new ArgumentException("Exponent must be non-negative", nameof(exponent));
            case 0:
                return new SecureBigInteger(1);
            case 1:
                return new SecureBigInteger(this);
        }

        var result = new SecureBigInteger(1);
        var baseValue = new SecureBigInteger(this);
        var exp = exponent;

        try
        {
            while (exp > 0)
            {
                if ((exp & 1) == 1)
                {
                    var temp = Multiply(result, baseValue);
                    result.Dispose();
                    result = temp;
                }

                exp >>= 1;

                if (exp > 0)
                {
                    var temp = Multiply(baseValue, baseValue);
                    baseValue.Dispose();
                    baseValue = temp;
                }
            }

            return result;
        }
        catch
        {
            result.Dispose();
            throw;
        }
        finally
        {
            baseValue.Dispose();
        }
    }

    /// <summary>
    /// Converts the current <see cref="SecureBigInteger"/> instance to a byte array representation.
    /// </summary>
    /// <returns>
    /// A byte array containing the serialized representation of the current instance,
    /// including its sign and data.
    /// </returns>
    public PinnedPoolArray<byte> ToByteArray()
    {
        this.ThrowIfDisposed();
        if (this.isNegative)
        {
            return TwosComplement(this.data.PoolArray, this.Length);
        }

        var result = new PinnedPoolArray<byte>(this.Length);
        Array.Copy(this.data.PoolArray, result.PoolArray, this.Length);
        return result;
    }

    /// <summary>
    /// Determines if the given byte array represents a negative number in two's complement representation.
    /// </summary>
    /// <param name="data">The byte array containing the data to evaluate.</param>
    /// <param name="length">The length of the byte array to process.</param>
    /// <returns>
    /// A boolean value indicating whether the byte array represents a negative number.
    /// Returns <see langword="true"/> if the data represents a negative number; otherwise, <see langword="false"/>.
    /// </returns>
    private static bool IsNegativeRepresentation(byte[] data, int length)
    {
        if (length == 0 || data is null || (length == 1 && data[0] == 0))
        {
            return false;
        }

        var msbIndex = length - 1;
        while (msbIndex > 0 && data[msbIndex] == 0)
        {
            msbIndex--;
        }

        if (msbIndex == 0 && data[0] == 0)
        {
            return false;
        }

        return (data[msbIndex] & 0x80) != 0;
    }

    /// <summary>
    /// Computes the two's complement of the given byte array representation of a number.
    /// </summary>
    /// <param name="data">The byte array representing the number to compute the two's complement for.</param>
    /// <param name="length">The length of the byte array.</param>
    /// <returns>A new byte array representing the two's complement of the given number.</returns>
    private static PinnedPoolArray<byte> TwosComplement(byte[] data, int length)
    {
        if (length == 0 || data is null || (length == 1 && data[0] == 0))
        {
            var zeroArray = new PinnedPoolArray<byte>(1);
            zeroArray[0] = 0;
            return zeroArray;
        }

        var twosCompArray = new PinnedPoolArray<byte>(length);
        for (int i = 0; i < length; i++)
        {
            twosCompArray[i] = (byte)~data[i];
        }

        int carry = 1;
        for (int i = 0; i < length && carry != 0; i++)
        {
            int sum = twosCompArray[i] + carry;
            twosCompArray[i] = (byte)sum;
            carry = sum >> 8;
        }

        return twosCompArray;
    }

    /// <summary>
    /// Calculates the logarithm to the specified base
    /// </summary>
    /// <param name="value">Value to calculate the logarithm for</param>
    /// <param name="baseValue">Base of the logarithm</param>
    /// <returns>The logarithm to the specified base or NaN if not defined</returns>
    public static double Log(SecureBigInteger value, double baseValue)
    {
        if (value is null)
        {
            throw new ArgumentNullException(nameof(value));
        }

        value.ThrowIfDisposed();
        if (double.IsNaN(baseValue))
        {
            return double.NaN;
        }

        if (baseValue == 1.0)
        {
            return double.NaN;
        }

        if (double.IsPositiveInfinity(baseValue))
        {
            return value.IsOne ? 0.0 : double.NaN;
        }

        if (baseValue == 0.0 && !value.IsOne)
        {
            return double.NaN;
        }

        if (baseValue < 0.0)
        {
            return double.NaN;
        }

        // Special cases for the value
        if (value.Sign <= 0)
        {
            return value.Sign == 0
                ? double.NegativeInfinity
                : double.NaN; // Logarithm of negative numbers is not defined
        }

        if (value.IsOne)
        {
            return 0.0;
        }

        if (value.Length <= 8)
        {
            try
            {
                ulong ulongValue = BytesToULong(value.data.PoolArray, value.Length);
                return Math.Log(ulongValue, baseValue);
            }
            catch
            {
                // Case of overflow, continue with the general method
            }
        }

        // For large numbers: log_b(x) = ln(x) / ln(b)
        double naturalLog = Log(value);
        return naturalLog / Math.Log(baseValue);
    }

    /// <summary>
    /// Calculates the natural logarithm (base e)
    /// </summary>
    /// <param name="value">Value to calculate the natural logarithm for</param>
    /// <returns>The natural logarithm</returns>
    public static double Log(SecureBigInteger value)
    {
        if (value is null)
        {
            throw new ArgumentNullException(nameof(value));
        }

        value.ThrowIfDisposed();

        if (value.Sign <= 0)
        {
            return value.Sign == 0 ? double.NegativeInfinity : double.NaN;
        }

        if (value.IsOne)
        {
            return 0.0;
        }

        // For small values, calculate directly
        if (value.Length <= 8)
        {
            try
            {
                var ulongValue = BytesToULong(value.data.PoolArray, value.Length);
                return Math.Log(ulongValue);
            }
            catch
            {
                // Case of overflow, continue with the general method
            }
        }

        // For large numbers:
        // ln(x) = ln(2^n * m) = n * ln(2) + ln(m)
        // where n is the number of bits and m is the mantissa

        var bitLength = GetBitLength(value);

        // Extract the leading bits for higher accuracy
        const int mantissaBits = 53;
        var mantissa = ExtractMantissa(value, bitLength, mantissaBits);

        // ln(x) = (bitLength - mantissaBits) * ln(2) + ln(mantissa)
        return (bitLength - mantissaBits) * Math.Log(2.0) + Math.Log(mantissa);
    }

    /// <summary>
    /// Calculates the logarithm to base 10
    /// </summary>
    /// <param name="value">Value to calculate the logarithm for</param>
    /// <returns>The logarithm to base 10</returns>
    public static double Log10(SecureBigInteger value)
    {
        if (value is null)
        {
            throw new ArgumentNullException(nameof(value));
        }

        value.ThrowIfDisposed();

        if (value.Sign <= 0)
        {
            return value.Sign == 0 ? double.NegativeInfinity : double.NaN;
        }

        if (value.IsOne)
        {
            return 0.0;
        }

        // For small values, calculate directly
        if (value.Length <= 8)
        {
            try
            {
                var ulongValue = BytesToULong(value.data.PoolArray, value.Length);
                return Math.Log10(ulongValue);
            }
            catch
            {
                // Case of overflow, continue with the general method
            }
        }

        // log10(x) = ln(x) / ln(10)
        return Log(value) / Math.Log(10.0);
    }

    /// <summary>
    /// Calculates the logarithm to base 2
    /// </summary>
    /// <param name="value">Value to calculate the logarithm for</param>
    /// <returns>The logarithm to base 2</returns>
    public static double Log2(SecureBigInteger value)
    {
        if (value is null)
        {
            throw new ArgumentNullException(nameof(value));
        }

        value.ThrowIfDisposed();

        if (value.Sign <= 0)
        {
            return value.Sign == 0 ? double.NegativeInfinity : double.NaN;
        }

        if (value.IsOne)
        {
            return 0.0;
        }

        // For small values, calculate directly
        if (value.Length <= 8)
        {
            try
            {
                ulong ulongValue = BytesToULong(value.data.PoolArray, value.Length);
                return Math.Log(ulongValue, 2.0);
            }
            catch
            {
                // Case of overflow, continue with the general method
            }
        }

        // The logarithm to base 2 can be calculated efficiently:
        var bitLength = GetBitLength(value);

        // Extract the mantissa using the leading 53 bits (double mantissa) for higher accuracy
        const int mantissaBits = 53;
        var mantissa = ExtractMantissa(value, bitLength, mantissaBits);

        // log2(x) = (bitLength - mantissaBits) + log2(mantissa)
        return (bitLength - mantissaBits) + Math.Log(mantissa, 2.0);
    }

    /// <summary>
    /// Converts the first bytes of a given byte array into a 64-bit unsigned integer (ulong) in a Little-Endian manner.
    /// </summary>
    /// <param name="data">The byte array to be converted. Only the first 8 bytes (or fewer if the array is smaller) will be considered.</param>
    /// <param name="length">The number of bytes to consider from the start of the array.</param>
    /// <returns>A 64-bit unsigned integer (ulong) representation of the first bytes of the provided array.</returns>
    private static ulong BytesToULong(byte[] data, int length)
    {
        var result = 0UL;
        var len = Math.Min(length, 8);

        for (int i = len - 1; i >= 0; i--)
        {
            result = result << 8 | data[i];
        }

        return result;
    }

    /// <summary>
    /// Extracts the leading bits from the given <see cref="SecureBigInteger"/> to form a mantissa suitable for logarithm calculations.
    /// </summary>
    /// <param name="secureBigInteger">The <see cref="SecureBigInteger"/> instance to extract the mantissa from.</param>
    /// <param name="totalBits">The total number of bits in the number.</param>
    /// <param name="bitsToExtract">The number of leading bits to extract.</param>
    /// <returns>A mantissa as a double, where 1.0 &lt;= result &lt; 2.0.</returns>
    private static double ExtractMantissa(SecureBigInteger secureBigInteger, int totalBits, int bitsToExtract)
    {
        var actualLen = GetActualLength(secureBigInteger);
        if (totalBits <= bitsToExtract)
        {
            // The entire number fits into the mantissa
            return BytesToULong(secureBigInteger.data.PoolArray, actualLen);
        }

        using var tempData = new PinnedPoolArray<byte>(actualLen);
        Array.Copy(secureBigInteger.data.PoolArray, tempData.PoolArray, actualLen);
        var bitsToShift = totalBits - bitsToExtract;
        ShiftRightInPlaceInternal(tempData.PoolArray, actualLen, bitsToShift);
        return BytesToULong(tempData.PoolArray, actualLen);
    }

    /// <summary>
    /// Shift method for byte array.
    /// </summary>
    private static void ShiftRightInPlaceInternal(byte[] data, int length, int bits)
    {
        if (bits <= 0)
        {
            return;
        }

        var byteShift = bits / 8;
        var bitShift = bits % 8;

        if (byteShift >= length)
        {
            Array.Clear(data, 0, length);
            return;
        }

        // Byte-Shift
        if (byteShift > 0)
        {
            for (int i = 0; i < length - byteShift; i++)
            {
                data[i] = data[i + byteShift];
            }

            for (int i = length - byteShift; i < length; i++)
            {
                data[i] = 0;
            }
        }

        // Bit-Shift
        if (bitShift > 0)
        {
            for (int i = 0; i < length - 1; i++)
            {
                data[i] = (byte)(data[i] >> bitShift | data[i + 1] << (8 - bitShift));
            }

            data[length - 1] >>= bitShift;
        }
    }

    /// <summary>
    /// Computes the greatest common divisor (GCD) of two <see cref="SecureBigInteger"/> instances.
    /// </summary>
    /// <param name="left">The first <see cref="SecureBigInteger"/> instance for which to compute the GCD.</param>
    /// <param name="right">The second <see cref="SecureBigInteger"/> instance for which to compute the GCD.</param>
    /// <returns>A new <see cref="SecureBigInteger"/> representing the greatest common divisor of the two input instances.</returns>
    /// <exception cref="ArgumentNullException">Thrown if either <paramref name="left"/> or <paramref name="right"/> is <see langword="null"/>.</exception>
    public static SecureBigInteger Gcd(SecureBigInteger left, SecureBigInteger right)
    {
        if (left is null)
        {
            throw new ArgumentNullException(nameof(left));
        }

        if (right is null)
        {
            throw new ArgumentNullException(nameof(right));
        }

        left.ThrowIfDisposed();
        right.ThrowIfDisposed();

        var a = left.Abs();
        var b = right.Abs();
        while (!b.IsZeroInternal())
        {
            using var temp = Remainder(a, b);
            a.Dispose();
            a = new SecureBigInteger(b);

            b.Dispose();
            b = new SecureBigInteger(temp);
        }

        b.Dispose();

        return a;
    }

    /// <summary>
    /// Computes the modular exponentiation of a <see cref="SecureBigInteger"/> value.
    /// </summary>
    /// <param name="value">The base <see cref="SecureBigInteger"/> value for the exponentiation operation.</param>
    /// <param name="exponent">The exponent <see cref="SecureBigInteger"/> value for the exponentiation operation.</param>
    /// <param name="modulus">The modulus <see cref="SecureBigInteger"/> value for the exponentiation operation.</param>
    /// <returns>A new <see cref="SecureBigInteger"/> representing the result of the modular exponentiation operation.</returns>
    /// <exception cref="ArgumentNullException">Thrown if any of the input parameters (<paramref name="value"/>, <paramref name="exponent"/>, or <paramref name="modulus"/>) is <see langword="null"/>.</exception>
    /// <exception cref="DivideByZeroException">Thrown if the modulus is zero.</exception>
    /// <exception cref="ArgumentException">Thrown if the exponent is negative.</exception>
    public static SecureBigInteger ModPow(SecureBigInteger value, SecureBigInteger exponent, SecureBigInteger modulus)
    {
        if (value is null)
        {
            throw new ArgumentNullException(nameof(value));
        }

        if (exponent is null)
        {
            throw new ArgumentNullException(nameof(exponent));
        }

        if (modulus is null)
        {
            throw new ArgumentNullException(nameof(modulus));
        }

        value.ThrowIfDisposed();
        exponent.ThrowIfDisposed();
        modulus.ThrowIfDisposed();

        if (modulus.IsZeroInternal())
        {
            throw new DivideByZeroException("Modulus must not be zero");
        }

        if (exponent.isNegative)
        {
            throw new ArgumentException("Exponent must be non-negative", nameof(exponent));
        }

        var result = new SecureBigInteger(1);
        SecureBigInteger baseValue = null;
        try
        {
            baseValue = Remainder(value, modulus);
            using var exp = new SecureBigInteger(exponent);
            while (!exp.IsZeroInternal())
            {
                if ((exp.data[0] & 1) == 1)
                {
                    using var temp = Multiply(result, baseValue);
                    using var tempMod = Remainder(temp, modulus);
                    result.Dispose();
                    result = new SecureBigInteger(tempMod);
                }

                ShiftRightInPlace(exp, 1);

                if (!exp.IsZeroInternal())
                {
                    using var temp = Multiply(baseValue, baseValue);
                    using var tempMod = Remainder(temp, modulus);
                    baseValue.Dispose();
                    baseValue = new SecureBigInteger(tempMod);
                }
            }

            return result;
        }
        catch
        {
            result.Dispose();
            throw;
        }
        finally
        {
            baseValue?.Dispose();
        }
    }

    /// <summary>
    /// Addition operator for <see cref="SecureBigInteger"/>.
    /// </summary>
    /// <param name="left">1st summand</param>
    /// <param name="right">2nd summand</param>
    /// <returns>sum</returns>
    public static SecureBigInteger operator +(SecureBigInteger left, SecureBigInteger right) => Add(left, right);

    /// <summary>
    /// Subtraction operator for <see cref="SecureBigInteger"/>.
    /// </summary>
    /// <param name="left">minuend</param>
    /// <param name="right">subtrahend</param>
    /// <returns>difference</returns>
    public static SecureBigInteger operator -(SecureBigInteger left, SecureBigInteger right) => Subtract(left, right);

    /// <summary>
    /// Multiplication operator for <see cref="SecureBigInteger"/>.
    /// </summary>
    /// <param name="left">multiplicand</param>
    /// <param name="right">multiplier</param>
    /// <returns>product</returns>
    public static SecureBigInteger operator *(SecureBigInteger left, SecureBigInteger right) => Multiply(left, right);

    /// <summary>
    /// Division operator for <see cref="SecureBigInteger"/>.
    /// </summary>
    /// <param name="left">dividend</param>
    /// <param name="right">divisor</param>
    /// <returns>quotient</returns>
    public static SecureBigInteger operator /(SecureBigInteger left, SecureBigInteger right) => Divide(left, right);

    /// <summary>
    /// Remainder operator for <see cref="SecureBigInteger"/>.
    /// </summary>
    /// <param name="left">dividend</param>
    /// <param name="right">divisor</param>
    /// <returns>remainder</returns>
    public static SecureBigInteger operator %(SecureBigInteger left, SecureBigInteger right) => Remainder(left, right);

    /// <summary>
    /// Unary negation operator for <see cref="SecureBigInteger"/>.
    /// </summary>
    /// <param name="value">Value to negate</param>
    /// <returns>Negated value</returns>
    public static SecureBigInteger operator -(SecureBigInteger value) => value?.Negate();

    /// <summary>
    /// Defines the behavior of the increment operator (++) for the <see cref="SecureBigInteger"/> class,
    /// which increases the value of a <see cref="SecureBigInteger"/> instance by one.
    /// </summary>
    /// <param name="value">The <see cref="SecureBigInteger"/> value to increment.</param>
    /// <returns>A new <see cref="SecureBigInteger"/> instance representing the incremented value.</returns>
    public static SecureBigInteger operator ++(SecureBigInteger value)
    {
        using var one = new SecureBigInteger(1);
        return Add(value, one);
    }

    /// <summary>
    /// Defines the behavior of the decrement operator (--) for the <see cref="SecureBigInteger"/> class,
    /// which decreases the value of a <see cref="SecureBigInteger"/> instance by one.
    /// </summary>
    /// <param name="value">The <see cref="SecureBigInteger"/> value to decrement.</param>
    /// <returns>A new <see cref="SecureBigInteger"/> instance representing the decremented value.</returns>
    public static SecureBigInteger operator --(SecureBigInteger value)
    {
        using var one = new SecureBigInteger(1);
        return Subtract(value, one);
    }

    /// <summary>
    /// Equality operator for <see cref="SecureBigInteger"/>.
    /// </summary>
    /// <param name="left">first object to compare</param>
    /// <param name="right">second object to compare</param>
    /// <returns><see langword="true"/> if the <paramref name="left"/> instance is equal to the
    /// <paramref name="right"/> instance; otherwise, <see langword="false"/>.</returns>
    public static bool operator ==(SecureBigInteger left, SecureBigInteger right)
    {
        if (ReferenceEquals(left, right))
        {
            return true;
        }

        if (left is null || right is null)
        {
            return false;
        }

        return left.Equals(right);
    }

    /// <summary>
    /// Inequality operator for <see cref="SecureBigInteger"/>.
    /// </summary>
    /// <param name="left"></param>
    /// <param name="right"></param>
    /// <returns>><see langword="true"/> if the <paramref name="left"/> instance is not equal to the
    /// <paramref name="right"/> instance; otherwise, <see langword="false"/>.</returns>
    public static bool operator !=(SecureBigInteger left, SecureBigInteger right) => !(left == right);

    /// <summary>
    /// Defines the less-than operator for comparing two instances of <see cref="SecureBigInteger"/>.
    /// </summary>
    /// <param name="left">The first <see cref="SecureBigInteger"/> to compare.</param>
    /// <param name="right">The second <see cref="SecureBigInteger"/> to compare.</param>
    /// <returns>
    /// Returns <see langword="true"/> if <paramref name="left"/> is less than <paramref name="right"/>;
    /// otherwise, <see langword="false"/>.
    /// </returns>
    /// <exception cref="ArgumentNullException">
    /// Thrown if <paramref name="left"/> or <paramref name="right"/> is <see langword="null"/>.
    /// </exception>
    public static bool operator <(SecureBigInteger left, SecureBigInteger right)
    {
        if (left is null)
        {
            throw new ArgumentNullException(nameof(left));
        }

        if (right is null)
        {
            throw new ArgumentNullException(nameof(right));
        }

        return left.CompareTo(right) < 0;
    }

    /// <summary>
    /// Performs a greater-than comparison between two instances of <see cref="SecureBigInteger"/>.
    /// </summary>
    /// <param name="left">The first <see cref="SecureBigInteger"/> to compare.</param>
    /// <param name="right">The second <see cref="SecureBigInteger"/> to compare.</param>
    /// <returns>
    /// <see langword="true"/> if the <paramref name="left"/> is greater than the <paramref name="right"/>;
    /// otherwise, <see langword="false"/>.
    /// </returns>
    /// <exception cref="ArgumentNullException">
    /// Thrown if either <paramref name="left"/> or <paramref name="right"/> is <see langword="null"/>.
    /// </exception>
    public static bool operator >(SecureBigInteger left, SecureBigInteger right)
    {
        if (left is null)
        {
            throw new ArgumentNullException(nameof(left));
        }

        if (right is null)
        {
            throw new ArgumentNullException(nameof(right));
        }

        return left.CompareTo(right) > 0;
    }

    /// <summary>
    /// 
    /// </summary>
    /// <param name="left"></param>
    /// <param name="right"></param>
    /// <returns></returns>
    public static bool operator <=(SecureBigInteger left, SecureBigInteger right) => left < right || left == right;

    /// <summary>
    /// 
    /// </summary>
    /// <param name="left"></param>
    /// <param name="right"></param>
    /// <returns></returns>
    public static bool operator >=(SecureBigInteger left, SecureBigInteger right) => left > right || left == right;

    /// <summary>
    /// Implicit conversion from <see cref="int"/> to <see cref="SecureBigInteger"/>.
    /// </summary>
    /// <param name="value">The integer value to convert.</param>
    /// <returns>A <see cref="SecureBigInteger"/> instance representing the integer value.</returns>
    public static implicit operator SecureBigInteger(int value) => new SecureBigInteger(value);

    /// <summary>
    /// Implicit conversion from <see cref="long"/> to <see cref="SecureBigInteger"/>.
    /// </summary>
    /// <param name="value">The long integer value to convert.</param>
    /// <returns>A <see cref="SecureBigInteger"/> instance representing the long integer value.</returns>
    public static implicit operator SecureBigInteger(long value) => new SecureBigInteger(value);

    /// <summary>
    /// Explicit conversion from <see cref="SecureBigInteger"/> to <see cref="int"/>.
    /// </summary>
    /// <param name="value">The <see cref="SecureBigInteger"/> instance to convert.</param>
    /// <returns>A <see cref="int"/> value  representing the <see cref="SecureBigInteger" /> instance.</returns>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="value"/> is null.</exception>
    /// <exception cref="OverflowException">Thrown if the <see cref="SecureBigInteger"/> value is too large for <see cref="int"/>.</exception>
    public static explicit operator int(SecureBigInteger value)
    {
        if (value is null)
        {
            throw new ArgumentNullException(nameof(value));
        }

        value.ThrowIfDisposed();

        if (value.Length > 4)
        {
            throw new OverflowException("Value is too large for int");
        }

        uint result = 0;
        for (var i = Math.Min(3, value.Length - 1); i >= 0; i--)
        {
            result = (result << 8) | value.data[i];
        }

        if (result > int.MaxValue && !(value.isNegative && result == (uint)int.MaxValue + 1))
        {
            throw new OverflowException("Value is too large for int");
        }

        return value.isNegative ? -(int)result : (int)result;
    }

    /// <summary>
    /// Explicit conversion from <see cref="SecureBigInteger"/> to <see cref="long"/>.
    /// </summary>
    /// <param name="value">The <see cref="SecureBigInteger"/> instance to convert.</param>
    /// <returns>A <see cref="long"/> value representing the <see cref="SecureBigInteger" /> instance.</returns>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="value"/> is null.</exception>
    /// <exception cref="OverflowException">Thrown if the <see cref="SecureBigInteger"/> value is too large for <see cref="long"/>.</exception>
    public static explicit operator long(SecureBigInteger value)
    {
        if (value is null)
        {
            throw new ArgumentNullException(nameof(value));
        }

        value.ThrowIfDisposed();

        if (value.Length > 8)
        {
            throw new OverflowException("The value is too large for long");
        }

        var result = 0UL;
        for (var i = Math.Min(7, value.Length - 1); i >= 0; i--)
        {
            result = result << 8 | value.data[i];
        }

        if (result > long.MaxValue && !(value.isNegative && result == (ulong)long.MaxValue + 1))
        {
            throw new OverflowException("The value is too large for long");
        }

        return value.isNegative ? -(long)result : (long)result;
    }

    /// <summary>
    /// Adds two unsigned <see cref="SecureBigInteger"/> values and returns the result.
    /// </summary>
    /// <param name="left">The first unsigned <see cref="SecureBigInteger"/> value to add.</param>
    /// <param name="right">The second unsigned <see cref="SecureBigInteger"/> value to add.</param>
    /// <returns>A new <see cref="SecureBigInteger"/> representing the sum of the two input values.</returns>
    private static SecureBigInteger AddUnsigned(SecureBigInteger left, SecureBigInteger right)
    {
        var leftLen = GetActualLength(left);
        var rightLen = GetActualLength(right);
        var maxLen = Math.Max(leftLen, rightLen);
        using var result = new PinnedPoolArray<byte>(maxLen + 1);

        var carry = 0;
        var i = 0;
        for (; i < maxLen || carry > 0; i++)
        {
            var sum = carry;
            if (i < leftLen)
            {
                sum += left.data[i];
            }

            if (i < rightLen)
            {
                sum += right.data[i];
            }

            result[i] = (byte)(sum & 0xFF);
            carry = sum >> 8;
        }

        return new SecureBigInteger(result.PoolArray, i, false);
    }

    /// <summary>
    /// Subtracts two unsigned <see cref="SecureBigInteger"/> instances and returns the result.
    /// </summary>
    /// <param name="left">The minuend <see cref="SecureBigInteger"/> instance.</param>
    /// <param name="right">The subtrahend <see cref="SecureBigInteger"/> instance.</param>
    /// <returns>A new <see cref="SecureBigInteger"/> instance representing the unsigned subtraction result.</returns>
    private static SecureBigInteger SubtractUnsigned(SecureBigInteger left, SecureBigInteger right)
    {
        var leftLen = GetActualLength(left);
        var rightLen = GetActualLength(right);
        using var result = new PinnedPoolArray<byte>(leftLen);

        var borrow = 0;
        var i = 0;
        for (; i < leftLen; i++)
        {
            int diff = left.data[i] - borrow;
            if (i < rightLen)
            {
                diff -= right.data[i];
            }

            if (diff < 0)
            {
                diff += 256;
                borrow = 1;
            }
            else
            {
                borrow = 0;
            }

            result[i] = (byte)diff;
        }

        return new SecureBigInteger(result.PoolArray, GetActualLength(result.PoolArray, i), false);
    }

    /// <summary>
    /// Multiplies two unsigned <see cref="SecureBigInteger"/> values and returns the result.
    /// </summary>
    /// <param name="left">The first <see cref="SecureBigInteger"/> operand in the multiplication.</param>
    /// <param name="right">The second <see cref="SecureBigInteger"/> operand in the multiplication.</param>
    /// <returns>A new <see cref="SecureBigInteger"/> instance representing the product of the two inputs.</returns>
    private static SecureBigInteger MultiplyUnsigned(SecureBigInteger left, SecureBigInteger right)
    {
        var leftLen = GetActualLength(left);
        var rightLen = GetActualLength(right);

        if (leftLen == 1 && left.data[0] == 0 || rightLen == 1 && right.data[0] == 0)
        {
            return new SecureBigInteger(0);
        }

        using var result = new PinnedPoolArray<byte>(leftLen + rightLen);
        for (int i = 0; i < leftLen; i++)
        {
            if (left.data[i] == 0)
            {
                continue;
            }

            ulong carry = 0;
            for (int j = 0; j < rightLen || carry > 0; j++)
            {
                ulong product = result[i + j] + carry;
                if (j < rightLen)
                {
                    product += (ulong)left.data[i] * right.data[j];
                }

                result[i + j] = (byte)(product & 0xFF);
                carry = product >> 8;
            }
        }

        return new SecureBigInteger(result.PoolArray, GetActualLength(result.PoolArray, leftLen + rightLen), false);
    }

    /// <summary>
    /// Performs an unsigned division of two <see cref="SecureBigInteger"/> instances and returns the quotient.
    /// Additionally, calculates the remainder of the division and outputs it through the <paramref name="remainder"/> parameter.
    /// </summary>
    /// <param name="dividend">The <see cref="SecureBigInteger"/> to divide.</param>
    /// <param name="divisor">The <see cref="SecureBigInteger"/> to divide by.</param>
    /// <param name="remainder">The out parameter that will contain the remainder of the division.</param>
    /// <returns>A new <see cref="SecureBigInteger"/> representing the unsigned quotient of the division.</returns>
    private static SecureBigInteger DivideUnsigned(SecureBigInteger dividend, SecureBigInteger divisor,
        out SecureBigInteger remainder)
    {
        var dividendLen = GetActualLength(dividend);
        var divisorLen = GetActualLength(divisor);
        var cmp = CompareUnsigned(dividend.data.PoolArray, dividendLen, divisor.data.PoolArray, divisorLen);

        switch (cmp)
        {
            case < 0:
                remainder = new SecureBigInteger(dividend.data.PoolArray, dividendLen, false);
                return new SecureBigInteger(0);
            case 0:
                remainder = new SecureBigInteger(0);
                return new SecureBigInteger(1);
        }

        var bitLength = GetBitLength(dividend);
        using var quotient = new PinnedPoolArray<byte>((bitLength + 7) / 8);

        var currentRemainder = new SecureBigInteger(0);
        using var one = new SecureBigInteger(1);
        for (var i = bitLength - 1; i >= 0; i--)
        {
            var nextRemainder = ShiftLeftByOneBit(currentRemainder);
            currentRemainder.Dispose();
            currentRemainder = nextRemainder;

            if (GetBit(dividend.data.PoolArray, i))
            {
                var nextRemWithBit = AddUnsigned(currentRemainder, one);
                currentRemainder.Dispose();
                currentRemainder = nextRemWithBit;
            }

            if (CompareUnsigned(currentRemainder.data.PoolArray, currentRemainder.Length, divisor.data.PoolArray, divisorLen) >= 0)
            {
                var nextRemSub = SubtractUnsigned(currentRemainder, divisor);
                currentRemainder.Dispose();
                currentRemainder = nextRemSub;
                SetBit(quotient.PoolArray, i);
            }
        }

        remainder = currentRemainder;

        return new SecureBigInteger(quotient.PoolArray, GetActualLength(quotient.PoolArray, (bitLength + 7) / 8), false);
    }

    /// <summary>
    /// Sets a specific bit in the given byte array to 1 at the specified bit index.
    /// </summary>
    /// <param name="data">The byte array in which the bit will be set.</param>
    /// <param name="bitIndex">The index of the bit to set, where the index is zero-based and spans across the entire array.</param>
    private static void SetBit(byte[] data, int bitIndex)
    {
        var byteIndex = bitIndex / 8;
        var bitInByte = bitIndex % 8;

        if (byteIndex < data.Length)
        {
            data[byteIndex] |= (byte)(1 << bitInByte);
        }
    }

    /// <summary>
    /// Compares two <see cref="SecureBigInteger"/> instances as unsigned values and returns a value that indicates their relative order.
    /// </summary>
    /// <param name="left">The first <see cref="SecureBigInteger"/> instance to compare.</param>
    /// <param name="right">The second <see cref="SecureBigInteger"/> instance to compare.</param>
    /// <returns>
    /// A signed integer that indicates the relative order of the values:
    /// Less than zero if <paramref name="left"/> is less than <paramref name="right"/>.
    /// Zero if <paramref name="left"/> is equal to <paramref name="right"/>.
    /// Greater than zero if <paramref name="left"/> is greater than <paramref name="right"/>.
    /// </returns>
    private static int CompareUnsigned(SecureBigInteger left, SecureBigInteger right)
    {
        var leftLength = GetActualLength(left);
        var rightLength = GetActualLength(right);
        return CompareUnsigned(left.data.PoolArray, leftLength, right.data.PoolArray, rightLength);
    }

    /// <summary>
    /// Compares two unsigned byte arrays representing large integer values.
    /// </summary>
    /// <param name="left">The byte array representing the first unsigned integer.</param>
    /// <param name="leftLen">The number of significant bytes in the first unsigned integer.</param>
    /// <param name="right">The byte array representing the second unsigned integer.</param>
    /// <param name="rightLen">The number of significant bytes in the second unsigned integer.</param>
    /// <returns>
    /// Returns 1 if the first unsigned integer is greater than the second,
    /// -1 if the first unsigned integer is less than the second, and 0 if they are equal.
    /// </returns>
    private static int CompareUnsigned(byte[] left, int leftLen, byte[] right, int rightLen)
    {
        if (leftLen > rightLen)
        {
            return 1;
        }

        if (leftLen < rightLen)
        {
            return -1;
        }

        for (var i = leftLen - 1; i >= 0; i--)
        {
            if (left[i] > right[i])
            {
                return 1;
            }

            if (left[i] < right[i])
            {
                return -1;
            }
        }

        return 0;
    }

    /// <summary>
    /// Removes leading zeros from the internal representation of the <see cref="SecureBigInteger"/> instance.
    /// Adjusts the length property to accurately reflect the number of significant bytes.
    /// </summary>
    private void TrimLeadingZerosInPlace()
    {
        this.Length = GetActualLength(this);
    }

    /// <summary>
    /// Computes the actual length of the given byte array excluding leading zero bytes.
    /// </summary>
    /// <param name="data">The byte array for which the actual length is to be determined.</param>
    /// <param name="length">The length of the byte array to consider.</param>
    /// <returns>The actual length of the byte array, excluding leading zero bytes. If the array contains only zeros,
    /// it returns 1.</returns>
    private static int GetActualLength(byte[] data, int length)
    {
        for (var i = length - 1; i >= 0; i--)
        {
            if (data[i] != 0)
            {
                return i + 1;
            }
        }

        return 1;
    }

    /// <summary>
    /// Calculates the actual length of significant data in the specified <see cref="SecureBigInteger"/> instance,
    /// excluding leading zeros.
    /// </summary>
    /// <param name="secureBigInteger">The <see cref="SecureBigInteger"/> instance for which to calculate the actual length.</param>
    /// <returns>The number of significant bytes in the <paramref name="secureBigInteger"/> instance.</returns>
    private static int GetActualLength(SecureBigInteger secureBigInteger)
    {
        return GetActualLength(secureBigInteger.data.PoolArray, secureBigInteger.Length);
    }

    /// <summary>
    /// Calculates the bit length of the specified <see cref="SecureBigInteger"/> instance.
    /// </summary>
    /// <param name="secureBigInteger">The <see cref="SecureBigInteger"/> whose bit length is to be calculated.</param>
    /// <returns>The number of bits required to represent the value of the <see cref="SecureBigInteger"/>.</returns>
    private static int GetBitLength(SecureBigInteger secureBigInteger)
    {
        var len = GetActualLength(secureBigInteger);
        if (len == 0 || (len == 1 && secureBigInteger.data[0] == 0))
        {
            return 0;
        }

        var highByte = secureBigInteger.data[len - 1];
        var bits = (len - 1) * 8;

        while (highByte > 0)
        {
            bits++;
            highByte >>= 1;
        }

        return bits;
    }

    /// <summary>
    /// Determines whether the specified bit is set in a byte array.
    /// </summary>
    /// <param name="data">The byte array from which to check the specified bit.</param>
    /// <param name="bitIndex">The zero-based index of the bit to check.</param>
    /// <returns>Returns <see langword="true"/> if the specified bit is set; otherwise, returns <see langword="false"/>.</returns>
    private static bool GetBit(byte[] data, int bitIndex)
    {
        var byteIndex = bitIndex / 8;
        var bitInByte = bitIndex % 8;

        if (byteIndex >= data.Length)
        {
            return false;
        }

        return (data[byteIndex] >> bitInByte & 1) == 1;
    }

    /// <summary>
    /// Shifts the bits of the specified <see cref="SecureBigInteger"/> to the left by one position.
    /// </summary>
    /// <param name="secureBigInteger">
    /// The <see cref="SecureBigInteger"/> instance whose bits are to be shifted left by one position.
    /// </param>
    /// <returns>
    /// A new <see cref="SecureBigInteger"/> representing the result of the left bitwise shift operation.
    /// </returns>
    private static SecureBigInteger ShiftLeftByOneBit(SecureBigInteger secureBigInteger)
    {
        var actualLen = GetActualLength(secureBigInteger);
        using var result = new PinnedPoolArray<byte>(actualLen + 1);

        var carry = 0;

        for (var i = 0; i < actualLen; i++)
        {
            int shifted = (secureBigInteger.data[i] << 1) | carry;
            result[i] = (byte)(shifted & 0xFF);
            carry = shifted >> 8;
        }

        var finalLen = actualLen;
        if (carry > 0)
        {
            result[actualLen] = (byte)carry;
            finalLen++;
        }

        return new SecureBigInteger(result.PoolArray, GetActualLength(result.PoolArray, finalLen), false);
    }

    private static SecureBigInteger ShiftRight(SecureBigInteger value, int bits)
    {
        if (bits <= 0)
        {
            return new SecureBigInteger(value);
        }

        var byteShift = bits / 8;
        var bitShift = bits % 8;

        if (byteShift >= value.Length)
        {
            return new SecureBigInteger(0);
        }

        using var result = new PinnedPoolArray<byte>(value.Length - byteShift);

        for (int i = 0; i < value.Length - byteShift; i++)
        {
            int val = value.data[i + byteShift] >> bitShift;

            if (i + byteShift + 1 < value.Length && bitShift > 0)
            {
                val |= (value.data[i + byteShift + 1] << (8 - bitShift)) & 0xFF;
            }

            result[i] = (byte)val;
        }

        return new SecureBigInteger(result.PoolArray, GetActualLength(result.PoolArray, value.Length - byteShift), value.isNegative);
    }

    private static void ShiftRightInPlace(SecureBigInteger value, int bits)
    {
        if (bits <= 0)
        {
            return;
        }

        var byteShift = bits / 8;
        var bitShift = bits % 8;

        if (byteShift >= value.Length)
        {
            value.data.SecureClear();
            value.Length = 1;
            value.data[0] = 0;
            value.isNegative = false;
            return;
        }

        // Byte-Shift
        if (byteShift > 0)
        {
            for (int i = 0; i < value.Length - byteShift; i++)
            {
                value.data[i] = value.data[i + byteShift];
            }

            for (int i = value.Length - byteShift; i < value.Length; i++)
            {
                value.data[i] = 0;
            }

            value.Length -= byteShift;
        }

        // Bit-Shift
        if (bitShift > 0)
        {
            for (int i = 0; i < value.Length - 1; i++)
            {
                value.data[i] = (byte)(value.data[i] >> bitShift | value.data[i + 1] << (8 - bitShift));
            }

            value.data[value.Length - 1] >>= bitShift;
        }

        value.TrimLeadingZerosInPlace();
        if (value.IsZeroInternal())
        {
            value.isNegative = false;
        }
    }

    /// <summary>
    /// Determines whether the current <see cref="SecureBigInteger"/> instance represents the value zero.
    /// </summary>
    /// <returns>
    /// True if the instance represents the value zero; otherwise, false.
    /// </returns>
    private bool IsZeroInternal() => this.Length == 1 && this.data[0] == 0;

    /// <summary>
    /// Throws an <see cref="ObjectDisposedException"/> if the current instance has been disposed.
    /// </summary>
    /// <exception cref="ObjectDisposedException">
    /// Thrown when an attempt is made to access a disposed instance of <see cref="SecureBigInteger"/>.
    /// </exception>
    private void ThrowIfDisposed()
    {
        if (Volatile.Read(ref this.disposed) == 1)
        {
            throw new ObjectDisposedException(nameof(SecureBigInteger));
        }
    }

    /// <summary>
    /// Releases all resources used by the current instance of the <see cref="SecureBigInteger"/> class.
    /// </summary>
    public void Dispose()
    {
        this.Dispose(true);
        GC.SuppressFinalize(this);
    }

    /// <summary>
    /// Releases the resources used by the <see cref="SecureBigInteger"/> instance.
    /// </summary>
    /// <param name="disposing">A boolean value indicating whether to release managed resources (true) or
    /// only unmanaged resources (false).</param>
    private void Dispose(bool disposing)
    {
        if (Interlocked.Exchange(ref this.disposed, 1) == 1)
        {
            return;
        }

        if (!disposing)
        {
            return;
        }

        // Release managed resources if any
        this.data?.Dispose();
        this.data = null;
    }

    /// <summary>
    /// Determines whether the current instance is equal to another <see cref="SecureBigInteger"/> instance.
    /// </summary>
    /// <param name="other">The <see cref="SecureBigInteger"/> instance to compare with the current instance.</param>
    /// <returns><see langword="true"/> if the current instance is equal to the <paramref name="other"/> instance;
    /// otherwise, <see langword="false"/>.</returns>
    /// <remarks>The equality comparison is performed in constant time to prevent timing attacks. </remarks>
    public bool Equals(SecureBigInteger other)
    {
        if (other is null)
        {
            return false;
        }

        if (ReferenceEquals(this, other))
        {
            return true;
        }

        this.ThrowIfDisposed();
        other.ThrowIfDisposed();

        if (this.isNegative != other.isNegative)
        {
            return false;
        }

        if (this.Length != other.Length)
        {
            return false;
        }

#if (NET8_0_OR_GREATER || NETSTANDARD2_1_OR_GREATER)
        return CryptographicOperations.FixedTimeEquals(this.data.PoolArray.AsSpan(0, this.Length),
            other.data.PoolArray.AsSpan(0, other.Length));
#else
        return this.data.FixedTimeEquals(other.data);
#endif
    }

    /// <summary>
    /// Determines whether the specified object is equal to the current <see cref="SecureBigInteger"/> instance.
    /// </summary>
    /// <param name="obj">The object to compare with the current <see cref="SecureBigInteger"/>.</param>
    /// <returns>
    /// <see langword="true"/> if the specified object is equal to the current <see cref="SecureBigInteger"/>;
    /// otherwise, <see langword="false"/>.
    /// </returns>
    public override bool Equals(object obj) => obj is SecureBigInteger other && this.Equals(other);

    /// <summary>
    /// Returns the hash code for the current instance of the <see cref="SecureBigInteger"/> class.
    /// </summary>
    /// <returns>An integer representing the hash code of the current instance.</returns>
    [SuppressMessage("ReSharper", "NonReadonlyMemberInGetHashCode", Justification = "Fields are not externally mutable. Fields are inernally mutable only for creation purposes.")]
    [SuppressMessage("SonarQube", "S2328", Justification = "Fields are not externally mutable. Fields are inernally mutable only for creation purposes.")]
    public override int GetHashCode()
    {
        this.ThrowIfDisposed();
#if NETSTANDARD2_1_OR_GREATER || NET8_0_OR_GREATER
        var hash = new HashCode();
        hash.Add(this.Sign);
        hash.Add(this.Length);
#if NET8_0_OR_GREATER
        hash.AddBytes(this.data.PoolArray.AsSpan(0, this.Length));
#else
        for (int i = 0; i < this.Length; i++)
        {
            hash.Add(this.data[i]);
        }
#endif
        return hash.ToHashCode();
#else
        unchecked
        {
            var hash = 17;
            hash = hash * 31 + this.Sign.GetHashCode();
            hash = hash * 31 + this.Length.GetHashCode();
            for (int i = 0; i < this.Length; i++)
            {
                hash = hash * 31 + this.data[i].GetHashCode();
            }

            return hash;
        }
#endif
    }

    /// <summary>
    /// Compares the current instance to another <see cref="SecureBigInteger"/> object
    /// and returns an integer indicating the relative order of the objects.
    /// </summary>
    /// <param name="other">The <see cref="SecureBigInteger"/> object to compare with the current instance.</param>
    /// <returns>
    /// A signed integer indicating the relative values of the current instance and the <paramref name="other"/> object:
    /// - Less than zero if the current instance is less than <paramref name="other"/>.
    /// - Zero if the current instance is equal to <paramref name="other"/>.
    /// - Greater than zero if the current instance is greater than <paramref name="other"/>.
    /// </returns>
    public int CompareTo(SecureBigInteger other)
    {
        if (other is null)
        {
            return 1;
        }

        this.ThrowIfDisposed();
        other.ThrowIfDisposed();

        if (this.isNegative != other.isNegative)
        {
            return this.isNegative ? -1 : 1;
        }

        int comparison = CompareUnsigned(this.data.PoolArray, this.Length, other.data.PoolArray, other.Length);
        return this.isNegative ? -comparison : comparison;
    }

    /// <summary>
    /// Converts the current <see cref="SecureBigInteger"/> instance to a character array representation.
    /// </summary>
    /// <returns>A character array containing the string representation of the current instance.</returns>
    public PinnedPoolArray<char> ToPinnedCharArray()
    {
        this.ThrowIfDisposed();

        if (this.IsZeroInternal())
        {
            var zeroArray = new PinnedPoolArray<char>(1);
            zeroArray[0] = DigitOffset;
            return zeroArray;
        }

        using var negatedValue = this.Negate();
        var digitCount = (int)(Log10(this.isNegative ? negatedValue: this) + 1);

        var totalLength = this.isNegative ? digitCount + 1 : digitCount;
        var result = new PinnedPoolArray<char>(totalLength);
        var index = totalLength - 1;

        var temp = new SecureBigInteger(this);
        // Work with absolute value
        temp.isNegative = false;
        using var zero = new SecureBigInteger(0);
        using var ten = new SecureBigInteger(10);

        while (CompareUnsigned(temp.data.PoolArray, temp.Length, zero.data.PoolArray, 1) > 0)
        {
            using var quotient = DivideUnsigned(temp, ten, out var rem);
            result[index--] = (char)(DigitOffset + rem.data[0]);
            rem.Dispose();
            temp.Dispose();
            temp = new SecureBigInteger(quotient);
        }

        temp.Dispose();

        if (this.isNegative)
        {
            result[0] = '-';
        }

        return result;
    }

    /// <summary>
    /// Returns a string representation of the <see cref="SecureBigInteger"/> instance.
    /// </summary>
    /// <returns>
    /// A string that represents the current <see cref="SecureBigInteger"/> instance.
    /// In debug mode, the string includes the numerical value of the object, while in release mode,
    /// it returns a placeholder string indicating secured content.
    /// </returns>
    public override string ToString()
    {
        this.ThrowIfDisposed();
#if DEBUG
        using var pinnedCharArray = this.ToPinnedCharArray();
        var s = new string(pinnedCharArray.PoolArray, 0, pinnedCharArray.Length);
        return $"{this.GetType().Name}({s})";
#else
        return "*** Secured Value ***";
#endif
    }

    /// <summary>
    /// Converts the current <see cref="SecureBigInteger"/> instance to its hexadecimal string representation.
    /// </summary>
    /// <returns>
    /// A <see cref="PinnedPoolArray{T}"/> containing the hexadecimal representation of the number.
    /// If the instance is negative, the resulting hexadecimal string starts with a '-' character.
    /// </returns>
    public PinnedPoolArray<char> ToHexadecimal()
    {
        this.ThrowIfDisposed();

        var hexLength = this.Length * 2;
        var totalLength = this.isNegative ? hexLength + 1 : hexLength;
        var result = new PinnedPoolArray<char>(totalLength);
        var index = 0;

        if (this.isNegative)
        {
            result[index++] = '-';
        }

        for (int i = this.Length - 1; i >= 0; i--)
        {
            byte b = this.data[i];
            result[index++] = GetHexChar((b >> 4) & 0xF);
            result[index++] = GetHexChar(b & 0xF);
        }

        return result;
    }

    private static char GetHexChar(int value)
    {
        return value < 10 ? (char)(DigitOffset + value) : (char)('A' + value - 10);
    }
}
