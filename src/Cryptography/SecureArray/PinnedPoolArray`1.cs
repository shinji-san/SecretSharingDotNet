// ----------------------------------------------------------------------------
// <copyright file="PinnedPoolArray`1.cs" company="Private">
// Copyright (c) 2025 All Rights Reserved
// </copyright>
// <author>Sebastian Walther</author>
// <date>12/07/2025 06:20:00 PM</date>
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

namespace SecretSharingDotNet.Cryptography.SecureArray;

using System;
using System.Buffers;
using System.Collections;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
#if (NET8_0_OR_GREATER || NETSTANDARD2_1_OR_GREATER)
using System.Security.Cryptography;
#endif
using System.Threading;

/// <summary>
/// Represents a memory-efficient, array-backed pool that ensures the memory is pinned.
/// This class is specifically designed for scenarios where memory must remain fixed in
/// physical address space, such as when interacting with unmanaged APIs or handling
/// cryptographic operations that require secure and predictable memory access.
/// </summary>
/// <typeparam name="T">
/// The element type stored in the array. Must be an <c>unmanaged</c> type — a non-nullable
/// value type containing no reference fields at any nesting level. This stricter constraint
/// (over the more permissive <c>struct</c>) is required because the buffer is GC-pinned via
/// <see cref="GCHandle.Alloc(object, GCHandleType)"/> with <see cref="GCHandleType.Pinned"/>
/// and reinterpreted as raw bytes during <see cref="SecureClear"/>; both operations fail at
/// runtime for value types containing references.
/// </typeparam>
public sealed class PinnedPoolArray<T> : IStructuralComparable, IStructuralEquatable, IDisposable where T : unmanaged
{
    /// <summary>
    /// Indicates whether the current instance has been disposed.
    /// </summary>
    private int disposed;

    /// <summary>
    /// Counts in-flight public <see cref="SecureClear"/> calls. Incremented on entry,
    /// decremented in the corresponding <c>finally</c>. <see cref="Dispose(bool)"/>
    /// drains this counter to zero before returning the buffer to the pool, ensuring
    /// no thread is still writing to <see cref="poolArray"/> at return time.
    /// </summary>
    private int activeOperations;

    /// <summary>
    /// Represents the array rented from a shared array pool, used as a memory buffer
    /// with enhanced performance and reduced allocations, and pinned in memory to
    /// ensure stable access for unmanaged code.
    /// </summary>
    private readonly T[] poolArray;

    /// <summary>
    /// Represents a handle to the array rented from the shared array pool, which is pinned in memory
    /// to prevent it from being moved by the garbage collector, ensuring stable access for unmanaged code.
    /// </summary>
    private GCHandle poolArrayHandle;

    /// <summary>
    /// Represents the length of the pinned array managed by the <see cref="PinnedPoolArray{T}"/> instance.
    /// </summary>
    private int length;

    /// <summary>
    /// Initializes a new instance of the <see cref="PinnedPoolArray{T}"/> class.
    /// </summary>
    /// <param name="length">The length of the byte array to be pinned.</param>
    public PinnedPoolArray(int length)
    {
        this.poolArray = ArrayPool<T>.Shared.Rent(length);
        this.poolArrayHandle = GCHandle.Alloc(this.poolArray, GCHandleType.Pinned);
        Array.Clear(this.poolArray, 0, this.poolArray.Length);
        this.Length = length;
    }
    
    /// <summary>
    /// Finalizes an instance of the <see cref="PinnedPoolArray{T}"/> class.
    /// </summary>
    ~PinnedPoolArray()
    {
        this.Dispose(false);
    }

    /// <summary>
    /// Gets or sets the logical length of the pinned buffer. Must be in <c>[0, Capacity]</c>.
    /// </summary>
    /// <remarks>
    /// Length defines the range exposed to consumers via the indexer and the subset of bytes
    /// copied/interpreted by callers. It does <b>not</b> affect <see cref="SecureClear"/>, which
    /// always wipes the full <see cref="Capacity"/> — so shrinking <see cref="Length"/> before
    /// disposal cannot be used to bypass secure clearing.
    /// </remarks>
    /// <exception cref="ArgumentOutOfRangeException">
    /// Thrown when the assigned value is negative or greater than <see cref="Capacity"/>.
    /// </exception>
    /// <exception cref="ObjectDisposedException">
    /// Thrown when the instance has already been disposed.
    /// </exception>
    public int Length
    {
        get
        {
            this.ThrowIfDisposed();
            return this.length;
        }
        set
        {
            this.ThrowIfDisposed();
            if (value < 0 || value > this.poolArray.Length)
            {
                throw new ArgumentOutOfRangeException(nameof(value), "Length must be non-negative and less than or equal to the capacity of the array.");
            }

            this.length = value;
        }
    }

    /// <summary>
    /// Gets or sets the element at the specified index.
    /// </summary>
    /// <param name="index">The zero-based index of the element to get or set.</param>
    /// <returns>The element at the specified index.</returns>
    /// <exception cref="ArgumentOutOfRangeException">
    /// Thrown when the index is less than zero or greater than or equal to <see cref="Length"/>.
    /// </exception>
    public T this[int index]
    {
        get
        {
            this.ThrowIfDisposed();
            if (index < 0 || index >= this.Length)
            {
                throw new ArgumentOutOfRangeException(nameof(index), "Index must be non-negative and less than the length of the array.");
            }

            return this.poolArray[index];
        }
        set
        {
            this.ThrowIfDisposed();
            if (index < 0 || index >= this.Length)
            {
                throw new ArgumentOutOfRangeException(nameof(index), "Index must be non-negative and less than the length of the array.");
            }

            this.poolArray[index] = value;
        }
    }

    /// <summary>
    /// Gets the capacity of the pinned byte array.
    /// </summary>
    public int Capacity
    {
        get
        {
            this.ThrowIfDisposed();
            return this.poolArray.Length;
        }
    }

    /// <summary>
    /// Gets the pinned byte array.
    /// </summary>
    public T[] PoolArray 
    {
        get
        {
            this.ThrowIfDisposed();
            return this.poolArray;
        }
    }

    /// <summary>
    /// Compares the current <see cref="PinnedPoolArray{T}"/> instance to another object using a specified comparer.
    /// </summary>
    /// <param name="other">
    /// The object to compare with the current instance. It must be another <see cref="PinnedPoolArray{T}"/>
    /// of the same length and type, or an <see cref="ArgumentException"/> will be thrown.
    /// </param>
    /// <param name="comparer">
    /// The <see cref="IComparer"/> implementation to use for comparing individual elements
    /// of the two arrays.
    /// </param>
    /// <returns>
    /// An integer indicating the relative order of the objects being compared:
    /// -1 if the current instance is less than the `other`.
    /// 0 if the current instance is equal to the `other`.
    /// 1 if the current instance is greater than the `other`.
    /// </returns>
    /// <exception cref="ArgumentException">
    /// Thrown if the `other` object is not a <see cref="PinnedPoolArray{T}"/>,
    /// or if the lengths of the arrays differ.
    /// </exception>
    /// <exception cref="ObjectDisposedException">
    /// Thrown when the instance has already been disposed.
    /// </exception>
    int IStructuralComparable.CompareTo(object other, IComparer comparer)
    {
        this.ThrowIfDisposed();
        if (other == null)
        {
            return 1;
        }

        if (other is not PinnedPoolArray<T> otherArray)
        {
            throw new ArgumentException($"Argument must be an Array, but was {other.GetType().Name}");
        }

        if (this.Length != otherArray.Length)
        {
            throw new ArgumentException($"Argument must be an Array of the same length, but was {otherArray.Length} instead of {this.Length}");
        }

        var index = 0;
        var result = 0;

        while (index < otherArray.Length && result == 0)
        {
            result = comparer.Compare(this[index], otherArray[index]);
            index++;
        }

        return result;
    }

    /// <summary>
    /// Determines whether the current instance is equal to another object based on the specified equality comparer.
    /// </summary>
    /// <param name="other">The object to compare to the current instance.</param>
    /// <param name="comparer">The equality comparer used to evaluate equality.</param>
    /// <returns>
    /// <see langword="true"/> if the current instance and the specified object are equal; otherwise, <see langword="false"/>
    /// </returns>
    /// <exception cref="ArgumentException">
    /// Thrown when the specified comparer is not an instance of a counted comparer.
    /// </exception>
    /// <exception cref="ArgumentOutOfRangeException">
    /// Thrown when the count specified by the comparer exceeds the length of one of the arrays.
    /// </exception>
    /// <exception cref="ObjectDisposedException">
    /// Thrown when the instance has already been disposed.
    /// </exception>
    public bool Equals(object other, IEqualityComparer comparer)
    {
        this.ThrowIfDisposed();
        if (ReferenceEquals(this, other))
        {
            return true;
        }

        int otherLength;
        if (other is not T[] otherArray)
        {
            if (other is not PinnedPoolArray<T> otherPinnedArray)
            {
                return false;
            }

            otherArray = otherPinnedArray.poolArray;
            otherLength = otherPinnedArray.Length;
        }
        else
        {
            otherLength = otherArray.Length;
        }

        if (comparer is not ICountedEqualityComparer<T> countedComparer)
        {
            throw new ArgumentException(
                $"A counted comparer is required. Use '{typeof(CountedEqualityComparer<T>).FullName}' " +
                "to specify the number of elements to compare.",
                nameof(comparer));
        }

        var count = countedComparer.Count;
        if (count > this.Length || count > otherLength)
        {
            throw new ArgumentOutOfRangeException(
                nameof(comparer),
                $"Count '{count}' exceeds one of the array lengths ({this.Length}, {otherLength}).");
        }

        for (int i = 0; i < count; i++)
        {
            if (!countedComparer.Equals(this.poolArray[i], otherArray[i]))
            {
                return false;
            }
        }

        return true;
    }

    /// <summary>
    /// Computes a hash code for the current instance by using the provided comparer,
    /// considering a specific number of elements defined by the comparer.
    /// </summary>
    /// <param name="comparer">
    /// An <see cref="IEqualityComparer"/> instance that specifies how to compute the hash
    /// and the number of elements to include in the hash computation. Must implement
    /// <see cref="ICountedEqualityComparer{T}"/>.
    /// </param>
    /// <returns>
    /// An <see cref="int"/> hash code calculated based on the specified number of array elements.
    /// </returns>
    /// <exception cref="ArgumentException">
    /// Thrown when the provided comparer is not an instance of <see cref="ICountedEqualityComparer{T}"/>.
    /// </exception>
    /// <exception cref="ArgumentOutOfRangeException">
    /// Thrown when the number of elements specified by the comparer exceeds the length of the array.
    /// </exception>
    /// <exception cref="ObjectDisposedException">
    /// Thrown when the instance has already been disposed.
    /// </exception>
    public int GetHashCode(IEqualityComparer comparer)
    {
        this.ThrowIfDisposed();
        if (comparer is not ICountedEqualityComparer<T> countedComparer)
        {
            throw new ArgumentException(
                $"A counted comparer is required. Use '{typeof(CountedEqualityComparer<T>).FullName}' " +
                "to specify the number of elements to hash.",
                nameof(comparer));
        }

        var count = countedComparer.Count;
        if (count > this.Length)
        {
            throw new ArgumentOutOfRangeException(
                nameof(countedComparer),
                $"Count '{count}' exceeds the array length ({this.Length}).");
        }

#if NET8_0_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        var hash = new HashCode();
        hash.Add(count);

        for (var i = 0; i < count; i++)
        {
            hash.Add(this.poolArray[i], countedComparer);
        }

        return hash.ToHashCode();
#else
        unchecked
        {
            int hash = 17;
            hash = hash * 31 + count;

            for (int i = 0; i < count; i++)
            {
                int elementHash = countedComparer.GetHashCode(this.poolArray[i]);
                hash = hash * 31 + elementHash;
            }

            return hash;
        }
#endif
    }

    /// <summary>
    /// Overwrites the entire rented backing buffer (full <see cref="Capacity"/>, not just
    /// <see cref="Length"/>) with multiple passes of different patterns, then zeros it, so that
    /// no secret data remains in pooled memory after the array is returned to the pool.
    /// </summary>
    /// <remarks>
    /// <para>
    /// 3-Pass Overwrite (DOD 5220.22-M) with patterns 0xFF → 0x00 → 0xAA, followed by a final
    /// zeroization pass. Clearing the full capacity — not just the logical length — is essential:
    /// callers may have written past <see cref="Length"/> via the <see cref="PoolArray"/> escape
    /// hatch, and the pool reuses backing buffers across tenants. Because of this, the value of
    /// <see cref="Length"/> at the time of this call has no effect on how many bytes are wiped.
    /// </para>
    /// <para>
    /// This method is mutually exclusive with <see cref="Dispose()"/>: any in-flight call is
    /// drained before the backing buffer is returned to the pool, and any call that races with
    /// (or follows) disposal observes the disposed state and throws.
    /// </para>
    /// </remarks>
    /// <exception cref="ObjectDisposedException">
    /// Thrown when the instance has already been disposed.
    /// </exception>
    [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
    public void SecureClear()
    {
        Interlocked.Increment(ref this.activeOperations);
        try
        {
            this.ThrowIfDisposed();
            this.SecureClearCore();
        }
        finally
        {
            Interlocked.Decrement(ref this.activeOperations);
        }
    }

    /// <summary>
    /// Performs the actual 3-pass + zeroization wipe of <see cref="poolArray"/>, without
    /// disposal or concurrency checks.
    /// </summary>
    /// <remarks>
    /// Only called from <see cref="SecureClear"/> (after the disposal/counter guard) and
    /// from <see cref="Dispose(bool)"/> (after the in-flight counter has been drained).
    /// Direct callers must ensure no other thread is accessing the buffer.
    /// </remarks>
    [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
    private void SecureClearCore()
    {
        if (this.poolArray.Length == 0)
        {
            return;
        }

#if NET8_0_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        var data = MemoryMarshal.AsBytes(this.poolArray.AsSpan());
        for (int pass = 0; pass < 3; pass++)
        {
            byte pattern = (byte)(pass == 0 ? 0xFF : pass == 1 ? 0x00 : 0xAA);
            for (int i = 0; i < data.Length; i++)
            {
                data[i] = pattern;
            }
        }

        CryptographicOperations.ZeroMemory(data);
#else
        LegacySecureClear(this.poolArrayHandle.AddrOfPinnedObject(), this.poolArray.Length * SizeOf());
#endif
    }
    
    /// <summary>
    /// Releases all resources used by the current instance of the <see cref="PinnedPoolArray{T}"/> class.
    /// </summary>
    public void Dispose()
    {
        this.Dispose(true);
        GC.SuppressFinalize(this);
    }

    /// <summary>
    /// Releases the resources used by the <see cref="PinnedPoolArray{T}"/> instance.
    /// </summary>
    /// <remarks>
    /// Atomically transitions the instance to the disposed state, then waits until all
    /// in-flight <see cref="SecureClear"/> callers have exited their critical section
    /// before returning the rented buffer to the pool. New <see cref="SecureClear"/>
    /// callers arriving after the flag is set throw <see cref="ObjectDisposedException"/>.
    /// </remarks>
    /// <param name="disposing">A boolean value indicating whether to release managed resources (true) or
    /// only unmanaged resources (false).</param>
    private void Dispose(bool disposing)
    {
        if (Interlocked.Exchange(ref this.disposed, 1) == 1)
        {
            return;
        }

        // Drain in-flight public SecureClear callers. Each such caller incremented
        // activeOperations before reading disposed; once they observe disposed == 1
        // they throw and decrement in the finally block. We must wait for that to
        // finish before returning the backing buffer to the pool — otherwise a
        // late-finishing SecureClear could write into a buffer already owned by
        // another pool tenant.
        SpinWait spin = default;
        while (Interlocked.CompareExchange(ref this.activeOperations, 0, 0) != 0)
        {
            spin.SpinOnce();
        }

        if (disposing)
        {
            // Release managed resources if any
        }

        if (this.poolArray is null)
        {
            return;
        }

        this.SecureClearCore();
        if (this.poolArrayHandle.IsAllocated)
        {
            this.poolArrayHandle.Free();
        }

        ArrayPool<T>.Shared.Return(this.poolArray);
    }

    /// <summary>
    /// Ensures that the current instance of <see cref="PinnedPoolArray{T}"/> has not been disposed.
    /// </summary>
    /// <exception cref="ObjectDisposedException">
    /// Thrown if the instance has already been disposed.
    /// </exception>
    private void ThrowIfDisposed()
    {
        if (Volatile.Read(ref this.disposed) != 1)
        {
            return;
        }

        throw new ObjectDisposedException(nameof(PinnedPoolArray<>));
    }

#if NETFRAMEWORK || NETSTANDARD2_0
    /// <summary>
    /// Determines the size, in bytes, of an object of type <typeparamref name="T"/>.
    /// </summary>
    /// <returns>The size, in bytes, of the type <typeparamref name="T"/>.
    /// This value is calculated using <see cref="System.Runtime.InteropServices.Marshal.SizeOf(Type)"/>.
    /// </returns>
    private static int SizeOf()
    {
        return Marshal.SizeOf(typeof(T));
    }

    /// <summary>
    /// Performs a secure memory clearing operation on the specified memory region using a legacy method.
    /// This operation overwrites the memory multiple times to ensure data is securely erased.
    /// </summary>
    /// <param name="pointer">
    /// A pointer to the starting address of the memory to be securely cleared.
    /// </param>
    /// <param name="byteLength">
    /// The length of the memory region, in bytes, to clear.
    /// </param>
    [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
    private static unsafe void LegacySecureClear(IntPtr pointer, int byteLength)
    {
        byte* bytePointer = (byte*)pointer;
        if (bytePointer != null)
        {
            for (int pass = 0; pass < 3; pass++)
            {
                byte pattern = pass switch
                {
                    0 => 0xFF,
                    1 => 0x00,
                    _ => 0xAA
                };
                for (int i = 0; i < byteLength; i++)
                {
                    Volatile.Write(ref bytePointer[i], pattern);
                }
            }

            for (int i = 0; i < byteLength; i++)
            {
                Volatile.Write(ref bytePointer[i], 0);
            }
        }

        Thread.MemoryBarrier();
    }
#endif
}