namespace SecretSharingDotNet.Cryptography;

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
/// The type of data stored in the array. Must be a value type.
/// </typeparam>
public sealed class PinnedPoolArray<T> : IStructuralComparable, IDisposable where T : struct
{
    /// <summary>
    /// Indicates whether the current instance has been disposed.
    /// </summary>
    private int disposed;

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
    /// Gets or sets the length of the pinned byte array.
    /// </summary>
    public int Length
    {
        get => this.length;
        set
        {
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

    int IStructuralComparable.CompareTo(object other, IComparer comparer)
    {
        if (other == null)
        {
            return 1;
        }
        
        if (other is not PinnedPoolArray<T> otherArray)
        {
            throw new ArgumentException($"Argument must be an Array, but was {other?.GetType().Name ?? "null"}");
        }

        if (this.Length != otherArray.Length)
        {
            throw new ArgumentException($"Argument must be an Array of the same length, but was {otherArray.Length} instead of {this.Length}");
        }

        int i = 0;
        int c = 0;

        while (i < otherArray.Length && c == 0)
        {
            c = comparer.Compare(this[i], otherArray[i]);
            i++;
        }

        return c;
    }
    
    /// <summary>
    /// Overwrites the contents of the specified byte array with multiple passes of different patterns
    /// to securely clear its data, ensuring sensitive information is not left in memory.
    /// </summary>
    /// <remarks>3-Pass Overwrite (DOD 5220.22-M)</remarks>
    [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
    public void SecureClear()
    {
        if (this.poolArray is null || this.poolArray.Length == 0)
        {
            return;
        }
        
#if NET8_0_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        var data = MemoryMarshal.AsBytes(this.poolArray.AsSpan(0, this.Length));
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
    /// <param name="disposing">A boolean value indicating whether to release managed resources (true) or
    /// only unmanaged resources (false).</param>
    private void Dispose(bool disposing)
    {
        if (Interlocked.Exchange(ref this.disposed, 1) == 1)
        {
            return;
        }

        if (disposing)
        {
            // Release managed resources if any
        }

        if (this.poolArray is null)
        {
            return;
        }

        this.SecureClear();
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