namespace SecretSharingDotNetTest.Cryptography.SecureArray;

using SecretSharingDotNet.Cryptography.SecureArray;
using Xunit;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Threading;

/// <summary>
/// Unit tests for <see cref="PinnedPoolArray{T}"/>: GC-pinned ArrayPool wrapper with secure
/// zero-out on dispose, structural equality / comparison, length-bounded indexer, and
/// disposed-state guards on every public surface.
/// </summary>
public class PinnedPoolArrayTest
{
    /// <summary>
    /// Tests that a freshly constructed <see cref="PinnedPoolArray{T}"/> reports the
    /// requested <see cref="PinnedPoolArray{T}.Length"/> and a <see cref="PinnedPoolArray{T}.Capacity"/>
    /// equal to the underlying pool array's length and at least as large as <c>Length</c>.
    /// </summary>
    [Fact]
    public void Constructor_ShouldAllocateArrayWithPinnedMemory()
    {
        // Arrange
        const int length = 50;

        // Act
        using var pinnedArray = new PinnedPoolArray<byte>(length);

        // Assert
        Assert.Equal(length, pinnedArray.Length);
        Assert.Equal(pinnedArray.Capacity, pinnedArray.PoolArray.Length);
        Assert.True(length <= pinnedArray.Capacity);
        Assert.True(length <= pinnedArray.PoolArray.Length);
    }

    /// <summary>
    /// Tests that the <see cref="PinnedPoolArray{T}.Length"/> setter rejects negative values
    /// and values exceeding <see cref="PinnedPoolArray{T}.Capacity"/> with
    /// <see cref="ArgumentOutOfRangeException"/>.
    /// </summary>
    [Fact]
    public void Length_Setter_ShouldThrowForInvalidLength()
    {
        // Arrange
        const int initialLength = 50;

        using var pinnedArray = new PinnedPoolArray<byte>(initialLength);

        // Act & Assert
        Assert.Throws<ArgumentOutOfRangeException>(() => pinnedArray.Length = -1);
        Assert.Throws<ArgumentOutOfRangeException>(() => pinnedArray.Length = 10000);
    }

    /// <summary>
    /// Tests that assigning a valid value to the <see cref="PinnedPoolArray{T}.Length"/>
    /// setter updates the logical length accordingly.
    /// </summary>
    [Fact]
    public void Length_Setter_ShouldUpdateLength()
    {
        // Arrange
        const int length = 512;

        using var pinnedArray = new PinnedPoolArray<byte>(length);

        // Act
        var pinnedArrayLength = pinnedArray.Length;
        pinnedArray.Length = 30;

        // Assert
        Assert.Equal(30, pinnedArray.Length);
        Assert.True(30 < pinnedArrayLength);
    }

    /// <summary>
    /// Tests that accessing <see cref="PinnedPoolArray{T}.PoolArray"/> after
    /// <see cref="IDisposable.Dispose"/> throws <see cref="ObjectDisposedException"/>.
    /// </summary>
    [Fact]
    public void PoolArray_ShouldThrowObjectDisposedException_WhenDisposed()
    {
        // Arrange
        var pinnedArray = new PinnedPoolArray<byte>(50);
        pinnedArray.Dispose();

        // Act & Assert
        Assert.Throws<ObjectDisposedException>(() => { _ = pinnedArray.PoolArray; });
    }

    /// <summary>
    /// Tests that accessing <see cref="PinnedPoolArray{T}.Capacity"/> after
    /// <see cref="IDisposable.Dispose"/> throws <see cref="ObjectDisposedException"/>.
    /// </summary>
    [Fact]
    public void Capacity_ShouldThrowObjectDisposedException_WhenDisposed()
    {
        // Arrange
        var pinnedArray = new PinnedPoolArray<byte>(50);
        pinnedArray.Dispose();

        // Act & Assert
        Assert.Throws<ObjectDisposedException>(() => { _ = pinnedArray.Capacity; });
    }

    /// <summary>
    /// Tests that <see cref="PinnedPoolArray{T}.SecureClear"/> zeroes every byte of the
    /// underlying pool array after the buffer has been filled with non-zero data.
    /// </summary>
    [Fact]
    public void SecureClear_ShouldClearArray()
    {
        // Arrange
        using var pinnedArray = new PinnedPoolArray<byte>(50);
        for (int i = 0; i < pinnedArray.Length; i++)
        {
            pinnedArray.PoolArray[i] = (byte)i;
        }

        // Act
        pinnedArray.SecureClear();

        // Assert
        foreach (byte value in pinnedArray.PoolArray)
        {
            Assert.Equal(0, value);
        }
    }

    /// <summary>
    /// Tests that <see cref="PinnedPoolArray{T}.SecureClear"/> clears the full
    /// <see cref="PinnedPoolArray{T}.Capacity"/>, not just <c>[0..Length)</c> — bytes
    /// written through the <see cref="PinnedPoolArray{T}.PoolArray"/> escape hatch and
    /// later hidden by shrinking <c>Length</c> must still be wiped.
    /// </summary>
    [Fact]
    public void SecureClear_ClearsBytesBeyondLogicalLength()
    {
        // Arrange — write to every Capacity byte via the PoolArray escape hatch.
        var pinnedArray = new PinnedPoolArray<byte>(8);
        for (int i = 0; i < pinnedArray.Capacity; i++)
        {
            pinnedArray.PoolArray[i] = 0x55;
        }

        // Shrink the logical length so that [Length..Capacity) is "outside the view".
        pinnedArray.Length = 4;

        // Act
        pinnedArray.SecureClear();

        // Assert — the full capacity, not just [0..Length), must be zero.
        for (int i = 0; i < pinnedArray.Capacity; i++)
        {
            Assert.Equal(0, pinnedArray.PoolArray[i]);
        }

        pinnedArray.Dispose();
    }

    /// <summary>
    /// Regression guard that a caller setting <see cref="PinnedPoolArray{T}.Length"/> to
    /// zero before disposal cannot bypass the secure-clear pass —
    /// <see cref="PinnedPoolArray{T}.SecureClear"/> must still zero the full capacity.
    /// </summary>
    [Fact]
    public void SecureClear_AfterLengthSetToZero_StillClearsCapacity()
    {
        // Arrange — regression guard: a caller setting Length = 0 before disposal
        // must not be able to bypass the secure-clear pass.
        var pinnedArray = new PinnedPoolArray<byte>(16);
        for (int i = 0; i < pinnedArray.Length; i++)
        {
            pinnedArray.PoolArray[i] = 0x42;
        }

        pinnedArray.Length = 0;

        // Act
        pinnedArray.SecureClear();

        // Assert — every Capacity byte must be zero despite Length == 0.
        for (int i = 0; i < pinnedArray.Capacity; i++)
        {
            Assert.Equal(0, pinnedArray.PoolArray[i]);
        }

        pinnedArray.Dispose();
    }

    /// <summary>
    /// Tests that <see cref="IDisposable.Dispose"/> releases the pinned buffer such that
    /// subsequent property accesses throw <see cref="ObjectDisposedException"/>.
    /// </summary>
    [Fact]
    public void Dispose_ShouldReleasePinnedMemory()
    {
        // Arrange
        var pinnedArray = new PinnedPoolArray<byte>(50);

        // Act
        pinnedArray.Dispose();

        // Assert: Accessing properties after Dispose should throw
        Assert.Throws<ObjectDisposedException>(() => { _ = pinnedArray.PoolArray; });
        Assert.Throws<ObjectDisposedException>(() => { _ = pinnedArray.Capacity; });
    }

    /// <summary>
    /// Tests that <see cref="IDisposable.Dispose"/> is idempotent — calling it twice
    /// does not throw.
    /// </summary>
    [Fact]
    public void Dispose_ShouldBeIdempotent()
    {
        // Arrange
        var pinnedArray = new PinnedPoolArray<byte>(50);

        // Act: Calling Dispose multiple times should not throw exceptions
        var exception1 = Record.Exception(pinnedArray.Dispose);
        var exception2 = Record.Exception(pinnedArray.Dispose);

        // Assert
        Assert.Null(exception1);
        Assert.Null(exception2);
    }

    /// <summary>
    /// Tests that an unreachable <see cref="PinnedPoolArray{T}"/> is collected by the GC —
    /// the finalizer is wired correctly and does not keep the instance alive.
    /// </summary>
    [Fact]
    public void Finalizer_ShouldCallDispose()
    {
        // Arrange
        WeakReference weakRef;

        // Act
        CreatePinnedPoolArray();
        GC.Collect();
        GC.WaitForPendingFinalizers();

        // Assert
        Assert.False(weakRef.IsAlive);
        return;

        void CreatePinnedPoolArray()
        {
            var pinnedArray = new PinnedPoolArray<byte>(50);
            weakRef = new WeakReference(pinnedArray);
        }
    }

    /// <summary>
    /// Q1 regression guard: a <see cref="PinnedPoolArray{T}.SecureClear"/> call that
    /// arrives after <see cref="IDisposable.Dispose"/> must NOT touch the pool-resident
    /// buffer (which may already be owned by another tenant) — it must throw
    /// <see cref="ObjectDisposedException"/> instead.
    /// </summary>
    [Fact]
    public void SecureClear_AfterDispose_ThrowsObjectDisposedException()
    {
        // Arrange
        // Q1 regression guard: a SecureClear call that arrives after Dispose
        // must NOT touch the pool-resident buffer (which may already be owned by
        // another tenant). It must throw instead.
        var pinnedArray = new PinnedPoolArray<byte>(50);
        pinnedArray.Dispose();

        // Act & Assert
        Assert.Throws<ObjectDisposedException>(pinnedArray.SecureClear);
    }

    /// <summary>
    /// Q2 regression smoke-test: hammers <see cref="PinnedPoolArray{T}.SecureClear"/> from
    /// one thread while <see cref="IDisposable.Dispose"/> runs on another. Acceptable
    /// outcomes per iteration are clean completion or an <see cref="ObjectDisposedException"/>
    /// in the clearer; anything else (AccessViolation, pool double-return) fails.
    /// </summary>
    [Fact]
    public void Dispose_DrainsInFlightSecureClear()
    {
        // Arrange
        // Q2 regression smoke-test: hammer SecureClear from one thread while
        // disposing from another. Acceptable outcomes per iteration: clean
        // completion, or ObjectDisposedException from the SecureClear thread.
        // Anything else (AccessViolation, pool double-return, etc.) fails.

        // Act & Assert
        for (int iteration = 0; iteration < 100; iteration++)
        {
            var pinnedArray = new PinnedPoolArray<byte>(1024);
            Exception observedFromClearer = null;

            var clearer = new Thread(() =>
            {
                try
                {
                    for (int i = 0; i < 50; i++)
                    {
                        pinnedArray.SecureClear();
                    }
                }
                catch (ObjectDisposedException)
                {
                    // Expected once Dispose has won the race.
                }
                catch (Exception ex)
                {
                    observedFromClearer = ex;
                }
            });

            clearer.Start();
            Thread.Yield();
            pinnedArray.Dispose();
            clearer.Join();

            Assert.Null(observedFromClearer);
        }
    }

    /// <summary>
    /// Tests that reading <see cref="PinnedPoolArray{T}.Length"/> after dispose throws
    /// <see cref="ObjectDisposedException"/>.
    /// </summary>
    [Fact]
    public void Length_Getter_AfterDispose_ThrowsObjectDisposedException()
    {
        // Arrange
        var arr = new PinnedPoolArray<byte>(50);
        arr.Dispose();

        // Act & Assert
        Assert.Throws<ObjectDisposedException>(() => { _ = arr.Length; });
    }

    /// <summary>
    /// Tests that assigning to <see cref="PinnedPoolArray{T}.Length"/> after dispose
    /// throws <see cref="ObjectDisposedException"/>.
    /// </summary>
    [Fact]
    public void Length_Setter_AfterDispose_ThrowsObjectDisposedException()
    {
        // Arrange
        var arr = new PinnedPoolArray<byte>(50);
        arr.Dispose();

        // Act & Assert
        Assert.Throws<ObjectDisposedException>(() => { arr.Length = 10; });
    }

    /// <summary>
    /// Tests that <c>Equals</c> with a <see cref="CountedEqualityComparer{T}"/> on a
    /// disposed receiver throws <see cref="ObjectDisposedException"/>.
    /// </summary>
    [Fact]
    public void Equals_WithCountedComparer_AfterDispose_ThrowsObjectDisposedException()
    {
        // Arrange
        var arr = new PinnedPoolArray<byte>(50);
        using var other = new PinnedPoolArray<byte>(50);
        arr.Dispose();

        // Act & Assert
        Assert.Throws<ObjectDisposedException>(
            () => arr.Equals(other, new CountedEqualityComparer<byte>(50)));
    }

    /// <summary>
    /// Tests that <c>GetHashCode</c> with a <see cref="CountedEqualityComparer{T}"/> on a
    /// disposed receiver throws <see cref="ObjectDisposedException"/>.
    /// </summary>
    [Fact]
    public void GetHashCode_WithCountedComparer_AfterDispose_ThrowsObjectDisposedException()
    {
        // Arrange
        var arr = new PinnedPoolArray<byte>(50);
        arr.Dispose();

        // Act & Assert
        Assert.Throws<ObjectDisposedException>(
            () => arr.GetHashCode(new CountedEqualityComparer<byte>(50)));
    }

    /// <summary>
    /// Tests that <see cref="IStructuralComparable.CompareTo"/> on a disposed receiver
    /// throws <see cref="ObjectDisposedException"/>.
    /// </summary>
    [Fact]
    public void StructuralCompareTo_AfterDispose_ThrowsObjectDisposedException()
    {
        // Arrange
        var arr = new PinnedPoolArray<byte>(50);
        using var other = new PinnedPoolArray<byte>(50);
        arr.Dispose();

        // Act & Assert
        Assert.Throws<ObjectDisposedException>(
            () => ((IStructuralComparable)arr).CompareTo(other, Comparer<object>.Default));
    }

    /// <summary>
    /// Tests that <see cref="IStructuralComparable.CompareTo"/> against a disposed
    /// <paramref name="other"/> argument throws <see cref="ObjectDisposedException"/>.
    /// </summary>
    [Fact]
    public void StructuralCompareTo_OtherDisposed_ThrowsObjectDisposedException()
    {
        // Arrange
        using var arr = new PinnedPoolArray<byte>(50);
        var other = new PinnedPoolArray<byte>(50);
        other.Dispose();

        // Act & Assert
        Assert.Throws<ObjectDisposedException>(
            () => ((IStructuralComparable)arr).CompareTo(other, Comparer<object>.Default));
    }

    /// <summary>
    /// Tests that <see cref="IStructuralComparable.CompareTo"/> rejects a
    /// <see langword="null"/> comparer with <see cref="ArgumentNullException"/>.
    /// </summary>
    [Fact]
    public void StructuralCompareTo_NullComparer_ThrowsArgumentNullException()
    {
        // Arrange
        using var arr = new PinnedPoolArray<byte>(50);
        using var other = new PinnedPoolArray<byte>(50);

        // Act & Assert
        Assert.Throws<ArgumentNullException>(
            () => ((IStructuralComparable)arr).CompareTo(other, null));
    }

    /// <summary>
    /// Tests that argument validation precedes the
    /// <see cref="IStructuralComparable.CompareTo"/> "null is less than anything"
    /// shortcut — a null <c>comparer</c> raises <see cref="ArgumentNullException"/>
    /// even when <c>other</c> is also null.
    /// </summary>
    [Fact]
    public void StructuralCompareTo_NullOther_NullComparer_PrefersArgumentNullException()
    {
        // Arrange
        using var arr = new PinnedPoolArray<byte>(50);

        // Act & Assert
        // Argument validation precedes the IStructuralComparable.CompareTo
        // "null is less than anything" shortcut.
        Assert.Throws<ArgumentNullException>(
            () => ((IStructuralComparable)arr).CompareTo(null, null));
    }

    /// <summary>
    /// Tests that <c>Equals(other, comparer)</c> rejects a <see langword="null"/>
    /// comparer with <see cref="ArgumentNullException"/>.
    /// </summary>
    [Fact]
    public void Equals_NullComparer_ThrowsArgumentNullException()
    {
        // Arrange
        using var arr = new PinnedPoolArray<byte>(50);
        using var other = new PinnedPoolArray<byte>(50);

        // Act & Assert
        Assert.Throws<ArgumentNullException>(
            () => arr.Equals(other, null));
    }

    /// <summary>
    /// Tests that <c>Equals(other, comparer)</c> against a disposed
    /// <paramref name="other"/> throws <see cref="ObjectDisposedException"/>.
    /// </summary>
    [Fact]
    public void Equals_OtherPinnedArrayDisposed_ThrowsObjectDisposedException()
    {
        // Arrange
        using var arr = new PinnedPoolArray<byte>(50);
        var other = new PinnedPoolArray<byte>(50);
        other.Dispose();

        // Act & Assert
        Assert.Throws<ObjectDisposedException>(
            () => arr.Equals(other, new CountedEqualityComparer<byte>(50)));
    }

    /// <summary>
    /// Tests that <c>GetHashCode(comparer)</c> rejects a <see langword="null"/>
    /// comparer with <see cref="ArgumentNullException"/>.
    /// </summary>
    [Fact]
    public void GetHashCode_NullComparer_ThrowsArgumentNullException()
    {
        // Arrange
        using var arr = new PinnedPoolArray<byte>(50);

        // Act & Assert
        Assert.Throws<ArgumentNullException>(
            () => arr.GetHashCode(null));
    }

    /// <summary>
    /// Tests that two pinned arrays holding the same byte sequence produce the same
    /// <c>GetHashCode</c> result under a <see cref="CountedEqualityComparer{T}"/> with
    /// matching count — the <c>Equals</c>/<c>GetHashCode</c> contract.
    /// </summary>
    [Fact]
    public void GetHashCode_EqualArraysWithSameComparer_ProduceSameHash()
    {
        // Arrange
        using var arr1 = new PinnedPoolArray<byte>(4);
        using var arr2 = new PinnedPoolArray<byte>(4);
        for (int i = 0; i < 4; i++)
        {
            arr1[i] = (byte)(i + 10);
            arr2[i] = (byte)(i + 10);
        }

        // Act
        var hash1 = arr1.GetHashCode(new CountedEqualityComparer<byte>(4));
        var hash2 = arr2.GetHashCode(new CountedEqualityComparer<byte>(4));

        // Assert
        Assert.Equal(hash1, hash2);
    }

    /// <summary>
    /// Tests that two pinned arrays differing in a single byte produce different
    /// <c>GetHashCode</c> results — minimum quality bound on the hash function.
    /// </summary>
    [Fact]
    public void GetHashCode_DifferentBytes_ProduceDifferentHash()
    {
        // Arrange
        using var arr1 = new PinnedPoolArray<byte>(4);
        using var arr2 = new PinnedPoolArray<byte>(4);
        for (int i = 0; i < 4; i++)
        {
            arr1[i] = (byte)(i + 10);
            arr2[i] = (byte)(i + 10);
        }

        arr2[2] = 0xFF;

        // Act
        var hash1 = arr1.GetHashCode(new CountedEqualityComparer<byte>(4));
        var hash2 = arr2.GetHashCode(new CountedEqualityComparer<byte>(4));

        // Assert
        Assert.NotEqual(hash1, hash2);
    }

    /// <summary>
    /// Tests that <c>GetHashCode(comparer)</c> rejects any
    /// <see cref="IEqualityComparer{T}"/> that is not a
    /// <see cref="CountedEqualityComparer{T}"/> with <see cref="ArgumentException"/>.
    /// </summary>
    [Fact]
    public void GetHashCode_ComparerNotCounted_ThrowsArgumentException()
    {
        // Arrange
        using var arr = new PinnedPoolArray<byte>(4);

        // Act & Assert
        Assert.Throws<ArgumentException>(
            () => arr.GetHashCode(EqualityComparer<byte>.Default));
    }

    /// <summary>
    /// Tests that <c>GetHashCode(comparer)</c> throws
    /// <see cref="ArgumentOutOfRangeException"/> when the
    /// <see cref="CountedEqualityComparer{T}"/>'s count exceeds the receiver's
    /// <see cref="PinnedPoolArray{T}.Length"/>.
    /// </summary>
    [Fact]
    public void GetHashCode_CountExceedsLength_ThrowsArgumentOutOfRangeException()
    {
        // Arrange
        using var arr = new PinnedPoolArray<byte>(4);

        // Act & Assert
        Assert.Throws<ArgumentOutOfRangeException>(
            () => arr.GetHashCode(new CountedEqualityComparer<byte>(8)));
    }

    /// <summary>
    /// Tests that <c>Equals</c> returns <see langword="true"/> for a reference-equal
    /// receiver/argument pair — reflexive equality.
    /// </summary>
    [Fact]
    public void Equals_ReferenceEqualsSelf_ReturnsTrue()
    {
        // Arrange
        using var arr = new PinnedPoolArray<byte>(4);

        // Act
        var result = arr.Equals(arr, new CountedEqualityComparer<byte>(4));

        // Assert
        Assert.True(result);
    }

    /// <summary>
    /// Tests that <c>Equals(raw, comparer)</c> returns <see langword="true"/> when the
    /// <see cref="PinnedPoolArray{T}"/> and a raw <see cref="T:T[]"/> hold the same
    /// byte sequence.
    /// </summary>
    [Fact]
    public void Equals_OtherIsRawArrayWithMatchingBytes_ReturnsTrue()
    {
        // Arrange
        using var arr = new PinnedPoolArray<byte>(4);
        for (int i = 0; i < 4; i++)
        {
            arr[i] = (byte)(i + 1);
        }

        var rawOther = new byte[] { 1, 2, 3, 4 };

        // Act
        var result = arr.Equals(rawOther, new CountedEqualityComparer<byte>(4));

        // Assert
        Assert.True(result);
    }

    /// <summary>
    /// Tests that <c>Equals(other, comparer)</c> returns <see langword="true"/> for two
    /// <see cref="PinnedPoolArray{T}"/> instances holding the same byte sequence.
    /// </summary>
    [Fact]
    public void Equals_OtherIsPinnedPoolArrayWithMatchingBytes_ReturnsTrue()
    {
        // Arrange
        using var arr = new PinnedPoolArray<byte>(4);
        using var other = new PinnedPoolArray<byte>(4);
        for (int i = 0; i < 4; i++)
        {
            arr[i] = (byte)(i + 1);
            other[i] = (byte)(i + 1);
        }

        // Act
        var result = arr.Equals(other, new CountedEqualityComparer<byte>(4));

        // Assert
        Assert.True(result);
    }

    /// <summary>
    /// Tests that <c>Equals(other, comparer)</c> returns <see langword="false"/> when the
    /// two <see cref="PinnedPoolArray{T}"/> instances differ in a single byte.
    /// </summary>
    [Fact]
    public void Equals_OtherIsPinnedPoolArrayWithDifferingByte_ReturnsFalse()
    {
        // Arrange
        using var arr = new PinnedPoolArray<byte>(4);
        using var other = new PinnedPoolArray<byte>(4);
        for (int i = 0; i < 4; i++)
        {
            arr[i] = (byte)(i + 1);
            other[i] = (byte)(i + 1);
        }

        other[2] = 99;

        // Act
        var result = arr.Equals(other, new CountedEqualityComparer<byte>(4));

        // Assert
        Assert.False(result);
    }

    /// <summary>
    /// Tests that <c>Equals(other, comparer)</c> returns <see langword="false"/> when
    /// <paramref name="other"/> is neither a raw array nor a
    /// <see cref="PinnedPoolArray{T}"/>.
    /// </summary>
    [Fact]
    public void Equals_OtherIsUnsupportedType_ReturnsFalse()
    {
        // Arrange
        using var arr = new PinnedPoolArray<byte>(4);

        // Act
        var result = arr.Equals("not an array", new CountedEqualityComparer<byte>(4));

        // Assert
        Assert.False(result);
    }

    /// <summary>
    /// Tests that <c>Equals(other, comparer)</c> rejects any
    /// <see cref="IEqualityComparer{T}"/> that is not a
    /// <see cref="CountedEqualityComparer{T}"/> with <see cref="ArgumentException"/>.
    /// </summary>
    [Fact]
    public void Equals_ComparerNotCounted_ThrowsArgumentException()
    {
        // Arrange
        using var arr = new PinnedPoolArray<byte>(4);
        using var other = new PinnedPoolArray<byte>(4);

        // Act & Assert
        Assert.Throws<ArgumentException>(
            () => arr.Equals(other, EqualityComparer<byte>.Default));
    }

    /// <summary>
    /// Tests that <c>Equals(other, comparer)</c> throws
    /// <see cref="ArgumentOutOfRangeException"/> when the
    /// <see cref="CountedEqualityComparer{T}"/>'s count exceeds the receiver's
    /// <see cref="PinnedPoolArray{T}.Length"/>.
    /// </summary>
    [Fact]
    public void Equals_CountExceedsLength_ThrowsArgumentOutOfRangeException()
    {
        // Arrange
        using var arr = new PinnedPoolArray<byte>(4);
        using var other = new PinnedPoolArray<byte>(4);

        // Act & Assert
        Assert.Throws<ArgumentOutOfRangeException>(
            () => arr.Equals(other, new CountedEqualityComparer<byte>(8)));
    }

    /// <summary>
    /// Tests that <see cref="IStructuralComparable.CompareTo"/> returns zero for two
    /// <see cref="PinnedPoolArray{T}"/> instances holding identical byte sequences.
    /// </summary>
    [Fact]
    public void StructuralCompareTo_EqualArrays_ReturnsZero()
    {
        // Arrange
        using var arr = new PinnedPoolArray<byte>(4);
        using var other = new PinnedPoolArray<byte>(4);
        for (int i = 0; i < 4; i++)
        {
            arr[i] = (byte)i;
            other[i] = (byte)i;
        }

        // Act
        var result = ((IStructuralComparable)arr).CompareTo(other, Comparer<object>.Default);

        // Assert
        Assert.Equal(0, result);
    }

    /// <summary>
    /// Tests that <see cref="IStructuralComparable.CompareTo"/> returns a negative value
    /// when the receiver is lexicographically less than <paramref name="other"/>.
    /// </summary>
    [Fact]
    public void StructuralCompareTo_ThisLessThanOther_ReturnsNegative()
    {
        // Arrange
        using var arr = new PinnedPoolArray<byte>(4);
        using var other = new PinnedPoolArray<byte>(4);
        arr[0] = 1;
        arr[1] = 2;
        other[0] = 1;
        other[1] = 3;

        // Act
        var result = ((IStructuralComparable)arr).CompareTo(other, Comparer<object>.Default);

        // Assert
        Assert.True(result < 0);
    }

    /// <summary>
    /// Tests that <see cref="IStructuralComparable.CompareTo"/> returns a positive value
    /// when the receiver is lexicographically greater than <paramref name="other"/>.
    /// </summary>
    [Fact]
    public void StructuralCompareTo_ThisGreaterThanOther_ReturnsPositive()
    {
        // Arrange
        using var arr = new PinnedPoolArray<byte>(4);
        using var other = new PinnedPoolArray<byte>(4);
        arr[0] = 5;
        other[0] = 1;

        // Act
        var result = ((IStructuralComparable)arr).CompareTo(other, Comparer<object>.Default);

        // Assert
        Assert.True(result > 0);
    }

    /// <summary>
    /// Tests that <see cref="IStructuralComparable.CompareTo"/> with a non-null comparer
    /// and a <see langword="null"/> <paramref name="other"/> returns <c>1</c> —
    /// "null is less than anything" convention.
    /// </summary>
    [Fact]
    public void StructuralCompareTo_NullOther_ReturnsOne()
    {
        // Arrange
        using var arr = new PinnedPoolArray<byte>(4);

        // Act
        var result = ((IStructuralComparable)arr).CompareTo(null, Comparer<object>.Default);

        // Assert
        Assert.Equal(1, result);
    }

    /// <summary>
    /// Tests that <see cref="IStructuralComparable.CompareTo"/> throws
    /// <see cref="ArgumentException"/> when <paramref name="other"/> is not a
    /// <see cref="PinnedPoolArray{T}"/> — a raw array argument is not supported.
    /// </summary>
    [Fact]
    public void StructuralCompareTo_OtherNotPinnedPoolArray_ThrowsArgumentException()
    {
        // Arrange
        using var arr = new PinnedPoolArray<byte>(4);

        // Act & Assert
        Assert.Throws<ArgumentException>(
            () => ((IStructuralComparable)arr).CompareTo(new byte[] { 1, 2, 3, 4 }, Comparer<object>.Default));
    }

    /// <summary>
    /// Tests that <see cref="IStructuralComparable.CompareTo"/> throws
    /// <see cref="ArgumentException"/> when the receiver and <paramref name="other"/>
    /// have different <see cref="PinnedPoolArray{T}.Length"/>s.
    /// </summary>
    [Fact]
    public void StructuralCompareTo_LengthMismatch_ThrowsArgumentException()
    {
        // Arrange
        using var arr = new PinnedPoolArray<byte>(4);
        using var other = new PinnedPoolArray<byte>(8);

        // Act & Assert
        Assert.Throws<ArgumentException>(
            () => ((IStructuralComparable)arr).CompareTo(other, Comparer<object>.Default));
    }

    /// <summary>
    /// Tests that the indexer getter returns the byte previously written via the
    /// <see cref="PinnedPoolArray{T}.PoolArray"/> escape hatch at the same index.
    /// </summary>
    [Fact]
    public void Indexer_Get_ValidIndex_ReturnsStoredValue()
    {
        // Arrange
        using var arr = new PinnedPoolArray<byte>(8);
        arr.PoolArray[3] = 0x42;

        // Act & Assert
        Assert.Equal(0x42, arr[3]);
    }

    /// <summary>
    /// Tests that the indexer getter rejects a negative index with
    /// <see cref="ArgumentOutOfRangeException"/>.
    /// </summary>
    [Fact]
    public void Indexer_Get_NegativeIndex_ThrowsArgumentOutOfRangeException()
    {
        // Arrange
        using var arr = new PinnedPoolArray<byte>(8);

        // Act & Assert
        Assert.Throws<ArgumentOutOfRangeException>(() => arr[-1]);
    }

    /// <summary>
    /// Tests that the indexer getter rejects an index equal to or beyond
    /// <see cref="PinnedPoolArray{T}.Length"/> with
    /// <see cref="ArgumentOutOfRangeException"/>.
    /// </summary>
    [Fact]
    public void Indexer_Get_IndexAtOrBeyondLength_ThrowsArgumentOutOfRangeException()
    {
        // Arrange
        using var arr = new PinnedPoolArray<byte>(8);

        // Act & Assert
        Assert.Throws<ArgumentOutOfRangeException>(() => arr[8]);
        Assert.Throws<ArgumentOutOfRangeException>(() => arr[100]);
    }

    /// <summary>
    /// Tests that the indexer getter on a disposed receiver throws
    /// <see cref="ObjectDisposedException"/>.
    /// </summary>
    [Fact]
    public void Indexer_Get_AfterDispose_ThrowsObjectDisposedException()
    {
        // Arrange
        var arr = new PinnedPoolArray<byte>(8);
        arr.Dispose();

        // Act & Assert
        Assert.Throws<ObjectDisposedException>(() => arr[0]);
    }

    /// <summary>
    /// Tests that the indexer setter writes the value at the requested index, observable
    /// through the <see cref="PinnedPoolArray{T}.PoolArray"/> escape hatch.
    /// </summary>
    [Fact]
    public void Indexer_Set_ValidIndex_StoresValue()
    {
        // Arrange
        using var arr = new PinnedPoolArray<byte>(8);

        // Act
        arr[3] = 0x42;

        // Assert
        Assert.Equal((byte)0x42, arr.PoolArray[3]);
    }

    /// <summary>
    /// Tests that the indexer setter rejects a negative index with
    /// <see cref="ArgumentOutOfRangeException"/>.
    /// </summary>
    [Fact]
    public void Indexer_Set_NegativeIndex_ThrowsArgumentOutOfRangeException()
    {
        // Arrange
        using var arr = new PinnedPoolArray<byte>(8);

        // Act & Assert
        Assert.Throws<ArgumentOutOfRangeException>(() => arr[-1] = 0);
    }

    /// <summary>
    /// Tests that the indexer setter rejects an index equal to or beyond
    /// <see cref="PinnedPoolArray{T}.Length"/> with
    /// <see cref="ArgumentOutOfRangeException"/>.
    /// </summary>
    [Fact]
    public void Indexer_Set_IndexAtOrBeyondLength_ThrowsArgumentOutOfRangeException()
    {
        // Arrange
        using var arr = new PinnedPoolArray<byte>(8);

        // Act & Assert
        Assert.Throws<ArgumentOutOfRangeException>(() => arr[8] = 0);
        Assert.Throws<ArgumentOutOfRangeException>(() => arr[100] = 0);
    }

    /// <summary>
    /// Tests that the indexer setter on a disposed receiver throws
    /// <see cref="ObjectDisposedException"/>.
    /// </summary>
    [Fact]
    public void Indexer_Set_AfterDispose_ThrowsObjectDisposedException()
    {
        // Arrange
        var arr = new PinnedPoolArray<byte>(8);
        arr.Dispose();

        // Act & Assert
        Assert.Throws<ObjectDisposedException>(() => arr[0] = 1);
    }

    /// <summary>
    /// Tests that after shrinking <see cref="PinnedPoolArray{T}.Length"/>, indices in
    /// <c>[Length..Capacity)</c> throw <see cref="ArgumentOutOfRangeException"/> for both
    /// getter and setter — the <see cref="PinnedPoolArray{T}.PoolArray"/> escape hatch is
    /// the only way to touch those bytes.
    /// </summary>
    [Fact]
    public void Indexer_RespectsLengthNotCapacity()
    {
        // Arrange
        // After shrinking Length, indices in [Length..Capacity) must throw — the
        // PoolArray escape hatch is the only way to touch those bytes.
        using var arr = new PinnedPoolArray<byte>(16);
        arr.Length = 4;

        // Act & Assert
        Assert.Throws<ArgumentOutOfRangeException>(() => arr[4]);
        Assert.Throws<ArgumentOutOfRangeException>(() => arr[4] = 1);
    }

    /// <summary>
    /// Tests that concurrent <see cref="IDisposable.Dispose"/> calls from two threads do
    /// not return the same array to the pool twice (ArrayPool surfaces double-return via
    /// <see cref="InvalidOperationException"/> on some TFMs).
    /// </summary>
    [Fact]
    public void Dispose_TwiceFromMultipleThreads_DoesNotDoubleFree()
    {
        // Arrange
        // Concurrent Dispose calls must not return the same array to the pool twice.
        // ArrayPool surfaces double-return via InvalidOperationException on some TFMs.

        // Act & Assert
        for (int iteration = 0; iteration < 50; iteration++)
        {
            var pinnedArray = new PinnedPoolArray<byte>(64);

            Exception ex1 = null;
            Exception ex2 = null;
            var t1 = new Thread(() =>
            {
                try { pinnedArray.Dispose(); }
                catch (Exception ex) { ex1 = ex; }
            });
            var t2 = new Thread(() =>
            {
                try { pinnedArray.Dispose(); }
                catch (Exception ex) { ex2 = ex; }
            });

            t1.Start();
            t2.Start();
            t1.Join();
            t2.Join();

            Assert.Null(ex1);
            Assert.Null(ex2);
        }
    }
}
