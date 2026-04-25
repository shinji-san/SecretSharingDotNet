namespace SecretSharingDotNetTest.Cryptography;

using SecretSharingDotNet.Cryptography.SecureArray;
using Xunit;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Threading;

public class PinnedPoolArrayTest
{
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

    [Fact]
    public void PoolArray_ShouldThrowObjectDisposedException_WhenDisposed()
    {
        // Arrange
        var pinnedArray = new PinnedPoolArray<byte>(50);
        pinnedArray.Dispose();

        // Act & Assert
        Assert.Throws<ObjectDisposedException>(() => { _ = pinnedArray.PoolArray; });
    }

    [Fact]
    public void Capacity_ShouldThrowObjectDisposedException_WhenDisposed()
    {
        // Arrange
        var pinnedArray = new PinnedPoolArray<byte>(50);
        pinnedArray.Dispose();

        // Act & Assert
        Assert.Throws<ObjectDisposedException>(() => { _ = pinnedArray.Capacity; });
    }

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

    [Fact]
    public void SecureClear_AfterDispose_ThrowsObjectDisposedException()
    {
        // Q1 regression guard: a SecureClear call that arrives after Dispose
        // must NOT touch the pool-resident buffer (which may already be owned by
        // another tenant). It must throw instead.
        var pinnedArray = new PinnedPoolArray<byte>(50);
        pinnedArray.Dispose();

        Assert.Throws<ObjectDisposedException>(() => pinnedArray.SecureClear());
    }

    [Fact]
    public void Dispose_DrainsInFlightSecureClear()
    {
        // Q2 regression smoke-test: hammer SecureClear from one thread while
        // disposing from another. Acceptable outcomes per iteration: clean
        // completion, or ObjectDisposedException from the SecureClear thread.
        // Anything else (AccessViolation, pool double-return, etc.) fails.
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

    [Fact]
    public void Length_Getter_AfterDispose_ThrowsObjectDisposedException()
    {
        var arr = new PinnedPoolArray<byte>(50);
        arr.Dispose();

        Assert.Throws<ObjectDisposedException>(() => { _ = arr.Length; });
    }

    [Fact]
    public void Length_Setter_AfterDispose_ThrowsObjectDisposedException()
    {
        var arr = new PinnedPoolArray<byte>(50);
        arr.Dispose();

        Assert.Throws<ObjectDisposedException>(() => { arr.Length = 10; });
    }

    [Fact]
    public void Equals_WithCountedComparer_AfterDispose_ThrowsObjectDisposedException()
    {
        var arr = new PinnedPoolArray<byte>(50);
        using var other = new PinnedPoolArray<byte>(50);
        arr.Dispose();

        Assert.Throws<ObjectDisposedException>(
            () => arr.Equals(other, new CountedEqualityComparer<byte>(50)));
    }

    [Fact]
    public void GetHashCode_WithCountedComparer_AfterDispose_ThrowsObjectDisposedException()
    {
        var arr = new PinnedPoolArray<byte>(50);
        arr.Dispose();

        Assert.Throws<ObjectDisposedException>(
            () => arr.GetHashCode(new CountedEqualityComparer<byte>(50)));
    }

    [Fact]
    public void StructuralCompareTo_AfterDispose_ThrowsObjectDisposedException()
    {
        var arr = new PinnedPoolArray<byte>(50);
        using var other = new PinnedPoolArray<byte>(50);
        arr.Dispose();

        Assert.Throws<ObjectDisposedException>(
            () => ((IStructuralComparable)arr).CompareTo(other, Comparer<object>.Default));
    }

    [Fact]
    public void StructuralCompareTo_OtherDisposed_ThrowsObjectDisposedException()
    {
        using var arr = new PinnedPoolArray<byte>(50);
        var other = new PinnedPoolArray<byte>(50);
        other.Dispose();

        Assert.Throws<ObjectDisposedException>(
            () => ((IStructuralComparable)arr).CompareTo(other, Comparer<object>.Default));
    }

    [Fact]
    public void StructuralCompareTo_NullComparer_ThrowsArgumentNullException()
    {
        using var arr = new PinnedPoolArray<byte>(50);
        using var other = new PinnedPoolArray<byte>(50);

        Assert.Throws<ArgumentNullException>(
            () => ((IStructuralComparable)arr).CompareTo(other, null));
    }

    [Fact]
    public void StructuralCompareTo_NullOther_NullComparer_PrefersArgumentNullException()
    {
        using var arr = new PinnedPoolArray<byte>(50);

        // Argument validation precedes the IStructuralComparable.CompareTo
        // "null is less than anything" shortcut.
        Assert.Throws<ArgumentNullException>(
            () => ((IStructuralComparable)arr).CompareTo(null, null));
    }

    [Fact]
    public void Equals_NullComparer_ThrowsArgumentNullException()
    {
        using var arr = new PinnedPoolArray<byte>(50);
        using var other = new PinnedPoolArray<byte>(50);

        Assert.Throws<ArgumentNullException>(
            () => arr.Equals(other, null));
    }

    [Fact]
    public void Equals_OtherPinnedArrayDisposed_ThrowsObjectDisposedException()
    {
        using var arr = new PinnedPoolArray<byte>(50);
        var other = new PinnedPoolArray<byte>(50);
        other.Dispose();

        Assert.Throws<ObjectDisposedException>(
            () => arr.Equals(other, new CountedEqualityComparer<byte>(50)));
    }

    [Fact]
    public void GetHashCode_NullComparer_ThrowsArgumentNullException()
    {
        using var arr = new PinnedPoolArray<byte>(50);

        Assert.Throws<ArgumentNullException>(
            () => arr.GetHashCode(null));
    }

    [Fact]
    public void Dispose_TwiceFromMultipleThreads_DoesNotDoubleFree()
    {
        // Concurrent Dispose calls must not return the same array to the pool twice.
        // ArrayPool surfaces double-return via InvalidOperationException on some TFMs.
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
