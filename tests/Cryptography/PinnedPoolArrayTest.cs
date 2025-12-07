using SecretSharingDotNet.Cryptography;
using Xunit;
using System;

namespace SecretSharingDotNetTest.Cryptography;

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
        var exception1 = Record.Exception(() => pinnedArray.Dispose());
        var exception2 = Record.Exception(() => pinnedArray.Dispose());

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
}
