namespace SecretSharingDotNetTest.Cryptography.SecureArray;

using SecretSharingDotNet.Cryptography.SecureArray;
using System;
using System.Collections;
using Xunit;

public class CountedEqualityComparerTest
{
    [Fact]
    public void Constructor_NegativeCount_ThrowsArgumentOutOfRangeException()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new CountedEqualityComparer<byte>(-1));
    }

    [Fact]
    public void Constructor_ZeroCount_Succeeds()
    {
        // Arrange
        var comparer = new CountedEqualityComparer<byte>(0);

        // Act & Assert
        Assert.Equal(0, comparer.Count);
    }

    [Fact]
    public void Constructor_PositiveCount_StoresCount()
    {
        // Arrange
        var comparer = new CountedEqualityComparer<byte>(50);

        // Act & Assert
        Assert.Equal(50, comparer.Count);
    }

    [Fact]
    public void GenericEquals_DelegatesToElementComparer()
    {
        // Arrange
        var comparer = new CountedEqualityComparer<byte>(50);

        // Act & Assert
        Assert.True(comparer.Equals((byte)42, (byte)42));
        Assert.False(comparer.Equals((byte)42, (byte)43));
    }

    [Fact]
    public void NonGenericEquals_BothNull_ReturnsTrue()
    {
        // Arrange
        IEqualityComparer comparer = new CountedEqualityComparer<byte>(50);

        // Act & Assert
        Assert.True(comparer.Equals(null, null));
    }

    [Fact]
    public void NonGenericEquals_OneNull_ReturnsFalse()
    {
        // Arrange
        IEqualityComparer comparer = new CountedEqualityComparer<byte>(50);

        // Act & Assert
        Assert.False(comparer.Equals(null, (byte)42));
        Assert.False(comparer.Equals((byte)42, null));
    }

    [Fact]
    public void NonGenericEquals_FirstWrongType_ThrowsWithParamNameX()
    {
        // Arrange
        IEqualityComparer comparer = new CountedEqualityComparer<byte>(50);

        // Act
        var ex = Assert.Throws<ArgumentException>(() => comparer.Equals("not a byte", (byte)42));

        // Assert
        Assert.Equal("x", ex.ParamName);
    }

    [Fact]
    public void NonGenericEquals_SecondWrongType_ThrowsWithParamNameY()
    {
        // Arrange
        IEqualityComparer comparer = new CountedEqualityComparer<byte>(50);

        // Act
        var ex = Assert.Throws<ArgumentException>(() => comparer.Equals((byte)42, "not a byte"));

        // Assert
        Assert.Equal("y", ex.ParamName);
    }

    [Fact]
    public void NonGenericGetHashCode_NullObj_ThrowsArgumentNullException()
    {
        // Arrange
        IEqualityComparer comparer = new CountedEqualityComparer<byte>(50);

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => comparer.GetHashCode(null));
    }

    [Fact]
    public void NonGenericGetHashCode_WrongType_ThrowsWithParamNameObj()
    {
        // Arrange
        IEqualityComparer comparer = new CountedEqualityComparer<byte>(50);

        // Act
        var ex = Assert.Throws<ArgumentException>(() => comparer.GetHashCode("not a byte"));

        // Assert
        Assert.Equal("obj", ex.ParamName);
    }

    [Fact]
    public void NonGenericGetHashCode_ValidValue_DelegatesToElementComparer()
    {
        // Arrange
        IEqualityComparer comparer = new CountedEqualityComparer<byte>(50);

        // Act
        var hash = comparer.GetHashCode((byte)42);

        // Assert
        Assert.Equal(((byte)42).GetHashCode(), hash);
    }

    [Fact]
    public void ToString_IncludesCountAndElementType()
    {
        // Arrange
        var comparer = new CountedEqualityComparer<byte>(50);

        // Act
        var representation = comparer.ToString();

        // Assert
        Assert.Contains("Byte", representation);
        Assert.Contains("Count=50", representation);
        Assert.Contains("Element=", representation);
    }

    [Fact]
    public void Constructor_CustomElementComparer_IsUsedInsteadOfDefault()
    {
        // Arrange
        var customComparer = StringComparer.OrdinalIgnoreCase;
        var comparer = new CountedEqualityComparer<string>(10, customComparer);

        // Act & Assert
        Assert.True(comparer.Equals("Hello", "HELLO"));
        Assert.False(comparer.Equals("Hello", "World"));
    }

    [Fact]
    public void Constructor_NullElementComparer_FallsBackToDefault()
    {
        // Arrange
        var comparer = new CountedEqualityComparer<byte>(10, null);

        // Act & Assert
        Assert.True(comparer.Equals((byte)42, (byte)42));
        Assert.False(comparer.Equals((byte)42, (byte)43));
    }

    [Fact]
    public void NonGenericEquals_BothMatchingType_DelegatesToGenericEquals()
    {
        // Arrange
        IEqualityComparer comparer = new CountedEqualityComparer<byte>(10);

        // Act & Assert
        Assert.True(comparer.Equals((byte)42, (byte)42));
        Assert.False(comparer.Equals((byte)42, (byte)43));
    }

    [Fact]
    public void GenericGetHashCode_DelegatesToElementComparer()
    {
        // Arrange
        var comparer = new CountedEqualityComparer<byte>(10);

        // Act
        var hash = comparer.GetHashCode((byte)42);

        // Assert
        Assert.Equal(((byte)42).GetHashCode(), hash);
    }
}