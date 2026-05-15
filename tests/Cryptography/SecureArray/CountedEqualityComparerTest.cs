namespace SecretSharingDotNetTest.Cryptography.SecureArray;

using SecretSharingDotNet.Cryptography.SecureArray;
using System;
using System.Collections;
using Xunit;

/// <summary>
/// Tests for <see cref="CountedEqualityComparer{T}"/> — an <see cref="IEqualityComparer{T}"/>
/// implementation that pairs an element comparer with a fixed count, used to compare the
/// first <c>N</c> elements of pinned buffers without exposing the full
/// <see cref="PinnedPoolArray{T}.PoolArray"/> capacity to the comparison.
/// </summary>
public class CountedEqualityComparerTest
{
    /// <summary>
    /// Tests that the constructor rejects a negative <c>count</c> with
    /// <see cref="ArgumentOutOfRangeException"/>.
    /// </summary>
    [Fact]
    public void Constructor_NegativeCount_ThrowsArgumentOutOfRangeException()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new CountedEqualityComparer<byte>(-1));
    }

    /// <summary>
    /// Tests that the constructor accepts <c>count = 0</c> (a valid degenerate case for
    /// comparing empty prefixes) and stores it as the <see cref="CountedEqualityComparer{T}.Count"/> property.
    /// </summary>
    [Fact]
    public void Constructor_ZeroCount_Succeeds()
    {
        // Arrange
        var comparer = new CountedEqualityComparer<byte>(0);

        // Act & Assert
        Assert.Equal(0, comparer.Count);
    }

    /// <summary>
    /// Tests that the constructor stores a positive <c>count</c> verbatim on the
    /// <see cref="CountedEqualityComparer{T}.Count"/> property.
    /// </summary>
    [Fact]
    public void Constructor_PositiveCount_StoresCount()
    {
        // Arrange
        var comparer = new CountedEqualityComparer<byte>(50);

        // Act & Assert
        Assert.Equal(50, comparer.Count);
    }

    /// <summary>
    /// Tests that the strongly-typed <c>Equals(T, T)</c> overload delegates to the
    /// configured element comparer (default <see cref="EqualityComparer{T}.Default"/>).
    /// </summary>
    [Fact]
    public void GenericEquals_DelegatesToElementComparer()
    {
        // Arrange
        var comparer = new CountedEqualityComparer<byte>(50);

        // Act & Assert
        Assert.True(comparer.Equals((byte)42, (byte)42));
        Assert.False(comparer.Equals((byte)42, (byte)43));
    }

    /// <summary>
    /// Tests that the non-generic <c>IEqualityComparer.Equals(object, object)</c> returns
    /// <see langword="true"/> when both arguments are <see langword="null"/>.
    /// </summary>
    [Fact]
    public void NonGenericEquals_BothNull_ReturnsTrue()
    {
        // Arrange
        IEqualityComparer comparer = new CountedEqualityComparer<byte>(50);

        // Act & Assert
        Assert.True(comparer.Equals(null, null));
    }

    /// <summary>
    /// Tests that the non-generic <c>IEqualityComparer.Equals(object, object)</c> returns
    /// <see langword="false"/> when exactly one of the arguments is <see langword="null"/>.
    /// </summary>
    [Fact]
    public void NonGenericEquals_OneNull_ReturnsFalse()
    {
        // Arrange
        IEqualityComparer comparer = new CountedEqualityComparer<byte>(50);

        // Act & Assert
        Assert.False(comparer.Equals(null, (byte)42));
        Assert.False(comparer.Equals((byte)42, null));
    }

    /// <summary>
    /// Tests that the non-generic <c>Equals</c> throws <see cref="ArgumentException"/> with
    /// <c>ParamName == "x"</c> when the first argument is of the wrong element type.
    /// </summary>
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

    /// <summary>
    /// Tests that the non-generic <c>Equals</c> throws <see cref="ArgumentException"/> with
    /// <c>ParamName == "y"</c> when the second argument is of the wrong element type.
    /// </summary>
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

    /// <summary>
    /// Tests that the non-generic <c>GetHashCode</c> throws
    /// <see cref="ArgumentNullException"/> for a <see langword="null"/> input.
    /// </summary>
    [Fact]
    public void NonGenericGetHashCode_NullObj_ThrowsArgumentNullException()
    {
        // Arrange
        IEqualityComparer comparer = new CountedEqualityComparer<byte>(50);

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => comparer.GetHashCode(null));
    }

    /// <summary>
    /// Tests that the non-generic <c>GetHashCode</c> throws <see cref="ArgumentException"/>
    /// with <c>ParamName == "obj"</c> when the argument is of the wrong element type.
    /// </summary>
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

    /// <summary>
    /// Tests that the non-generic <c>GetHashCode</c> on a valid value delegates to the
    /// configured element comparer's hashing — matches
    /// <see cref="byte.GetHashCode()"/> for the default comparer.
    /// </summary>
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

    /// <summary>
    /// Tests that <see cref="CountedEqualityComparer{T}.ToString"/> includes the element
    /// type, the count, and the element comparer name so debug diagnostics surface the
    /// comparer's configuration.
    /// </summary>
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

    /// <summary>
    /// Tests that the constructor's optional element-comparer parameter overrides the
    /// default — here <see cref="StringComparer.OrdinalIgnoreCase"/> is injected, so
    /// <c>"Hello"</c> and <c>"HELLO"</c> compare equal.
    /// </summary>
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

    /// <summary>
    /// Tests that the constructor falls back to <see cref="EqualityComparer{T}.Default"/>
    /// when a <see langword="null"/> element comparer is supplied.
    /// </summary>
    [Fact]
    public void Constructor_NullElementComparer_FallsBackToDefault()
    {
        // Arrange
        var comparer = new CountedEqualityComparer<byte>(10, null);

        // Act & Assert
        Assert.True(comparer.Equals((byte)42, (byte)42));
        Assert.False(comparer.Equals((byte)42, (byte)43));
    }

    /// <summary>
    /// Tests that the non-generic <c>Equals</c> with two correctly-typed arguments delegates
    /// to the strongly-typed <c>Equals(T, T)</c> overload (matching results for matching inputs).
    /// </summary>
    [Fact]
    public void NonGenericEquals_BothMatchingType_DelegatesToGenericEquals()
    {
        // Arrange
        IEqualityComparer comparer = new CountedEqualityComparer<byte>(10);

        // Act & Assert
        Assert.True(comparer.Equals((byte)42, (byte)42));
        Assert.False(comparer.Equals((byte)42, (byte)43));
    }

    /// <summary>
    /// Tests that the strongly-typed <c>GetHashCode(T)</c> overload delegates to the
    /// configured element comparer's hashing.
    /// </summary>
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