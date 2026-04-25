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
        var comparer = new CountedEqualityComparer<byte>(0);
        Assert.Equal(0, comparer.Count);
    }

    [Fact]
    public void Constructor_PositiveCount_StoresCount()
    {
        var comparer = new CountedEqualityComparer<byte>(50);
        Assert.Equal(50, comparer.Count);
    }

    [Fact]
    public void GenericEquals_DelegatesToElementComparer()
    {
        var comparer = new CountedEqualityComparer<byte>(50);
        Assert.True(comparer.Equals((byte)42, (byte)42));
        Assert.False(comparer.Equals((byte)42, (byte)43));
    }

    [Fact]
    public void NonGenericEquals_BothNull_ReturnsTrue()
    {
        IEqualityComparer comparer = new CountedEqualityComparer<byte>(50);
        Assert.True(comparer.Equals(null, null));
    }

    [Fact]
    public void NonGenericEquals_OneNull_ReturnsFalse()
    {
        IEqualityComparer comparer = new CountedEqualityComparer<byte>(50);
        Assert.False(comparer.Equals(null, (byte)42));
        Assert.False(comparer.Equals((byte)42, null));
    }

    [Fact]
    public void NonGenericEquals_FirstWrongType_ThrowsWithParamNameX()
    {
        IEqualityComparer comparer = new CountedEqualityComparer<byte>(50);
        var ex = Assert.Throws<ArgumentException>(() => comparer.Equals("not a byte", (byte)42));
        Assert.Equal("x", ex.ParamName);
    }

    [Fact]
    public void NonGenericEquals_SecondWrongType_ThrowsWithParamNameY()
    {
        IEqualityComparer comparer = new CountedEqualityComparer<byte>(50);
        var ex = Assert.Throws<ArgumentException>(() => comparer.Equals((byte)42, "not a byte"));
        Assert.Equal("y", ex.ParamName);
    }

    [Fact]
    public void NonGenericGetHashCode_NullObj_ThrowsArgumentNullException()
    {
        IEqualityComparer comparer = new CountedEqualityComparer<byte>(50);
        Assert.Throws<ArgumentNullException>(() => comparer.GetHashCode(null));
    }

    [Fact]
    public void NonGenericGetHashCode_WrongType_ThrowsWithParamNameObj()
    {
        IEqualityComparer comparer = new CountedEqualityComparer<byte>(50);
        var ex = Assert.Throws<ArgumentException>(() => comparer.GetHashCode("not a byte"));
        Assert.Equal("obj", ex.ParamName);
    }

    [Fact]
    public void NonGenericGetHashCode_ValidValue_DelegatesToElementComparer()
    {
        IEqualityComparer comparer = new CountedEqualityComparer<byte>(50);
        var hash = comparer.GetHashCode((byte)42);
        Assert.Equal(((byte)42).GetHashCode(), hash);
    }

    [Fact]
    public void ToString_IncludesCountAndElementType()
    {
        var comparer = new CountedEqualityComparer<byte>(50);
        var representation = comparer.ToString();

        Assert.Contains("Byte", representation);
        Assert.Contains("Count=50", representation);
        Assert.Contains("Element=", representation);
    }
}