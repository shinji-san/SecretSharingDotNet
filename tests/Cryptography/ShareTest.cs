using Xunit;
using SecretSharingDotNet.Cryptography;
using System;

namespace SecretSharingDotNetTest.Cryptography;

using SecretSharingDotNet.Math.BigInteger;
using System.Numerics;

public class ShareTest
{
    private const string Share1TextRepresentation = "01-2929AA3E809003D578AA69B1C3E6F62C517437FEFBAD5BFBB240";
    private const string Share2TextRepresentation = "02-665C74ED38FDFF095B2FC9319A272A75";

    [Theory]
    [InlineData(5, 10)]
    [InlineData(1, 0)]
    [InlineData(12345678901234567890, 987654321098765430)]
    public void Constructor_ValidInputs_ShouldInitializeCorrectly(BigInteger index, BigInteger value)
    {
        // Arrange & Act
        var share = new Share<BigInteger>(index, value);

        // Assert
        Assert.Equal(new BigIntCalculator(index), share.Index);
        Assert.Equal(new BigIntCalculator(value), share.Value);
    }

    [Theory]
    [InlineData(-1)]
    [InlineData(-50)]
    [InlineData(-100)]
    public void Constructor_NegativeIndex_ShouldThrowArgumentOutOfRangeException(BigInteger index)
    {
        // Arrange
        var value = new BigIntCalculator(10);

        // Act & Assert
        Assert.Throws<ArgumentOutOfRangeException>(() => new Share<BigInteger>(index, value));
    }

    [Fact]
    public void Constructor_DefaultIndexValue_ShouldThrowArgumentOutOfRangeException()
    {
        // Arrange
        var index = BigIntCalculator.Zero;
        var value = new BigIntCalculator(10);

        // Act & Assert
        Assert.Throws<ArgumentOutOfRangeException>(() => new Share<BigInteger>(index, value));
    }

    [Fact]
    public void IsEven_ShouldReturnTrueIfIndexIsEven()
    {
        // Arrange
        var index = new BigIntCalculator(4);
        var value = new BigIntCalculator(10);
        var share = new Share<BigInteger>(index, value);

        // Act & Assert
        Assert.True(share.IsIndexEven);
    }

    [Fact]
    public void IsOdd_ShouldReturnTrueIfIndexIsOdd()
    {
        // Arrange
        var index = new BigIntCalculator(5);
        var value = new BigIntCalculator(10);
        var share = new Share<BigInteger>(index, value);

        // Act & Assert
        Assert.True(share.IsIndexOdd);
    }

    [Fact]
    public void IsEmpty_ShouldReturnTrueIfShareIsDefault()
    {
        // Arrange
        var share = new Share<BigInteger>();

        // Act & Assert
        Assert.True(share.IsEmpty);
    }

    [Theory]
    [InlineData(5, 10, "05-0A")]
    [InlineData(255, 255, "FF00-FF00")]
    [InlineData(16, 32, "10-20")]
    [InlineData(11, -86, "0B-AA")]
    [InlineData(1, 1, "01-01")]
    [InlineData(1000, 4096, "E803-0010")]
    public void ToString_ValidShare_ShouldReturnFormattedString(BigInteger index, BigInteger value, string expected)
    {
        // Arrange
        var share = new Share<BigInteger>(index, value);

        // Act & Assert
        Assert.Equal(expected, share.ToString());
    }

    [Theory]
    [InlineData(5, 10, "05-0a")]
    [InlineData(255, 255, "ff00-ff00")]
    [InlineData(16, 32, "10-20")]
    [InlineData(11, -86, "0b-aa")]
    [InlineData(1, 1, "01-01")]
    [InlineData(1000, 4096, "e803-0010")]
    public void ToString_WithFormatSpecifier_ShouldReturnFormattedString(BigInteger index, BigInteger value,
        string expected)
    {
        // Arrange
        var share = new Share<BigInteger>(index, value);

        // Act & Assert
        Assert.Equal(expected, share.ToString("x"));
    }

    [Fact]
    public void Parse_ValidString_ShouldParseCorrectly()
    {
        // Arrange
        const string shareString = "B-AA";

        // Act
        var share = Share<BigInteger>.Parse(shareString);

        // Assert
        Assert.Equal(new BigIntCalculator(11), share.Index);
        Assert.Equal(new BigIntCalculator(-86), share.Value);
    }

    [Theory]
    [InlineData(Share1TextRepresentation, Share1TextRepresentation)]
    [InlineData(Share2TextRepresentation, Share2TextRepresentation)]
    public void ToString_FromValidShare_ReturnsCoordinatesSeparatedWithMinus(string input, string expected)
    {
        // Arrange
        var shareUnderTest = new Share<BigInteger>(input);

        // Act
        string actual = shareUnderTest.ToString();

        // Assert
        Assert.Equal(expected, actual);
    }

    [Fact]
    public void Parse_InvalidString_ShouldThrowFormatException()
    {
        // Arrange
        const string shareString = "invalid-input";

        // Act & Assert
        Assert.Throws<ArgumentException>(() => Share<BigInteger>.Parse(shareString));
    }

    [Fact]
    public void TryParse_ValidString_ShouldReturnTrueAndOutputParsedShare()
    {
        // Arrange
        const string shareString = "05-10";

        // Act & Assert
        Assert.True(Share<BigInteger>.TryParse(shareString, out var share));
        Assert.Equal(new BigIntCalculator(5), share.Index);
        Assert.Equal(new BigIntCalculator(16), share.Value);
    }

    [Fact]
    public void TryParse_InvalidString_ShouldReturnFalse()
    {
        // Arrange
        const string shareString = "invalid-input";

        // Act & Assert
        Assert.False(Share<BigInteger>.TryParse(shareString, out var share));
        Assert.True(share.IsEmpty);
    }

    [Fact]
    public void CompareTo_ShouldReturnCorrectComparisonResult()
    {
        // Arrange
        var share1 = new Share<BigInteger>(new BigIntCalculator(5), new BigIntCalculator(10));
        var share2 = new Share<BigInteger>(new BigIntCalculator(10), new BigIntCalculator(20));

        // Act & Assert
        Assert.True(share1.CompareTo(share2) < 0);
        Assert.True(share2.CompareTo(share1) > 0);
        Assert.Equal(0, share1.CompareTo(new Share<BigInteger>(new BigIntCalculator(5), new BigIntCalculator(15))));
    }

    [Fact]
    public void Operators_ShouldPerformComparisonsCorrectly()
    {
        // Arrange
        var share1 = new Share<BigInteger>(new BigIntCalculator(5), new BigIntCalculator(10));
        var share2 = new Share<BigInteger>(new BigIntCalculator(10), new BigIntCalculator(20));

        // Act & Assert
        Assert.True(share1 < share2);
        Assert.False(share1 > share2);
        Assert.True(share1 <= share2);
        Assert.True(share2 >= share1);
    }
}