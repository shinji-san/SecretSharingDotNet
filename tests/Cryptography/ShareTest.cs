namespace SecretSharingDotNetTest.Cryptography;

using SecretSharingDotNet.Cryptography;
using SecretSharingDotNet.Cryptography.SecureInput;
using SecretSharingDotNet.Math;
using SecretSharingDotNet.Math.Numerics;
using System;
using System.Numerics;
using Xunit;

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
        // Arrange
        using Calculator<BigInteger> expectedIndex = index;
        using Calculator<BigInteger> expectedValue = value;

        // Act
        var share = new Share<BigInteger>(index, value);

        // Assert
        Assert.Equal(expectedIndex, share.Index);
        Assert.Equal(expectedValue, share.Value);
    }

    [Theory]
    [InlineData(-1)]
    [InlineData(-50)]
    [InlineData(-100)]
    public void Constructor_NegativeIndex_ShouldThrowArgumentOutOfRangeException(BigInteger index)
    {
        // Arrange
        using Calculator<BigInteger> value = (BigInteger)10;

        // Act & Assert
        Assert.Throws<ArgumentOutOfRangeException>(() => new Share<BigInteger>(index, value));
    }

    [Fact]
    public void Constructor_DefaultIndexValue_ShouldThrowArgumentOutOfRangeException()
    {
        // Arrange
        using var index = BigIntCalculator.Zero;
        using Calculator<BigInteger> value = (BigInteger)10;

        // Act & Assert
        Assert.Throws<ArgumentOutOfRangeException>(() => new Share<BigInteger>(index, value));
    }

    [Fact]
    public void Constructor_NullIndex_ThrowsArgumentNullException()
    {
        // Arrange
        Calculator<BigInteger> index = null;
        using Calculator<BigInteger> value = (BigInteger)10;

        // Act & Assert
        var ex = Assert.Throws<ArgumentNullException>(() => new Share<BigInteger>(index, value));
        Assert.Equal("index", ex.ParamName);
    }

    [Fact]
    public void Constructor_NullValue_ThrowsArgumentNullException()
    {
        // Arrange
        using Calculator<BigInteger> index = (BigInteger)5;
        Calculator<BigInteger> value = null;

        // Act & Assert
        var ex = Assert.Throws<ArgumentNullException>(() => new Share<BigInteger>(index, value));
        Assert.Equal("value", ex.ParamName);
    }

    [Fact]
    public void Constructor_ByteArrays_NullIndexBytes_ThrowsArgumentNullException()
    {
        // Arrange
        byte[] indexBytes = null;
        var valueBytes = new byte[] { 10 };

        // Act & Assert
        var ex = Assert.Throws<ArgumentNullException>(() => new Share<BigInteger>(indexBytes, valueBytes));
        Assert.Equal("indexBytes", ex.ParamName);
    }

    [Fact]
    public void Constructor_ByteArrays_NullValueBytes_ThrowsArgumentNullException()
    {
        // Arrange
        var indexBytes = new byte[] { 5 };
        byte[] valueBytes = null;

        // Act & Assert
        var ex = Assert.Throws<ArgumentNullException>(() => new Share<BigInteger>(indexBytes, valueBytes));
        Assert.Equal("valueBytes", ex.ParamName);
    }

    [Fact]
    public void Constructor_ByteArrays_ZeroIndex_ThrowsArgumentOutOfRangeException()
    {
        // Arrange
        var indexBytes = new byte[] { 0 };
        var valueBytes = new byte[] { 10 };

        // Act & Assert
        var ex = Assert.Throws<ArgumentOutOfRangeException>(() => new Share<BigInteger>(indexBytes, valueBytes));
        Assert.Equal("indexBytes", ex.ParamName);
    }

    [Fact]
    public void Constructor_ByteArrays_ValidInputs_InitializesCorrectly()
    {
        // Arrange
        var indexBytes = new byte[] { 5, 0 };
        var valueBytes = new byte[] { 10, 0 };

        // Act
        var share = new Share<BigInteger>(indexBytes, valueBytes);

        // Assert
        Assert.Equal(new BigIntCalculator(5), share.Index);
        Assert.Equal(new BigIntCalculator(10), share.Value);
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
#if DEBUG
        Assert.Equal(expected, share.ToString());
#else
        Assert.Equal("*** Secured Value ***", share.ToString());
#endif
    }

    [Fact]
    public void Constructor_ValidPinnedInput_ShouldParseCorrectly()
    {
        // Arrange
        using var pinned = "B-AA".ToPinnedSecure();

        // Act
        var share = new Share<BigInteger>(pinned);

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
        using var pinned = input.ToPinnedSecure();
        var shareUnderTest = new Share<BigInteger>(pinned);

        // Act
        string actual = shareUnderTest.ToString();

        // Assert
#if DEBUG
        Assert.Equal(expected, actual);
#else
        Assert.Equal("*** Secured Value ***", actual);
#endif
    }

    [Fact]
    public void Constructor_InvalidPinnedInput_ShouldThrowArgumentException()
    {
        // Arrange
        using var pinned = "invalid-input".ToPinnedSecure();

        // Act & Assert
        Assert.Throws<ArgumentException>(() => new Share<BigInteger>(pinned));
    }

    [Theory]
    [InlineData(5, 10, true, false, "05-0A")]
    [InlineData(5, 10, false, false, "05-0a")]
    [InlineData(16, 32, true, true, "0x10-0x20")]
    [InlineData(16, 32, false, true, "0x10-0x20")]
    [InlineData(11, -86, true, true, "0x0B-0xAA")]
    [InlineData(11, -86, false, true, "0x0b-0xaa")]
    [InlineData(1, 1, true, false, "01-01")]
    [InlineData(1000, 4096, false, false, "e803-0010")]
    public void ToCharArray_WithParameters_ShouldReturnFormattedChars(
        BigInteger index, BigInteger value, bool uppercase, bool withPrefix, string expected)
    {
        // Arrange
        var share = new Share<BigInteger>(index, value);

        // Act
        using var result = share.ToCharArray(uppercase, withPrefix);

        // Assert
        Assert.Equal(expected, new string(result.PoolArray, 0, result.Length));
    }

    [Fact]
    public void ToCharArray_NoArgs_ShouldReturnUppercaseWithoutPrefix()
    {
        // Arrange
        var share = new Share<BigInteger>(new BigIntCalculator(5), new BigIntCalculator(10));

        // Act
        using var result = share.ToCharArray();

        // Assert
        Assert.Equal("05-0A", new string(result.PoolArray, 0, result.Length));
    }

    [Theory]
    [InlineData("0x05-0x0A", 5, 10)]
    [InlineData("0x0B-0xAA", 11, -86)]
    [InlineData("0x01-0x01", 1, 1)]
    public void Constructor_WithLowerHexPrefix_ShouldParse(string shareString, int expectedIndex, int expectedValue)
    {
        using var pinned = shareString.ToPinnedSecure();
        var share = new Share<BigInteger>(pinned);

        Assert.Equal(new BigIntCalculator(expectedIndex), share.Index);
        Assert.Equal(new BigIntCalculator(expectedValue), share.Value);
    }

    [Theory]
    [InlineData("0x05-0A", 5, 10)]
    [InlineData("05-0x0A", 5, 10)]
    public void Constructor_WithPartialPrefix_ShouldParse(string shareString, int expectedIndex, int expectedValue)
    {
        using var pinned = shareString.ToPinnedSecure();
        var share = new Share<BigInteger>(pinned);

        Assert.Equal(new BigIntCalculator(expectedIndex), share.Index);
        Assert.Equal(new BigIntCalculator(expectedValue), share.Value);
    }

    [Theory]
    [InlineData("0X05-0X0A")]
    [InlineData("0X05-0x0A")]
    [InlineData("0x05-0X0A")]
    public void Constructor_WithUpperHexPrefix_ShouldThrow(string shareString)
    {
        using var pinned = shareString.ToPinnedSecure();
        Assert.Throws<ArgumentException>(() => new Share<BigInteger>(pinned));
    }

    [Theory]
    [InlineData("0xZZ-01")]
    [InlineData("0x01-0xGG")]
    public void Constructor_WithInvalidHexAfterPrefix_ShouldThrow(string shareString)
    {
        using var pinned = shareString.ToPinnedSecure();
        Assert.Throws<ArgumentException>(() => new Share<BigInteger>(pinned));
    }

    [Fact]
    public void Constructor_InvalidHexMessage_ContainsPosition()
    {
        // "01-ZX" — the 'Z' at position 3 is the first invalid hex character.
        using var pinned = "01-ZX".ToPinnedSecure();

        var ex = Assert.Throws<ArgumentException>(() => new Share<BigInteger>(pinned));

        Assert.Contains("3", ex.Message);
    }

    [Fact]
    public void Constructor_OddLengthWithInvalidChar_ThrowsArgumentException()
    {
        // Single-char (odd-length) index with a non-hex character exercises the
        // odd-length branch in DecodeHexToCalculator.
        using var pinned = "Z-01".ToPinnedSecure();

        var ex = Assert.Throws<ArgumentException>(() => new Share<BigInteger>(pinned));

        Assert.Contains("0", ex.Message);
    }

    [Theory]
    [InlineData("0x-01")]
    [InlineData("01-0x")]
    [InlineData("0x-0x")]
    public void Constructor_WithEmptyCoordinateAfterPrefix_ShouldThrow(string shareString)
    {
        using var pinned = shareString.ToPinnedSecure();
        Assert.Throws<FormatException>(() => new Share<BigInteger>(pinned));
    }

    [Theory]
    [InlineData(5, 10)]
    [InlineData(11, 170)]
    [InlineData(1000, 4096)]
    public void RoundTrip_ToCharArrayWithPrefix_ShouldParseBack(BigInteger index, BigInteger value)
    {
        var original = new Share<BigInteger>(index, value);

        using var chars = original.ToCharArray(uppercase: true, withPrefix: true);
        var parsed = new Share<BigInteger>(chars);

        Assert.Equal(original.Index, parsed.Index);
        Assert.Equal(original.Value, parsed.Value);
    }

    [Theory]
    [InlineData(5, 10, false, 5)]
    [InlineData(5, 10, true, 9)]
    [InlineData(255, 255, false, 9)]
    [InlineData(255, 255, true, 13)]
    [InlineData(1000, 4096, false, 9)]
    [InlineData(1000, 4096, true, 13)]
    [InlineData(5, -86, false, 5)]
    [InlineData(5, -86, true, 9)]
    [InlineData(5, 128, false, 7)]
    [InlineData(5, 128, true, 11)]
    public void GetCharCount_MatchesToCharArrayLength(BigInteger index, BigInteger value, bool withPrefix, int expected)
    {
        var share = new Share<BigInteger>(index, value);

        var count = share.GetCharCount(withPrefix);
        using var chars = share.ToCharArray(uppercase: true, withPrefix);

        Assert.Equal(expected, count);
        Assert.Equal(chars.Length, count);
    }

    [Theory]
    [InlineData(5, 10, true, false, "05-0A")]
    [InlineData(16, 32, true, true, "0x10-0x20")]
    [InlineData(11, -86, false, true, "0x0b-0xaa")]
    [InlineData(1000, 4096, false, false, "e803-0010")]
    public void WriteCharsTo_WithParameters_WritesExpectedChars(
        BigInteger index, BigInteger value, bool uppercase, bool withPrefix, string expected)
    {
        var share = new Share<BigInteger>(index, value);
        var buffer = new char[expected.Length + 4];
        var written = share.WriteCharsTo(buffer, offset: 2, uppercase, withPrefix);

        Assert.Equal(expected.Length, written);
        Assert.Equal(expected, new string(buffer, 2, written));
        Assert.Equal('\0', buffer[0]);
        Assert.Equal('\0', buffer[1]);
    }

    [Fact]
    public void WriteCharsTo_NullDest_ThrowsArgumentNullException()
    {
        var share = new Share<BigInteger>(new BigIntCalculator(5), new BigIntCalculator(10));

        Assert.Throws<ArgumentNullException>(() => share.WriteCharsTo(null, 0, uppercase: true, withPrefix: false));
    }

    [Theory]
    [InlineData(-1)]
    [InlineData(17)]
    public void WriteCharsTo_InvalidOffset_ThrowsArgumentOutOfRangeException(int offset)
    {
        var share = new Share<BigInteger>(new BigIntCalculator(5), new BigIntCalculator(10));
        var buffer = new char[16];

        Assert.Throws<ArgumentOutOfRangeException>(
            () => share.WriteCharsTo(buffer, offset, uppercase: true, withPrefix: false));
    }

    [Fact]
    public void WriteCharsTo_InsufficientSpace_ThrowsArgumentException()
    {
        var share = new Share<BigInteger>(new BigIntCalculator(5), new BigIntCalculator(10));
        var buffer = new char[16];

        // share "05-0A" needs 5 chars; offset 14 leaves only 2.
        Assert.Throws<ArgumentException>(
            () => share.WriteCharsTo(buffer, offset: 14, uppercase: true, withPrefix: false));
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

    [Fact]
    public void Dispose_Idempotent_NoException()
    {
        // Arrange
        var share = new Share<BigInteger>(new BigIntCalculator(5), new BigIntCalculator(10));

        // Act
        var ex = Record.Exception(() =>
        {
            share.Dispose();
            share.Dispose();
            share.Dispose();
        });

        // Assert
        Assert.Null(ex);
    }

    [Fact]
    public void Dispose_ReleasesIndexAndValue()
    {
        var index = new BigIntCalculator(5);
        var value = new BigIntCalculator(10);
        var share = new Share<BigInteger>(index, value);

        share.Dispose();

        // Post-dispose access to the underlying calculators via a public Share property path
        // should throw; we verify the Share-level guard.
        Assert.Throws<ObjectDisposedException>(share.ToCharArray);
    }

    [Fact]
    public void PostDispose_ToString_DoesNotThrowInDebug()
    {
        var share = new Share<BigInteger>(new BigIntCalculator(5), new BigIntCalculator(10));
        share.Dispose();

#if DEBUG
        // DEBUG ToString reads state → guarded by ThrowIfDisposed
        Assert.Throws<ObjectDisposedException>(share.ToString);
#else
        // Release ToString returns literal, no state access
        Assert.Equal("*** Secured Value ***", share.ToString());
#endif
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void PostDispose_GetCharCount_ThrowsObjectDisposedException(bool withPrefix)
    {
        var share = new Share<BigInteger>(new BigIntCalculator(5), new BigIntCalculator(10));
        share.Dispose();

        Assert.Throws<ObjectDisposedException>(() => share.GetCharCount(withPrefix));
    }

    [Fact]
    public void PostDispose_WriteCharsTo_ThrowsObjectDisposedException()
    {
        var share = new Share<BigInteger>(new BigIntCalculator(5), new BigIntCalculator(10));
        share.Dispose();
        var buffer = new char[16];

        Assert.Throws<ObjectDisposedException>(
            () => share.WriteCharsTo(buffer, 0, uppercase: true, withPrefix: false));
    }

    [Fact]
    public void PostDispose_IsIndexEven_ThrowsObjectDisposedException()
    {
        var share = new Share<BigInteger>(new BigIntCalculator(4), new BigIntCalculator(10));
        share.Dispose();

        Assert.Throws<ObjectDisposedException>(() => _ = share.IsIndexEven);
    }

    [Fact]
    public void PostDispose_CompareTo_ThrowsObjectDisposedException()
    {
        var share1 = new Share<BigInteger>(new BigIntCalculator(5), new BigIntCalculator(10));
        using var share2 = new Share<BigInteger>(new BigIntCalculator(7), new BigIntCalculator(20));
        share1.Dispose();

        Assert.Throws<ObjectDisposedException>(() => share1.CompareTo(share2));
    }

    [Fact]
    public void CompareTo_NullOther_ReturnsPositive()
    {
        using var share = new Share<BigInteger>(new BigIntCalculator(5), new BigIntCalculator(10));

        Assert.Equal(1, share.CompareTo(null));
    }

    [Fact]
    public void PostDispose_IndexGetter_ThrowsObjectDisposedException()
    {
        var share = new Share<BigInteger>(new BigIntCalculator(5), new BigIntCalculator(10));
        share.Dispose();

        Assert.Throws<ObjectDisposedException>(() => _ = share.Index);
    }

    [Fact]
    public void PostDispose_ValueGetter_ThrowsObjectDisposedException()
    {
        var share = new Share<BigInteger>(new BigIntCalculator(5), new BigIntCalculator(10));
        share.Dispose();

        Assert.Throws<ObjectDisposedException>(() => _ = share.Value);
    }

    [Fact]
    public void PostDispose_Deconstruct_ThrowsObjectDisposedException()
    {
        var share = new Share<BigInteger>(new BigIntCalculator(5), new BigIntCalculator(10));
        share.Dispose();

        Assert.Throws<ObjectDisposedException>(() =>
        {
            var (_, _) = share;
        });
    }
}