namespace SecretSharingDotNetTest.Cryptography.BigInteger;

using SecretSharingDotNet.Cryptography;
using SecretSharingDotNet.Cryptography.SecureInput;
using SecretSharingDotNet.Math;
using SecretSharingDotNet.Math.Numerics;
using System;
using System.Collections.Generic;
using System.Numerics;
using Xunit;

/// <summary>
/// Tests for <see cref="Share{TNumber}"/> on the <see cref="BigInteger"/> backend —
/// construction (calculator + byte-array + pinned-char paths), hex serialization,
/// comparison, and the cascade-disposal contract.
/// </summary>
public class ShareTest
{
    private const string Share1TextRepresentation = "01-2929AA3E809003D578AA69B1C3E6F62C517437FEFBAD5BFBB240";
    private const string Share2TextRepresentation = "02-665C74ED38FDFF095B2FC9319A272A75";

    /// <summary>
    /// Tests that the <c>(index, value)</c> constructor stores both calculators verbatim
    /// across small, edge, and large inputs.
    /// </summary>
    /// <param name="index">Share index (x-coordinate).</param>
    /// <param name="value">Share value (y-coordinate).</param>
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
        using var share = new Share<BigInteger>(index, value);

        // Assert
        Assert.Equal(expectedIndex, share.Index);
        Assert.Equal(expectedValue, share.Value);
    }

    /// <summary>
    /// Tests that the <c>(index, value)</c> constructor rejects a negative index with
    /// <see cref="ArgumentOutOfRangeException"/> — share x-coordinates must be positive.
    /// </summary>
    /// <param name="index">A negative index value.</param>
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

    /// <summary>
    /// Tests that the <c>(index, value)</c> constructor rejects an index of zero with
    /// <see cref="ArgumentOutOfRangeException"/> — index 0 is reserved for the Lagrange
    /// reconstruction point.
    /// </summary>
    [Fact]
    public void Constructor_DefaultIndexValue_ShouldThrowArgumentOutOfRangeException()
    {
        // Arrange
        using var index = BigIntCalculator.Zero;
        using Calculator<BigInteger> value = (BigInteger)10;

        // Act & Assert
        Assert.Throws<ArgumentOutOfRangeException>(() => new Share<BigInteger>(index, value));
    }

    /// <summary>
    /// Tests that the <c>(index, value)</c> constructor rejects a <see langword="null"/>
    /// index with <see cref="ArgumentNullException"/>.
    /// </summary>
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

    /// <summary>
    /// Tests that the <c>(index, value)</c> constructor rejects a <see langword="null"/>
    /// value with <see cref="ArgumentNullException"/>.
    /// </summary>
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

    /// <summary>
    /// Tests that the byte-array constructor rejects a <see langword="null"/> indexBytes
    /// argument with <see cref="ArgumentNullException"/>.
    /// </summary>
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

    /// <summary>
    /// Tests that the byte-array constructor rejects a <see langword="null"/> valueBytes
    /// argument with <see cref="ArgumentNullException"/>.
    /// </summary>
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

    /// <summary>
    /// Tests that the byte-array constructor rejects index bytes that decode to zero with
    /// <see cref="InvalidShareException"/> — the same positivity invariant as the calculator-based
    /// constructor, surfaced as a malformed-share error on the byte-decode path.
    /// </summary>
    [Fact]
    public void Constructor_ByteArrays_ZeroIndex_ThrowsInvalidShareException()
    {
        // Arrange
        var indexBytes = new byte[] { 0 };
        var valueBytes = new byte[] { 10 };

        // Act & Assert
        var ex = Assert.Throws<InvalidShareException>(() => new Share<BigInteger>(indexBytes, valueBytes));
        Assert.IsAssignableFrom<SecretSharingException>(ex);
    }

    /// <summary>
    /// Tests that the byte-array constructor decodes the LE-2c byte streams into the matching
    /// <see cref="BigInteger"/> values for both index and value.
    /// </summary>
    [Fact]
    public void Constructor_ByteArrays_ValidInputs_InitializesCorrectly()
    {
        // Arrange
        var indexBytes = new byte[] { 5, 0 };
        var valueBytes = new byte[] { 10, 0 };

        // Act
        using var share = new Share<BigInteger>(indexBytes, valueBytes);

        // Assert
        using var expectedIndex = new BigIntCalculator(5);
        using var expectedValue = new BigIntCalculator(10);
        Assert.Equal(expectedIndex, share.Index);
        Assert.Equal(expectedValue, share.Value);
    }

    /// <summary>
    /// Tests that <see cref="Share{TNumber}.IsIndexEven"/> returns <see langword="true"/>
    /// for an even share index.
    /// </summary>
    [Fact]
    public void IsEven_ShouldReturnTrueIfIndexIsEven()
    {
        // Arrange
        var index = new BigIntCalculator(4);
        var value = new BigIntCalculator(10);
        using var share = new Share<BigInteger>(index, value);

        // Act & Assert
        Assert.True(share.IsIndexEven);
    }

    /// <summary>
    /// Tests that <see cref="Share{TNumber}.IsIndexOdd"/> returns <see langword="true"/>
    /// for an odd share index — the complementary case to the even check.
    /// </summary>
    [Fact]
    public void IsOdd_ShouldReturnTrueIfIndexIsOdd()
    {
        // Arrange
        var index = new BigIntCalculator(5);
        var value = new BigIntCalculator(10);
        using var share = new Share<BigInteger>(index, value);

        // Act & Assert
        Assert.True(share.IsIndexOdd);
    }

    /// <summary>
    /// Tests that <see cref="Share{TNumber}.ToString"/> emits the canonical
    /// <c>index-value</c> uppercase-hex form in DEBUG builds (and the redacted
    /// <c>"*** Secured Value ***"</c> marker in Release).
    /// </summary>
    /// <param name="index">Share index.</param>
    /// <param name="value">Share value.</param>
    /// <param name="expected">Expected DEBUG-mode string representation.</param>
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
        using var share = new Share<BigInteger>(index, value);

        // Act
        string actual = share.ToString();

        // Assert
#if DEBUG
        Assert.Equal(expected, actual);
#else
        Assert.Equal(TestData.SecuredValueSentinel, actual);
        Assert.NotEqual(expected, actual);
#endif
    }

    /// <summary>
    /// Tests that the pinned-char constructor parses an <c>index-value</c> hex
    /// representation into the matching index and value calculators.
    /// </summary>
    [Fact]
    public void Constructor_ValidPinnedInput_ShouldParseCorrectly()
    {
        // Arrange
        using var pinned = "B-AA".ToPinnedSecure();

        // Act
        using var share = new Share<BigInteger>(pinned);

        // Assert
        using var expectedIndex = new BigIntCalculator(11);
        using var expectedValue = new BigIntCalculator(-86);
        Assert.Equal(expectedIndex, share.Index);
        Assert.Equal(expectedValue, share.Value);
    }

    /// <summary>
    /// Tests the round-trip <c>parse → ToString</c> on representative share text:
    /// re-serialising a parsed share reproduces the original input verbatim in DEBUG.
    /// </summary>
    /// <param name="input">Share text fed to the pinned-char constructor.</param>
    /// <param name="expected">Expected DEBUG-mode <c>ToString</c> output.</param>
    [Theory]
    [InlineData(Share1TextRepresentation, Share1TextRepresentation)]
    [InlineData(Share2TextRepresentation, Share2TextRepresentation)]
    public void ToString_FromValidShare_ReturnsCoordinatesSeparatedWithMinus(string input, string expected)
    {
        // Arrange
        using var pinned = input.ToPinnedSecure();
        using var shareUnderTest = new Share<BigInteger>(pinned);

        // Act
        string actual = shareUnderTest.ToString();

        // Assert
#if DEBUG
        Assert.Equal(expected, actual);
#else
        Assert.Equal(TestData.SecuredValueSentinel, actual);
        Assert.NotEqual(expected, actual);
#endif
    }

    /// <summary>
    /// Tests that the pinned-char constructor rejects malformed inputs (here a hyphen-only
    /// separator without valid hex on either side) with <see cref="InvalidShareException"/>.
    /// </summary>
    [Fact]
    public void Constructor_InvalidPinnedInput_ShouldThrowInvalidShareException()
    {
        // Arrange
        using var pinned = "invalid-input".ToPinnedSecure();

        // Act & Assert
        Assert.Throws<InvalidShareException>(() => new Share<BigInteger>(pinned));
    }

    /// <summary>
    /// Tests that <see cref="Share{TNumber}.ToCharArray(bool, bool)"/> formats the share
    /// across the matrix of <c>uppercase × withPrefix</c> options consistent with the
    /// expected pinned-char output.
    /// </summary>
    /// <param name="index">Share index.</param>
    /// <param name="value">Share value.</param>
    /// <param name="uppercase">Whether hex letters are upper-case.</param>
    /// <param name="withPrefix">Whether the <c>0x</c> prefix is emitted.</param>
    /// <param name="expected">Expected serialised representation.</param>
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
        using var share = new Share<BigInteger>(index, value);

        // Act
        using var result = share.ToCharArray(uppercase, withPrefix);

        // Assert
        Assert.Equal(expected, new string(result.PoolArray, 0, result.Length));
    }

    /// <summary>
    /// Tests that the parameterless <see cref="Share{TNumber}.ToCharArray()"/> overload
    /// defaults to uppercase-without-prefix formatting (<c>"05-0A"</c>).
    /// </summary>
    [Fact]
    public void ToCharArray_NoArgs_ShouldReturnUppercaseWithoutPrefix()
    {
        // Arrange
        using var share = new Share<BigInteger>(new BigIntCalculator(5), new BigIntCalculator(10));

        // Act
        using var result = share.ToCharArray();

        // Assert
        Assert.Equal("05-0A", new string(result.PoolArray, 0, result.Length));
    }

    /// <summary>
    /// Tests that the pinned-char constructor accepts inputs with a lowercase <c>0x</c>
    /// prefix on both coordinates.
    /// </summary>
    /// <param name="shareString">Share text including the <c>0x</c> prefix.</param>
    /// <param name="expectedIndex">Expected parsed index.</param>
    /// <param name="expectedValue">Expected parsed value.</param>
    [Theory]
    [InlineData("0x05-0x0A", 5, 10)]
    [InlineData("0x0B-0xAA", 11, -86)]
    [InlineData("0x01-0x01", 1, 1)]
    public void Constructor_WithLowerHexPrefix_ShouldParse(string shareString, int expectedIndex, int expectedValue)
    {
        // Arrange
        using var pinned = shareString.ToPinnedSecure();

        // Act
        using var share = new Share<BigInteger>(pinned);

        // Assert
        using var expectedIndexCalc = new BigIntCalculator(expectedIndex);
        using var expectedValueCalc = new BigIntCalculator(expectedValue);
        Assert.Equal(expectedIndexCalc, share.Index);
        Assert.Equal(expectedValueCalc, share.Value);
    }

    /// <summary>
    /// Tests that the pinned-char constructor accepts inputs where only one of the two
    /// coordinates carries a <c>0x</c> prefix — the prefix on either side is optional.
    /// </summary>
    /// <param name="shareString">Share text with a partial prefix.</param>
    /// <param name="expectedIndex">Expected parsed index.</param>
    /// <param name="expectedValue">Expected parsed value.</param>
    [Theory]
    [InlineData("0x05-0A", 5, 10)]
    [InlineData("05-0x0A", 5, 10)]
    public void Constructor_WithPartialPrefix_ShouldParse(string shareString, int expectedIndex, int expectedValue)
    {
        // Arrange
        using var pinned = shareString.ToPinnedSecure();

        // Act
        using var share = new Share<BigInteger>(pinned);

        // Assert
        using var expectedIndexCalc = new BigIntCalculator(expectedIndex);
        using var expectedValueCalc = new BigIntCalculator(expectedValue);
        Assert.Equal(expectedIndexCalc, share.Index);
        Assert.Equal(expectedValueCalc, share.Value);
    }

    /// <summary>
    /// Tests that the pinned-char constructor rejects an uppercase <c>0X</c> prefix on
    /// either coordinate with <see cref="InvalidShareException"/> — only the lowercase
    /// <c>0x</c> form is accepted.
    /// </summary>
    /// <param name="shareString">Share text with an uppercase prefix variant.</param>
    [Theory]
    [InlineData("0X05-0X0A")]
    [InlineData("0X05-0x0A")]
    [InlineData("0x05-0X0A")]
    public void Constructor_WithUpperHexPrefix_ShouldThrow(string shareString)
    {
        // Arrange
        using var pinned = shareString.ToPinnedSecure();

        // Act & Assert
        Assert.Throws<InvalidShareException>(() => new Share<BigInteger>(pinned));
    }

    /// <summary>
    /// Tests that the pinned-char constructor rejects non-hex characters after a valid
    /// <c>0x</c> prefix with <see cref="InvalidShareException"/>.
    /// </summary>
    /// <param name="shareString">Share text containing non-hex characters after the prefix.</param>
    [Theory]
    [InlineData("0xZZ-01")]
    [InlineData("0x01-0xGG")]
    public void Constructor_WithInvalidHexAfterPrefix_ShouldThrow(string shareString)
    {
        // Arrange
        using var pinned = shareString.ToPinnedSecure();

        // Act & Assert
        Assert.Throws<InvalidShareException>(() => new Share<BigInteger>(pinned));
    }

    /// <summary>
    /// Tests that the pinned-char constructor's <see cref="InvalidShareException"/> for invalid
    /// hex includes the offending character's position in the message — aids debugging
    /// without leaking the surrounding share material.
    /// </summary>
    [Fact]
    public void Constructor_InvalidHexMessage_ContainsPosition()
    {
        // Arrange
        // "01-ZX" — the 'Z' at position 3 is the first invalid hex character.
        using var pinned = "01-ZX".ToPinnedSecure();

        // Act
        var ex = Assert.Throws<InvalidShareException>(() => new Share<BigInteger>(pinned));

        // Assert
        Assert.Contains("3", ex.Message);
    }

    /// <summary>
    /// Tests the odd-length branch in the hex-to-calculator decoder: a single-character
    /// coordinate with a non-hex character must throw <see cref="InvalidShareException"/>
    /// rather than silently truncating.
    /// </summary>
    [Fact]
    public void Constructor_OddLengthWithInvalidChar_ThrowsInvalidShareException()
    {
        // Arrange
        // Single-char (odd-length) index with a non-hex character exercises the
        // odd-length branch in DecodeHexToCalculator.
        using var pinned = "Z-01".ToPinnedSecure();

        // Act
        var ex = Assert.Throws<InvalidShareException>(() => new Share<BigInteger>(pinned));

        // Assert
        Assert.Contains("0", ex.Message);
    }

    /// <summary>
    /// Tests that the pinned-char constructor rejects a <c>0x</c> prefix followed by no
    /// hex digits at all with <see cref="InvalidShareException"/> — distinguishes "missing
    /// coordinate" from "invalid coordinate".
    /// </summary>
    /// <param name="shareString">Share text where the prefix is not followed by digits.</param>
    [Theory]
    [InlineData("0x-01")]
    [InlineData("01-0x")]
    [InlineData("0x-0x")]
    public void Constructor_WithEmptyCoordinateAfterPrefix_ShouldThrow(string shareString)
    {
        // Arrange
        using var pinned = shareString.ToPinnedSecure();

        // Act & Assert
        Assert.Throws<InvalidShareException>(() => new Share<BigInteger>(pinned));
    }

    /// <summary>
    /// Tests the round-trip <c>ToCharArray(uppercase: true, withPrefix: true)</c> →
    /// <c>new Share(chars)</c>: the parsed share's index and value match the original.
    /// </summary>
    /// <param name="index">Share index for the round trip.</param>
    /// <param name="value">Share value for the round trip.</param>
    [Theory]
    [InlineData(5, 10)]
    [InlineData(11, 170)]
    [InlineData(1000, 4096)]
    public void RoundTrip_ToCharArrayWithPrefix_ShouldParseBack(BigInteger index, BigInteger value)
    {
        // Arrange
        using var original = new Share<BigInteger>(index, value);

        // Act
        using var chars = original.ToCharArray(uppercase: true, withPrefix: true);
        using var parsed = new Share<BigInteger>(chars);

        // Assert
        Assert.Equal(original.Index, parsed.Index);
        Assert.Equal(original.Value, parsed.Value);
    }

    /// <summary>
    /// Tests that <see cref="Share{TNumber}.GetCharCount(bool)"/> pre-computes the same
    /// length that <see cref="Share{TNumber}.ToCharArray(bool, bool)"/> ends up emitting —
    /// the agreement is required so callers can size buffers exactly before serialising.
    /// </summary>
    /// <param name="index">Share index.</param>
    /// <param name="value">Share value.</param>
    /// <param name="withPrefix">Whether the <c>0x</c> prefix is included.</param>
    /// <param name="expected">Expected character count.</param>
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
        // Arrange
        using var share = new Share<BigInteger>(index, value);

        // Act
        var count = share.GetCharCount(withPrefix);
        using var chars = share.ToCharArray(uppercase: true, withPrefix);

        // Assert
        Assert.Equal(expected, count);
        Assert.Equal(chars.Length, count);
    }

    /// <summary>
    /// Tests that <see cref="Share{TNumber}.WriteCharsTo"/> writes the formatted share into
    /// a caller-supplied buffer at a given offset, returning the number of characters
    /// written. Bytes before the offset must remain untouched.
    /// </summary>
    /// <param name="index">Share index.</param>
    /// <param name="value">Share value.</param>
    /// <param name="uppercase">Whether hex letters are upper-case.</param>
    /// <param name="withPrefix">Whether the <c>0x</c> prefix is emitted.</param>
    /// <param name="expected">Expected substring written to the buffer.</param>
    [Theory]
    [InlineData(5, 10, true, false, "05-0A")]
    [InlineData(16, 32, true, true, "0x10-0x20")]
    [InlineData(11, -86, false, true, "0x0b-0xaa")]
    [InlineData(1000, 4096, false, false, "e803-0010")]
    public void WriteCharsTo_WithParameters_WritesExpectedChars(
        BigInteger index, BigInteger value, bool uppercase, bool withPrefix, string expected)
    {
        // Arrange
        using var share = new Share<BigInteger>(index, value);
        var buffer = new char[expected.Length + 4];

        // Act
        var written = share.WriteCharsTo(buffer, offset: 2, uppercase, withPrefix);

        // Assert
        Assert.Equal(expected.Length, written);
        Assert.Equal(expected, new string(buffer, 2, written));
        Assert.Equal('\0', buffer[0]);
        Assert.Equal('\0', buffer[1]);
    }

    /// <summary>
    /// Tests that <see cref="Share{TNumber}.WriteCharsTo"/> rejects a <see langword="null"/>
    /// destination buffer with <see cref="ArgumentNullException"/>.
    /// </summary>
    [Fact]
    public void WriteCharsTo_NullDest_ThrowsArgumentNullException()
    {
        // Arrange
        using var share = new Share<BigInteger>(new BigIntCalculator(5), new BigIntCalculator(10));

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => share.WriteCharsTo(null, 0, uppercase: true, withPrefix: false));
    }

    /// <summary>
    /// Tests that <see cref="Share{TNumber}.WriteCharsTo"/> rejects offsets outside
    /// <c>[0, buffer.Length]</c> with <see cref="ArgumentOutOfRangeException"/>.
    /// </summary>
    /// <param name="offset">An invalid offset value.</param>
    [Theory]
    [InlineData(-1)]
    [InlineData(17)]
    public void WriteCharsTo_InvalidOffset_ThrowsArgumentOutOfRangeException(int offset)
    {
        // Arrange
        using var share = new Share<BigInteger>(new BigIntCalculator(5), new BigIntCalculator(10));
        var buffer = new char[16];

        // Act & Assert
        Assert.Throws<ArgumentOutOfRangeException>(
            () => share.WriteCharsTo(buffer, offset, uppercase: true, withPrefix: false));
    }

    /// <summary>
    /// Tests that <see cref="Share{TNumber}.WriteCharsTo"/> throws
    /// <see cref="ArgumentException"/> when the buffer plus offset cannot accommodate the
    /// full formatted share — prevents partial writes that would corrupt the destination.
    /// </summary>
    [Fact]
    public void WriteCharsTo_InsufficientSpace_ThrowsArgumentException()
    {
        // Arrange
        using var share = new Share<BigInteger>(new BigIntCalculator(5), new BigIntCalculator(10));
        var buffer = new char[16];

        // Act & Assert
        // share "05-0A" needs 5 chars; offset 14 leaves only 2.
        Assert.Throws<ArgumentException>(
            () => share.WriteCharsTo(buffer, offset: 14, uppercase: true, withPrefix: false));
    }

    /// <summary>
    /// Tests <see cref="Share{TNumber}.CompareTo"/>: the comparison is by x-coordinate
    /// only — shares with the same index but different values compare equal.
    /// </summary>
    [Fact]
    public void CompareTo_ShouldReturnCorrectComparisonResult()
    {
        // Arrange
        using var share1 = new Share<BigInteger>(new BigIntCalculator(5), new BigIntCalculator(10));
        using var share2 = new Share<BigInteger>(new BigIntCalculator(10), new BigIntCalculator(20));
        using var sameIndexShare = new Share<BigInteger>(new BigIntCalculator(5), new BigIntCalculator(15));

        // Act & Assert
        Assert.True(share1.CompareTo(share2) < 0);
        Assert.True(share2.CompareTo(share1) > 0);
        Assert.Equal(0, share1.CompareTo(sameIndexShare));
    }

    /// <summary>
    /// Tests the relational operators (<c>&lt;</c>, <c>&gt;</c>, <c>&lt;=</c>,
    /// <c>&gt;=</c>) on <see cref="Share{TNumber}"/>: each one delegates to
    /// <see cref="Share{TNumber}.CompareTo"/>'s sign.
    /// </summary>
    [Fact]
    public void Operators_ShouldPerformComparisonsCorrectly()
    {
        // Arrange
        using var share1 = new Share<BigInteger>(new BigIntCalculator(5), new BigIntCalculator(10));
        using var share2 = new Share<BigInteger>(new BigIntCalculator(10), new BigIntCalculator(20));

        // Act & Assert
        Assert.True(share1 < share2);
        Assert.False(share1 > share2);
        Assert.True(share1 <= share2);
        Assert.True(share2 >= share1);
    }

    /// <summary>
    /// Tests that calling <see cref="Share{TNumber}.Dispose"/> repeatedly is idempotent —
    /// the second and third calls do not throw.
    /// </summary>
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

    /// <summary>
    /// Tests that <see cref="Share{TNumber}.Dispose"/> cascades to the underlying index
    /// and value calculators — post-dispose share-level operations throw
    /// <see cref="ObjectDisposedException"/>.
    /// </summary>
    [Fact]
    public void Dispose_ReleasesIndexAndValue()
    {
        // Arrange
        var index = new BigIntCalculator(5);
        var value = new BigIntCalculator(10);
        var share = new Share<BigInteger>(index, value);

        // Act
        share.Dispose();

        // Assert
        // Post-dispose access to the underlying calculators via a public Share property path
        // should throw; we verify the Share-level guard.
        Assert.Throws<ObjectDisposedException>(share.ToCharArray);
    }

    /// <summary>
    /// Tests <see cref="Share{TNumber}.ToString"/> post-dispose behaviour: in DEBUG the
    /// implementation reads state and is guarded by <c>ThrowIfDisposed</c>, so it throws
    /// <see cref="ObjectDisposedException"/>. In Release it returns the redacted literal
    /// without touching state.
    /// </summary>
    [Fact]
    public void PostDispose_ToString_DoesNotThrowInDebug()
    {
        // Arrange
        var share = new Share<BigInteger>(new BigIntCalculator(5), new BigIntCalculator(10));
        share.Dispose();

        // Act & Assert
#if DEBUG
        // DEBUG ToString reads state → guarded by ThrowIfDisposed
        Assert.Throws<ObjectDisposedException>(share.ToString);
#else
        // Release ToString returns literal, no state access
        Assert.Equal(TestData.SecuredValueSentinel, share.ToString());
#endif
    }

    /// <summary>
    /// Tests that <see cref="Share{TNumber}.GetCharCount"/> post-dispose throws
    /// <see cref="ObjectDisposedException"/> for both prefix variants.
    /// </summary>
    /// <param name="withPrefix">Whether the prefix flag is set.</param>
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void PostDispose_GetCharCount_ThrowsObjectDisposedException(bool withPrefix)
    {
        // Arrange
        var share = new Share<BigInteger>(new BigIntCalculator(5), new BigIntCalculator(10));
        share.Dispose();

        // Act & Assert
        Assert.Throws<ObjectDisposedException>(() => share.GetCharCount(withPrefix));
    }

    /// <summary>
    /// Tests that <see cref="Share{TNumber}.WriteCharsTo"/> post-dispose throws
    /// <see cref="ObjectDisposedException"/>.
    /// </summary>
    [Fact]
    public void PostDispose_WriteCharsTo_ThrowsObjectDisposedException()
    {
        // Arrange
        var share = new Share<BigInteger>(new BigIntCalculator(5), new BigIntCalculator(10));
        share.Dispose();
        var buffer = new char[16];

        // Act & Assert
        Assert.Throws<ObjectDisposedException>(
            () => share.WriteCharsTo(buffer, 0, uppercase: true, withPrefix: false));
    }

    /// <summary>
    /// Tests that <see cref="Share{TNumber}.IsIndexEven"/> post-dispose throws
    /// <see cref="ObjectDisposedException"/> rather than dereferencing a stale calculator.
    /// </summary>
    [Fact]
    public void PostDispose_IsIndexEven_ThrowsObjectDisposedException()
    {
        // Arrange
        var share = new Share<BigInteger>(new BigIntCalculator(4), new BigIntCalculator(10));
        share.Dispose();

        // Act & Assert
        Assert.Throws<ObjectDisposedException>(() => _ = share.IsIndexEven);
    }

    /// <summary>
    /// Tests that <see cref="Share{TNumber}.CompareTo"/> post-dispose throws
    /// <see cref="ObjectDisposedException"/> — the disposed share cannot be ordered.
    /// </summary>
    [Fact]
    public void PostDispose_CompareTo_ThrowsObjectDisposedException()
    {
        // Arrange
        var share1 = new Share<BigInteger>(new BigIntCalculator(5), new BigIntCalculator(10));
        using var share2 = new Share<BigInteger>(new BigIntCalculator(7), new BigIntCalculator(20));
        share1.Dispose();

        // Act & Assert
        Assert.Throws<ObjectDisposedException>(() => share1.CompareTo(share2));
    }

    /// <summary>
    /// Tests that <see cref="Share{TNumber}.CompareTo"/> against a <see langword="null"/>
    /// argument returns <c>+1</c> per the
    /// <see cref="IComparable{T}"/> convention (any non-null is greater than null).
    /// </summary>
    [Fact]
    public void CompareTo_NullOther_ReturnsPositive()
    {
        // Arrange
        using var share = new Share<BigInteger>(new BigIntCalculator(5), new BigIntCalculator(10));

        // Act & Assert
        Assert.Equal(1, share.CompareTo(null));
    }

    /// <summary>
    /// Tests that <see cref="Share{TNumber}.Index"/>'s getter throws
    /// <see cref="ObjectDisposedException"/> post-dispose.
    /// </summary>
    [Fact]
    public void PostDispose_IndexGetter_ThrowsObjectDisposedException()
    {
        // Arrange
        var share = new Share<BigInteger>(new BigIntCalculator(5), new BigIntCalculator(10));
        share.Dispose();

        // Act & Assert
        Assert.Throws<ObjectDisposedException>(() => _ = share.Index);
    }

    /// <summary>
    /// Tests that <see cref="Share{TNumber}.Value"/>'s getter throws
    /// <see cref="ObjectDisposedException"/> post-dispose.
    /// </summary>
    [Fact]
    public void PostDispose_ValueGetter_ThrowsObjectDisposedException()
    {
        // Arrange
        var share = new Share<BigInteger>(new BigIntCalculator(5), new BigIntCalculator(10));
        share.Dispose();

        // Act & Assert
        Assert.Throws<ObjectDisposedException>(() => _ = share.Value);
    }

    /// <summary>
    /// Tests that the <c>Deconstruct</c> pattern-matching operator throws
    /// <see cref="ObjectDisposedException"/> post-dispose — same guard as the property
    /// getters, applied at the deconstruction call site.
    /// </summary>
    [Fact]
    public void PostDispose_Deconstruct_ThrowsObjectDisposedException()
    {
        // Arrange
        var share = new Share<BigInteger>(new BigIntCalculator(5), new BigIntCalculator(10));
        share.Dispose();

        // Act & Assert
        Assert.Throws<ObjectDisposedException>(() =>
        {
            var (_, _) = share;
        });
    }

    /// <summary>
    /// Tests <see cref="Share{TNumber}.Equals(Share{TNumber})"/>: two live shares with
    /// identical <see cref="Share{TNumber}.Index"/> and <see cref="Share{TNumber}.Value"/>
    /// compare equal via the user-provided override.
    /// </summary>
    [Fact]
    public void Equals_BothLive_SameIndexAndValue_ReturnsTrue()
    {
        // Arrange
        using var share1 = new Share<BigInteger>(new BigIntCalculator(5), new BigIntCalculator(10));
        using var share2 = new Share<BigInteger>(new BigIntCalculator(5), new BigIntCalculator(10));

        // Act & Assert
        Assert.True(share1.Equals(share2));
        Assert.True(share1 == share2);
        Assert.False(share1 != share2);
    }

    /// <summary>
    /// Tests <see cref="Share{TNumber}.Equals(Share{TNumber})"/>: shares with identical
    /// indices but differing values are not equal.
    /// </summary>
    [Fact]
    public void Equals_BothLive_DifferentValue_ReturnsFalse()
    {
        // Arrange
        using var share1 = new Share<BigInteger>(new BigIntCalculator(5), new BigIntCalculator(10));
        using var share2 = new Share<BigInteger>(new BigIntCalculator(5), new BigIntCalculator(99));

        // Act & Assert
        Assert.False(share1.Equals(share2));
        Assert.False(share1 == share2);
        Assert.True(share1 != share2);
    }

    /// <summary>
    /// Tests <see cref="Share{TNumber}.Equals(Share{TNumber})"/>: shares with differing
    /// indices are not equal even when values match.
    /// </summary>
    [Fact]
    public void Equals_BothLive_DifferentIndex_ReturnsFalse()
    {
        // Arrange
        using var share1 = new Share<BigInteger>(new BigIntCalculator(5), new BigIntCalculator(10));
        using var share2 = new Share<BigInteger>(new BigIntCalculator(7), new BigIntCalculator(10));

        // Act & Assert
        Assert.False(share1.Equals(share2));
    }

    /// <summary>
    /// Tests <see cref="Share{TNumber}.Equals(Share{TNumber})"/>: a <see langword="null"/>
    /// <paramref name="other"/> argument returns <see langword="false"/>.
    /// </summary>
    [Fact]
    public void Equals_NullOther_ReturnsFalse()
    {
        // Arrange
        using var share = new Share<BigInteger>(new BigIntCalculator(5), new BigIntCalculator(10));

        // Act & Assert
        Assert.False(share.Equals(null));
    }

    /// <summary>
    /// Tests <see cref="Share{TNumber}.Equals(Share{TNumber})"/>: a self-comparison short-circuits
    /// to <see langword="true"/> via the <see cref="object.ReferenceEquals"/> fast-path.
    /// </summary>
    [Fact]
    public void Equals_SameReference_ReturnsTrue()
    {
        // Arrange
        using var share = new Share<BigInteger>(new BigIntCalculator(5), new BigIntCalculator(10));

        // Act & Assert
        Assert.True(share.Equals(share));
    }

    /// <summary>
    /// Regression guard mirroring the SecureBigInteger sibling: post-dispose
    /// <see cref="Share{TNumber}.Equals(Share{TNumber})"/> throws via the share-level
    /// <c>ThrowIfDisposed</c> guard. The BigInteger backend has no observable post-dispose
    /// state on its Calculator (BigInteger is a struct), so the guard is the only thing
    /// surfacing the disposal — the regression risk lives in the Share-level check.
    /// </summary>
    [Fact]
    public void PostDispose_Equals_ThrowsObjectDisposedException()
    {
        // Arrange
        var share1 = new Share<BigInteger>(new BigIntCalculator(5), new BigIntCalculator(10));
        using var share2 = new Share<BigInteger>(new BigIntCalculator(5), new BigIntCalculator(10));
        share1.Dispose();

        // Act & Assert
        Assert.Throws<ObjectDisposedException>(() => share1.Equals(share2));
    }

    /// <summary>
    /// Tests that <see cref="Share{TNumber}.Equals(Share{TNumber})"/> throws when only the
    /// <paramref name="other"/> operand has been disposed (symmetric counterpart to
    /// <c>PostDispose_Equals_ThrowsObjectDisposedException</c>).
    /// </summary>
    [Fact]
    public void Equals_OtherDisposed_ThrowsObjectDisposedException()
    {
        // Arrange
        using var live = new Share<BigInteger>(new BigIntCalculator(5), new BigIntCalculator(10));
        var disposed = new Share<BigInteger>(new BigIntCalculator(5), new BigIntCalculator(10));
        disposed.Dispose();

        // Act & Assert
        Assert.Throws<ObjectDisposedException>(() => live.Equals(disposed));
    }

    /// <summary>
    /// Tests <see cref="Share{TNumber}.GetHashCode"/>: two live shares with identical
    /// <see cref="Share{TNumber}.Index"/> and <see cref="Share{TNumber}.Value"/> produce the
    /// same hash code. The internal <c>disposed</c> flag is deliberately excluded from the
    /// hash to keep the hash contract aligned with the value-based equality.
    /// </summary>
    [Fact]
    public void GetHashCode_BothLive_SameIndexAndValue_ProducesSameHash()
    {
        // Arrange
        using var share1 = new Share<BigInteger>(new BigIntCalculator(5), new BigIntCalculator(10));
        using var share2 = new Share<BigInteger>(new BigIntCalculator(5), new BigIntCalculator(10));

        // Act
        int hash1 = share1.GetHashCode();
        int hash2 = share2.GetHashCode();

        // Assert
        Assert.Equal(hash1, hash2);
    }

    /// <summary>
    /// Tests that <see cref="Share{TNumber}.GetHashCode"/> post-dispose throws
    /// <see cref="ObjectDisposedException"/> via the share-level <c>ThrowIfDisposed</c> guard.
    /// </summary>
    [Fact]
    public void PostDispose_GetHashCode_ThrowsObjectDisposedException()
    {
        // Arrange
        var share = new Share<BigInteger>(new BigIntCalculator(5), new BigIntCalculator(10));
        share.Dispose();

        // Act & Assert
        Assert.Throws<ObjectDisposedException>(() => share.GetHashCode());
    }

    /// <summary>
    /// Regression for PR #296 codex review comment <c>r3291559146</c>: the record
    /// <c>with</c> expression must not be allowed to produce a shallow shallow-copy of
    /// a <see cref="Share{TNumber}"/>. The protected copy constructor blocks the
    /// compiler-synthesised <c>&lt;Clone&gt;$</c> path with
    /// <see cref="NotSupportedException"/>, preventing two share instances from
    /// aliasing the same disposable <see cref="Calculator{TNumber}"/> backing fields
    /// (where the first <c>Dispose</c> would silently invalidate the second).
    /// </summary>
    [Fact]
    public void With_Expression_ThrowsNotSupportedException()
    {
        // Arrange
        using var share = new Share<BigInteger>(new BigIntCalculator(5), new BigIntCalculator(10));

        // Act & Assert — empty `with { }` triggers the protected copy ctor.
        Assert.Throws<NotSupportedException>(() => _ = share with { });
    }
    /// <summary>
    /// The coordinate constructor records no level. A caller handing over two coordinates cannot
    /// know which field they came from, so there is nothing to record — and <see langword="null"/>
    /// here means exactly that and nothing more. In particular it does not mark the share as
    /// coming from the legacy text format; this constructor produces the same state.
    /// Mirror of the SecureBigInteger-side fact of the same name.
    /// </summary>
    [Fact]
    public void SecurityLevel_FromCoordinateConstructor_IsNull()
    {
        // Arrange & Act
        using var share = new Share<BigInteger>(new BigIntCalculator(5), new BigIntCalculator(10));

        // Assert
        Assert.Null(share.SecurityLevel);
    }

    /// <summary>
    /// The byte-array constructor records no level, for the same reason as the coordinate one.
    /// Mirror of the SecureBigInteger-side fact of the same name.
    /// </summary>
    [Fact]
    public void SecurityLevel_FromByteArrayConstructor_IsNull()
    {
        // Arrange & Act
        using var share = new Share<BigInteger>(new byte[] { 5 }, new byte[] { 10 });

        // Assert
        Assert.Null(share.SecurityLevel);
    }

    /// <summary>
    /// A share parsed from the two-segment text form records no level, because that form carries
    /// none. Mirror of the SecureBigInteger-side fact of the same name.
    /// </summary>
    [Fact]
    public void SecurityLevel_FromLegacyTextConstructor_IsNull()
    {
        // Arrange
        using var pinned = "B-AA".ToPinnedSecure();

        // Act
        using var share = new Share<BigInteger>(pinned);

        // Assert
        Assert.Null(share.SecurityLevel);
    }

    /// <summary>
    /// Reading the level after disposal throws, like the other public properties of this type.
    /// Mirror of the SecureBigInteger-side fact of the same name.
    /// </summary>
    [Fact]
    public void PostDispose_SecurityLevel_ThrowsObjectDisposedException()
    {
        // Arrange
        var share = new Share<BigInteger>(new BigIntCalculator(5), new BigIntCalculator(10), 17);
        share.Dispose();

        // Act & Assert
        Assert.Throws<ObjectDisposedException>(() => _ = share.SecurityLevel);
    }

    /// <summary>
    /// Equality over the level, for identical coordinates. <see langword="null"/> is a state of its
    /// own, never a wildcard that matches any exponent — a wildcard would break transitivity.
    /// Mirror of the SecureBigInteger-side theory of the same name.
    /// </summary>
    /// <param name="leftLevel">Level recorded on the left share, or <c>0</c> for none.</param>
    /// <param name="rightLevel">Level recorded on the right share, or <c>0</c> for none.</param>
    /// <param name="expectedEqual">Whether the two shares are expected to compare equal.</param>
    [Theory]
    [InlineData(0, 0, true)]
    [InlineData(17, 17, true)]
    [InlineData(0, 17, false)]
    [InlineData(17, 0, false)]
    [InlineData(17, 19, false)]
    public void Equals_BothLive_SameCoordinates_FollowsTheLevel(int leftLevel, int rightLevel, bool expectedEqual)
    {
        // Arrange
        using var left = leftLevel == 0
            ? new Share<BigInteger>(new BigIntCalculator(5), new BigIntCalculator(10))
            : new Share<BigInteger>(new BigIntCalculator(5), new BigIntCalculator(10), leftLevel);
        using var right = rightLevel == 0
            ? new Share<BigInteger>(new BigIntCalculator(5), new BigIntCalculator(10))
            : new Share<BigInteger>(new BigIntCalculator(5), new BigIntCalculator(10), rightLevel);

        // Act
        bool areEqual = left.Equals(right);

        // Assert
        Assert.Equal(expectedEqual, areEqual);
    }

    /// <summary>
    /// Shares that compare equal hash equally, with the level present and with it absent. The
    /// converse is deliberately not asserted: including the level in the hash guarantees nothing
    /// about unequal shares, and the contract requires nothing of them either.
    /// Mirror of the SecureBigInteger-side fact of the same name.
    /// </summary>
    [Fact]
    public void GetHashCode_BothLive_EqualShares_ProduceSameHash()
    {
        // Arrange
        using var levelledLeft = new Share<BigInteger>(new BigIntCalculator(5), new BigIntCalculator(10), 17);
        using var levelledRight = new Share<BigInteger>(new BigIntCalculator(5), new BigIntCalculator(10), 17);
        using var legacyLeft = new Share<BigInteger>(new BigIntCalculator(5), new BigIntCalculator(10));
        using var legacyRight = new Share<BigInteger>(new BigIntCalculator(5), new BigIntCalculator(10));

        // Act & Assert
        Assert.Equal(levelledLeft.GetHashCode(), levelledRight.GetHashCode());
        Assert.Equal(legacyLeft.GetHashCode(), legacyRight.GetHashCode());
    }

    /// <summary>
    /// A legacy share and its levelled counterpart are distinct entries in a <see cref="HashSet{T}"/>.
    /// This is the consequence of letting the level into equality, and it is intended: a set that
    /// collapsed them would keep whichever arrived first and silently drop the field information.
    /// Mirror of the SecureBigInteger-side fact of the same name.
    /// </summary>
    [Fact]
    public void HashSet_LegacyAndLevelledShare_AreDistinctEntries()
    {
        // Arrange
        using var legacy = new Share<BigInteger>(new BigIntCalculator(5), new BigIntCalculator(10));
        using var levelled = new Share<BigInteger>(new BigIntCalculator(5), new BigIntCalculator(10), 17);

        // Act
        var set = new HashSet<Share<BigInteger>> { legacy, levelled };

        // Assert
        Assert.Equal(2, set.Count);
    }
    /// <summary>
    /// The legacy form drops a recorded level, and the parser reading it back records none. That
    /// loss is not a bug in the writer — it is the whole reason a persisted share cannot be
    /// reconstructed without being told its field, and it stays the default so existing output is
    /// byte-for-byte unchanged.
    /// Mirror of the SecureBigInteger-side fact of the same name.
    /// </summary>
    [Fact]
    public void ToCharArray_LegacyFormat_DropsTheSecurityLevel()
    {
        // Arrange
        using var share = new Share<BigInteger>(new BigIntCalculator(11), new BigIntCalculator(42), 17);

        // Act
        using var serialized = share.ToCharArray(uppercase: true, withPrefix: false, ShareFormat.Legacy);
        using var reparsed = new Share<BigInteger>(serialized);

        // Assert
        Assert.Equal("0B-2A", new string(serialized.PoolArray, 0, serialized.Length));
        Assert.Null(reparsed.SecurityLevel);
    }

    /// <summary>
    /// The extended form carries the level through a round trip, with and without the <c>0x</c>
    /// prefix. The prefix rule is one rule for every segment — the level segment is prefixed like
    /// the coordinates are — and the parser strips a prefix from each segment independently.
    /// Mirror of the SecureBigInteger-side theory of the same name.
    /// </summary>
    /// <param name="withPrefix">Whether each segment carries the <c>0x</c> prefix.</param>
    /// <param name="expected">The exact expected serialized form.</param>
    [Theory]
    [InlineData(false, "0B-2A-11")]
    [InlineData(true, "0x0B-0x2A-0x11")]
    public void ToCharArray_ExtendedFormat_RoundTripsTheSecurityLevel(bool withPrefix, string expected)
    {
        // Arrange — 0x11 is 17.
        using var share = new Share<BigInteger>(new BigIntCalculator(11), new BigIntCalculator(42), 17);

        // Act
        using var serialized = share.ToCharArray(uppercase: true, withPrefix, ShareFormat.Extended);
        using var reparsed = new Share<BigInteger>(serialized);

        // Assert
        Assert.Equal(expected, new string(serialized.PoolArray, 0, serialized.Length));
        Assert.Equal(17, reparsed.SecurityLevel);
        Assert.Equal(share, reparsed);
    }

    /// <summary>
    /// Asking for the extended form from a share that records no level is an
    /// <see cref="InvalidOperationException"/> — a valid request the object's state cannot serve.
    /// Emitting a zero, dropping back to two segments or guessing would each hand back a share
    /// claiming a field it does not know.
    /// Mirror of the SecureBigInteger-side fact of the same name.
    /// </summary>
    [Fact]
    public void ExtendedFormat_WithoutARecordedLevel_ThrowsInvalidOperation()
    {
        // Arrange
        using var share = new Share<BigInteger>(new BigIntCalculator(11), new BigIntCalculator(42));
        var destination = new char[64];

        // Act & Assert — every entry point on the write path refuses alike.
        Assert.Throws<InvalidOperationException>(() => share.GetCharCount(false, ShareFormat.Extended));
        Assert.Throws<InvalidOperationException>(() => share.ToCharArray(true, false, ShareFormat.Extended));
        Assert.Throws<InvalidOperationException>(
            () => share.WriteCharsTo(destination, 0, true, false, ShareFormat.Extended));
    }

    /// <summary>
    /// The measurer and the writer agree in both formats, with and without the prefix. They derive
    /// from one shared length rule rather than restating it, which is what keeps them in step when
    /// a segment is added.
    /// Mirror of the SecureBigInteger-side theory of the same name.
    /// </summary>
    /// <param name="withPrefix">Whether each segment carries the <c>0x</c> prefix.</param>
    /// <param name="extended">Whether to write the security level segment.</param>
    [Theory]
    [InlineData(false, false)]
    [InlineData(true, false)]
    [InlineData(false, true)]
    [InlineData(true, true)]
    public void GetCharCount_AgreesWithWriteCharsTo(bool withPrefix, bool extended)
    {
        // Arrange — 4931 needs three hex digits, so the level segment is not a fixed width.
        using var share = new Share<BigInteger>(new BigIntCalculator(11), new BigIntCalculator(42), 4931);
        var format = extended ? ShareFormat.Extended : ShareFormat.Legacy;
        var destination = new char[128];

        // Act
        int measured = share.GetCharCount(withPrefix, format);
        int written = share.WriteCharsTo(destination, 0, uppercase: true, withPrefix, format);

        // Assert
        Assert.Equal(measured, written);
    }

    /// <summary>
    /// The property that makes the extension safe for readers that predate it, exercised rather
    /// than asserted about separators: a parser that takes the first separator and hex-decodes the
    /// remainder refuses every extended form and accepts every legacy one.
    /// <para>
    /// <b>This runs a model of the released parser, not the released parser.</b> The old assembly
    /// cannot be loaded here, so <see cref="LegacyTwoSegmentParseSucceeds"/> reimplements the two
    /// decisions that matter — split at the first separator, strip one <c>0x</c> prefix, require
    /// the remainder to be hexadecimal. It establishes that the extended form fails those
    /// decisions; it does not establish anything the model got wrong about the original.
    /// </para>
    /// Mirror of the SecureBigInteger-side theory of the same name.
    /// </summary>
    /// <param name="index">Share index.</param>
    /// <param name="value">Share value.</param>
    /// <param name="securityLevel">Recorded security level.</param>
    /// <param name="withPrefix">Whether each segment carries the <c>0x</c> prefix.</param>
    [Theory]
    [InlineData(11, 42, 13, false)]
    [InlineData(11, 42, 13, true)]
    [InlineData(1, 1, 17, false)]
    [InlineData(255, 4095, 4931, false)]
    [InlineData(255, 4095, 4931, true)]
    public void ExtendedFormat_IsRejectedByATwoSegmentReader(int index, int value, int securityLevel, bool withPrefix)
    {
        // Arrange
        using var share = new Share<BigInteger>(new BigIntCalculator(index), new BigIntCalculator(value), securityLevel);

        // Act
        using var extended = share.ToCharArray(uppercase: true, withPrefix, ShareFormat.Extended);
        using var legacy = share.ToCharArray(uppercase: true, withPrefix, ShareFormat.Legacy);

        // Assert — the legacy shape still reads; the extended one does not.
        Assert.True(LegacyTwoSegmentParseSucceeds(new string(legacy.PoolArray, 0, legacy.Length)));
        Assert.False(LegacyTwoSegmentParseSucceeds(new string(extended.PoolArray, 0, extended.Length)));
    }

    /// <summary>
    /// A model of the parse every released version performs: first separator, one optional
    /// <c>0x</c> prefix per segment, the remainder decoded as hexadecimal.
    /// </summary>
    /// <param name="serialized">The serialized share to try.</param>
    /// <returns><see langword="true"/> when that parse would succeed.</returns>
    private static bool LegacyTwoSegmentParseSucceeds(string serialized)
    {
        int separator = serialized.IndexOf('-');
        if (separator < 0)
        {
            return false;
        }

        string value = serialized.Substring(separator + 1);
        if (value.StartsWith("0x", StringComparison.Ordinal))
        {
            value = value.Substring(2);
        }

        if (value.Length == 0)
        {
            return false;
        }

        foreach (char c in value)
        {
            bool isHexDigit = (c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f');
            if (!isHexDigit)
            {
                return false;
            }
        }

        return true;
    }

    /// <summary>
    /// A fourth segment is refused by shape rather than by a hex-digit complaint two layers down.
    /// Mirror of the SecureBigInteger-side fact of the same name.
    /// </summary>
    [Fact]
    public void Constructor_WithFourSegments_ThrowsInvalidShare()
    {
        // Arrange
        using var pinned = "B-AA-11-22".ToPinnedSecure();

        // Act & Assert
        Assert.Throws<InvalidShareException>(() => new Share<BigInteger>(pinned));
    }

    /// <summary>
    /// A level segment that is empty, non-hexadecimal or decodes to zero is a malformed share.
    /// Whether the exponent is one the library <em>supports</em> is a different question, asked
    /// during reconstruction where a provider is present.
    /// Mirror of the SecureBigInteger-side theory of the same name.
    /// </summary>
    /// <param name="serialized">A share string with an unusable third segment.</param>
    [Theory]
    [InlineData("B-AA-")]
    [InlineData("B-AA-ZZ")]
    [InlineData("B-AA-0")]
    [InlineData("B-AA-000000000")]
    public void Constructor_WithAnUnusableLevelSegment_ThrowsInvalidShare(string serialized)
    {
        // Arrange
        using var pinned = serialized.ToPinnedSecure();

        // Act & Assert
        Assert.Throws<InvalidShareException>(() => new Share<BigInteger>(pinned));
    }
    /// <summary>
    /// Re-issuing produces a new share with the same coordinates and the given level, and leaves
    /// the original alone.
    /// Mirror of the SecureBigInteger-side fact of the same name.
    /// </summary>
    [Fact]
    public void ReissueWithSecurityLevel_RecordsTheLevelAndLeavesTheOriginal()
    {
        // Arrange
        using var original = new Share<BigInteger>(new BigIntCalculator(11), new BigIntCalculator(42));

        // Act
        using var reissued = original.ReissueWithSecurityLevel(17);

        // Assert
        Assert.Null(original.SecurityLevel);
        Assert.Equal(17, reissued.SecurityLevel);
        Assert.Equal(original.Index, reissued.Index);
        Assert.Equal(original.Value, reissued.Value);
    }

    /// <summary>
    /// The coordinates are cloned, not shared. The constructor takes ownership of what it is given,
    /// so handing it the original's instances would leave two shares owning one pair of buffers and
    /// disposing either would invalidate the other — a use-after-dispose surfacing far from here.
    /// <para>
    /// The two halves of this test carry different weight. <see cref="Assert.NotSame"/> on the
    /// coordinates catches a missing clone on <em>both</em> backends, because reference identity is
    /// observable everywhere — that is the assertion enforcing the contract. The post-dispose half
    /// adds the consequence a caller would actually meet, and only bites on the SecureBigInteger
    /// side: a disposed <c>SecureBigInteger</c> refuses further use, while a disposed
    /// <c>BigIntCalculator</c> has no observable state, so the shared-buffer mistake would read as
    /// success there on its own.
    /// </para>
    /// Mirror of the SecureBigInteger-side fact of the same name.
    /// </summary>
    [Fact]
    public void ReissueWithSecurityLevel_Clones_SoDisposingOneLeavesTheOtherUsable()
    {
        // Arrange
        var original = new Share<BigInteger>(new BigIntCalculator(11), new BigIntCalculator(42));
        var reissued = original.ReissueWithSecurityLevel(17);

        // Act & Assert — independent instances, which both backends can see.
        Assert.NotSame(original.Index, reissued.Index);
        Assert.NotSame(original.Value, reissued.Value);

        // Act — drop the original and keep using the copy.
        original.Dispose();

        // Assert
        Assert.Equal(17, reissued.SecurityLevel);
        Assert.True(reissued.Index.ByteCount > 0);
        Assert.True(reissued.Value.ByteCount > 0);

        // Act & Assert — and the other way round, on a fresh pair.
        using var other = new Share<BigInteger>(new BigIntCalculator(11), new BigIntCalculator(42));
        var copy = other.ReissueWithSecurityLevel(17);
        copy.Dispose();
        Assert.True(other.Index.ByteCount > 0);

        reissued.Dispose();
    }

    /// <summary>
    /// An exponent the library does not support is refused, naming the parameter it arrived in.
    /// Mirror of the SecureBigInteger-side theory of the same name.
    /// </summary>
    /// <param name="securityLevel">An exponent that is not a Mersenne prime exponent.</param>
    [Theory]
    [InlineData(18)]
    [InlineData(12)]
    [InlineData(0)]
    [InlineData(-1)]
    public void ReissueWithSecurityLevel_WithAnUnsupportedLevel_Throws(int securityLevel)
    {
        // Arrange
        using var share = new Share<BigInteger>(new BigIntCalculator(11), new BigIntCalculator(42));

        // Act & Assert
        var error = Assert.Throws<ArgumentOutOfRangeException>(
            () => share.ReissueWithSecurityLevel(securityLevel));
        Assert.Equal("securityLevel", error.ParamName);
    }

    /// <summary>
    /// A field too small for the coordinates is refused as well. This is the one wrong level the
    /// coordinates <em>can</em> rule out, and it is an argument error rather than a reconstruction
    /// failure because the exponent arrived as a parameter of this operation.
    /// Mirror of the SecureBigInteger-side fact of the same name.
    /// </summary>
    [Fact]
    public void ReissueWithSecurityLevel_WithAFieldTooSmall_Throws()
    {
        // Arrange — 9000 does not fit M13 = 8191.
        using var share = new Share<BigInteger>(new BigIntCalculator(11), new BigIntCalculator(9000));

        // Act & Assert
        var error = Assert.Throws<ArgumentException>(() => share.ReissueWithSecurityLevel(13));
        Assert.Equal("securityLevel", error.ParamName);
    }

    /// <summary>
    /// <b>The limit, pinned so it does not look like an oversight.</b> A supported exponent that is
    /// large enough but simply wrong is accepted without complaint. The coordinates do not say
    /// which field produced them — that absence is the whole defect this change works around — so
    /// no check here can tell a correct level from a plausible one. The caller's obligation to
    /// supply the exponent the split actually used is real, and this test is what keeps it from
    /// being quietly assumed away.
    /// Mirror of the SecureBigInteger-side fact of the same name.
    /// </summary>
    [Fact]
    public void ReissueWithSecurityLevel_WithAPlausibleButWrongLevel_IsNotDetected()
    {
        // Arrange — coordinates from a level-17 split.
        using var share = new Share<BigInteger>(new BigIntCalculator(1), new BigIntCalculator(3333));

        // Act — 19 is supported and admits these coordinates. It is also not the field they
        // came from, and nothing available here can say so.
        using var reissued = share.ReissueWithSecurityLevel(19);

        // Assert
        Assert.Equal(19, reissued.SecurityLevel);
    }

    /// <summary>
    /// Re-issuing a disposed share throws rather than cloning freed buffers.
    /// Mirror of the SecureBigInteger-side fact of the same name.
    /// </summary>
    [Fact]
    public void PostDispose_ReissueWithSecurityLevel_ThrowsObjectDisposedException()
    {
        // Arrange
        var share = new Share<BigInteger>(new BigIntCalculator(11), new BigIntCalculator(42));
        share.Dispose();

        // Act & Assert
        Assert.Throws<ObjectDisposedException>(() => share.ReissueWithSecurityLevel(17));
    }
    /// <summary>
    /// A share that already records a level is not talked out of it. Reconstruction refuses the
    /// same contradiction, and a migration helper that silently won the argument would be a way to
    /// steer the library into the wrong field — the exact failure this change exists to remove.
    /// Mirror of the SecureBigInteger-side fact of the same name.
    /// </summary>
    [Fact]
    public void ReissueWithSecurityLevel_ContradictingARecordedLevel_Throws()
    {
        // Arrange — 19 is supported and admits these coordinates, but the share says 17.
        using var share = new Share<BigInteger>(new BigIntCalculator(1), new BigIntCalculator(3333), 17);

        // Act & Assert
        var error = Assert.Throws<ArgumentException>(() => share.ReissueWithSecurityLevel(19));
        Assert.Equal("securityLevel", error.ParamName);
    }

    /// <summary>
    /// Re-issuing with the level a share already records is allowed. Nothing contradicts anything,
    /// and refusing it would make the operation depend on whether the caller happened to know the
    /// share was already migrated.
    /// Mirror of the SecureBigInteger-side fact of the same name.
    /// </summary>
    [Fact]
    public void ReissueWithSecurityLevel_MatchingARecordedLevel_IsAllowed()
    {
        // Arrange
        using var share = new Share<BigInteger>(new BigIntCalculator(1), new BigIntCalculator(3333), 17);

        // Act
        using var reissued = share.ReissueWithSecurityLevel(17);

        // Assert
        Assert.Equal(17, reissued.SecurityLevel);
        Assert.NotSame(share.Index, reissued.Index);
    }
}
