namespace SecretSharingDotNetTest.Cryptography.BigInteger;

using SecretSharingDotNet.Cryptography;
using SecretSharingDotNet.Cryptography.SecureInput;
using SecretSharingDotNet.Math;
using SecretSharingDotNet.Math.Numerics;
using System;
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
    /// <see cref="ArgumentOutOfRangeException"/> — same positivity invariant as the
    /// calculator-based constructor.
    /// </summary>
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

        // Act & Assert
#if DEBUG
        Assert.Equal(expected, share.ToString());
#else
        Assert.Equal(TestData.SecuredValueSentinel, share.ToString());
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
#endif
    }

    /// <summary>
    /// Tests that the pinned-char constructor rejects malformed inputs (here a hyphen-only
    /// separator without valid hex on either side) with <see cref="ArgumentException"/>.
    /// </summary>
    [Fact]
    public void Constructor_InvalidPinnedInput_ShouldThrowArgumentException()
    {
        // Arrange
        using var pinned = "invalid-input".ToPinnedSecure();

        // Act & Assert
        Assert.Throws<ArgumentException>(() => new Share<BigInteger>(pinned));
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
    /// either coordinate with <see cref="ArgumentException"/> — only the lowercase
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
        Assert.Throws<ArgumentException>(() => new Share<BigInteger>(pinned));
    }

    /// <summary>
    /// Tests that the pinned-char constructor rejects non-hex characters after a valid
    /// <c>0x</c> prefix with <see cref="ArgumentException"/>.
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
        Assert.Throws<ArgumentException>(() => new Share<BigInteger>(pinned));
    }

    /// <summary>
    /// Tests that the pinned-char constructor's <see cref="ArgumentException"/> for invalid
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
        var ex = Assert.Throws<ArgumentException>(() => new Share<BigInteger>(pinned));

        // Assert
        Assert.Contains("3", ex.Message);
    }

    /// <summary>
    /// Tests the odd-length branch in the hex-to-calculator decoder: a single-character
    /// coordinate with a non-hex character must throw <see cref="ArgumentException"/>
    /// rather than silently truncating.
    /// </summary>
    [Fact]
    public void Constructor_OddLengthWithInvalidChar_ThrowsArgumentException()
    {
        // Arrange
        // Single-char (odd-length) index with a non-hex character exercises the
        // odd-length branch in DecodeHexToCalculator.
        using var pinned = "Z-01".ToPinnedSecure();

        // Act
        var ex = Assert.Throws<ArgumentException>(() => new Share<BigInteger>(pinned));

        // Assert
        Assert.Contains("0", ex.Message);
    }

    /// <summary>
    /// Tests that the pinned-char constructor rejects a <c>0x</c> prefix followed by no
    /// hex digits at all with <see cref="FormatException"/> — distinguishes "missing
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
        Assert.Throws<FormatException>(() => new Share<BigInteger>(pinned));
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
}