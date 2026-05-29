// ----------------------------------------------------------------------------
// <copyright file="SecureNumericBufferExtensionsTest.cs" company="Private">
// Copyright (c) 2026 All Rights Reserved
// </copyright>
// <author>Sebastian Walther</author>
// <date>05/14/2026</date>
// ----------------------------------------------------------------------------

#region License
// ----------------------------------------------------------------------------
// Copyright 2026 Sebastian Walther
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
#endregion

namespace SecretSharingDotNetTest.Cryptography.SecureInput;

using System;
using System.Linq;
using System.Numerics;
using SecretSharingDotNet.Cryptography.SecureArray;
using SecretSharingDotNet.Cryptography.SecureInput;
using Xunit;

/// <summary>
/// Tests for <see cref="SecureNumericBufferExtensions"/> — the forward
/// (<c>numeric → pinned</c>) and reverse (<c>pinned → numeric</c>) bridge
/// between primitive integer types, <see cref="BigInteger"/>, and
/// <see cref="PinnedPoolArray{Byte}"/>.
/// </summary>
public class SecureNumericBufferExtensionsTest
{
    /// <summary>
    /// Tests that <see cref="SecureNumericBufferExtensions.ToPinnedSecureBytes(int)"/>
    /// produces a fixed 4-byte little-endian encoding, independent of the host's native
    /// endianness. The expected bytes for negative inputs exercise the two's-complement path.
    /// </summary>
    /// <param name="source">The <see cref="int"/> value to encode.</param>
    /// <param name="expected">The expected 4-byte little-endian encoding.</param>
    [Theory]
    [InlineData(0,             new byte[] { 0x00, 0x00, 0x00, 0x00 })]
    [InlineData(1,             new byte[] { 0x01, 0x00, 0x00, 0x00 })]
    [InlineData(42,            new byte[] { 0x2A, 0x00, 0x00, 0x00 })]
    [InlineData(255,           new byte[] { 0xFF, 0x00, 0x00, 0x00 })]
    [InlineData(256,           new byte[] { 0x00, 0x01, 0x00, 0x00 })]
    [InlineData(0x12345678,    new byte[] { 0x78, 0x56, 0x34, 0x12 })]
    [InlineData(int.MaxValue,  new byte[] { 0xFF, 0xFF, 0xFF, 0x7F })]
    [InlineData(-1,            new byte[] { 0xFF, 0xFF, 0xFF, 0xFF })]
    [InlineData(int.MinValue,  new byte[] { 0x00, 0x00, 0x00, 0x80 })]
    public void ToPinnedSecureBytes_FromInt_ProducesFourByteLittleEndianEncoding(int source, byte[] expected)
    {
        // Act
        using var pinned = source.ToPinnedSecureBytes();

        // Assert
        Assert.Equal(expected, pinned.PoolArray.Take(pinned.Length));
    }

    /// <summary>
    /// Tests that <see cref="SecureNumericBufferExtensions.ToPinnedSecureBytes(BigInteger)"/>
    /// returns a single zero byte for <see cref="BigInteger.Zero"/>, matching the BCL's own
    /// <see cref="BigInteger.ToByteArray()"/> convention (zero is encoded as <c>{0x00}</c>,
    /// not as an empty buffer).
    /// </summary>
    [Fact]
    public void ToPinnedSecureBytes_FromBigIntegerZero_ReturnsSingleZeroByte()
    {
        // Arrange — BigInteger.Zero.ToByteArray() returns a single 0x00 byte (not empty).
        BigInteger source = BigInteger.Zero;

        // Act
        using var pinned = source.ToPinnedSecureBytes();

        // Assert
        Assert.Equal(1, pinned.Length);
        Assert.Equal(0x00, pinned[0]);
    }

    /// <summary>
    /// Tests that <see cref="SecureNumericBufferExtensions.ToPinnedSecureBytes(BigInteger)"/>
    /// produces the minimal little-endian two's-complement encoding consistent with
    /// <see cref="BigInteger.ToByteArray()"/>, including the high-byte zero pad that
    /// keeps positive values from being misread as negative (e.g. 128 → <c>{0x80, 0x00}</c>).
    /// </summary>
    /// <param name="sourceLong">The source value as <see cref="long"/> (widened to
    /// <see cref="BigInteger"/> inside the test, since <c>BigInteger</c> is not a valid
    /// <see cref="InlineDataAttribute"/> argument type).</param>
    /// <param name="expected">The expected minimal LE 2c encoding.</param>
    [Theory]
    [InlineData(42,       new byte[] { 0x2A })]
    [InlineData(127,      new byte[] { 0x7F })]
    [InlineData(128,      new byte[] { 0x80, 0x00 })]  // sign byte to keep positive in 2c
    [InlineData(255,      new byte[] { 0xFF, 0x00 })]
    [InlineData(256,      new byte[] { 0x00, 0x01 })]
    [InlineData(-1,       new byte[] { 0xFF })]
    [InlineData(-128,     new byte[] { 0x80 })]
    [InlineData(0xDEADBEEF, new byte[] { 0xEF, 0xBE, 0xAD, 0xDE, 0x00 })]
    public void ToPinnedSecureBytes_FromBigInteger_ProducesMinimalLittleEndianTwosComplement(long sourceLong, byte[] expected)
    {
        // Arrange
        BigInteger source = sourceLong;

        // Act
        using var pinned = source.ToPinnedSecureBytes();

        // Assert
        Assert.Equal(expected, pinned.PoolArray.Take(pinned.Length));
    }

    /// <summary>
    /// Tests that <see cref="SecureNumericBufferExtensions.ToPinnedSecureBytesClearing(byte[])"/>
    /// copies every source byte into a pinned destination and then zeros the source array
    /// in place — the contract that makes this helper safe to call on caller-owned buffers
    /// holding secret material.
    /// </summary>
    [Fact]
    public void ToPinnedSecureBytesClearing_FromValidArray_CopiesAllBytesAndWipesSource()
    {
        // Arrange
        byte[] source = { 0xDE, 0xAD, 0xBE, 0xEF };
        byte[] originalCopy = { 0xDE, 0xAD, 0xBE, 0xEF };

        // Act
        using var pinned = source.ToPinnedSecureBytesClearing();

        // Assert — destination matches originals; source is zeroed.
        Assert.Equal(originalCopy, pinned.PoolArray.Take(pinned.Length));
        Assert.Equal(new byte[originalCopy.Length], source);
    }

    /// <summary>
    /// Tests that <see cref="SecureNumericBufferExtensions.ToPinnedSecureBytesClearing(byte[])"/>
    /// handles an empty source array gracefully — returning a zero-length pinned buffer
    /// without throwing.
    /// </summary>
    [Fact]
    public void ToPinnedSecureBytesClearing_FromEmptyArray_ReturnsEmptyBuffer()
    {
        // Arrange
        byte[] source = new byte[0];

        // Act
        using var pinned = source.ToPinnedSecureBytesClearing();

        // Assert
        Assert.Equal(0, pinned.Length);
    }

    /// <summary>
    /// Tests that <see cref="SecureNumericBufferExtensions.ToPinnedSecureBytesClearing(byte[])"/>
    /// throws <see cref="ArgumentNullException"/> for a <see langword="null"/> source rather
    /// than silently producing a zero-length buffer.
    /// </summary>
    [Fact]
    public void ToPinnedSecureBytesClearing_FromNullArray_ThrowsArgumentNullException()
    {
        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => ((byte[])null).ToPinnedSecureBytesClearing());
    }

    /// <summary>
    /// Tests that the pinned buffer returned by
    /// <see cref="SecureNumericBufferExtensions.ToPinnedSecureBytesClearing(byte[])"/> has
    /// its own backing store independent of the source array — so a post-call mutation of
    /// the source (after the helper has already wiped it) cannot reach the pinned copy.
    /// </summary>
    [Fact]
    public void ToPinnedSecureBytesClearing_FromValidArray_DoesNotShareBackingStore()
    {
        // Arrange — mutating the source array after the call must not affect the pinned copy.
        // Note that the source is wiped by the helper, so we mutate it post-wipe and verify
        // the pinned buffer still holds the original bytes.
        byte[] source = { 0x01, 0x02, 0x03 };

        // Act
        using var pinned = source.ToPinnedSecureBytesClearing();
        source[0] = 0xFF;

        // Assert — pinned reflects the pre-wipe original, not the post-mutation source.
        Assert.Equal(0x01, pinned[0]);
        Assert.Equal(0x02, pinned[1]);
        Assert.Equal(0x03, pinned[2]);
    }

    /// <summary>
    /// Tests that <see cref="SecureNumericBufferExtensions.ToInt32Unprotected"/> decodes a
    /// 4-byte little-endian pinned buffer back into the matching <see cref="int"/> value —
    /// the reverse of the <see cref="ToPinnedSecureBytes_FromInt_ProducesFourByteLittleEndianEncoding"/>
    /// forward direction.
    /// </summary>
    /// <param name="sourceBytes">The LE-encoded source bytes.</param>
    /// <param name="expected">The expected decoded <see cref="int"/>.</param>
    [Theory]
    [InlineData(new byte[] { 0x00, 0x00, 0x00, 0x00 }, 0)]
    [InlineData(new byte[] { 0x01, 0x00, 0x00, 0x00 }, 1)]
    [InlineData(new byte[] { 0x2A, 0x00, 0x00, 0x00 }, 42)]
    [InlineData(new byte[] { 0xFF, 0x00, 0x00, 0x00 }, 255)]
    [InlineData(new byte[] { 0x00, 0x01, 0x00, 0x00 }, 256)]
    [InlineData(new byte[] { 0x78, 0x56, 0x34, 0x12 }, 0x12345678)]
    [InlineData(new byte[] { 0xFF, 0xFF, 0xFF, 0x7F }, int.MaxValue)]
    [InlineData(new byte[] { 0xFF, 0xFF, 0xFF, 0xFF }, -1)]
    [InlineData(new byte[] { 0x00, 0x00, 0x00, 0x80 }, int.MinValue)]
    public void ToInt32Unprotected_FromValidLength4_DecodesLittleEndian(byte[] sourceBytes, int expected)
    {
        // Arrange
        using var source = sourceBytes.ToPinnedSecureBytesClearing();

        // Act
        int actual = source.ToInt32Unprotected();

        // Assert
        Assert.Equal(expected, actual);
    }

    /// <summary>
    /// Tests that <see cref="SecureNumericBufferExtensions.ToInt32Unprotected"/> rejects
    /// any pinned buffer whose length is not exactly 4 with
    /// <see cref="ArgumentException"/> — no implicit padding or truncation.
    /// </summary>
    /// <param name="badLength">A buffer length other than 4.</param>
    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(3)]
    [InlineData(5)]
    [InlineData(8)]
    public void ToInt32Unprotected_FromWrongLength_ThrowsArgumentException(int badLength)
    {
        // Arrange
        using var source = new PinnedPoolArray<byte>(badLength);

        // Act & Assert
        var ex = Assert.Throws<ArgumentException>(() => source.ToInt32Unprotected());
        Assert.Equal("source", ex.ParamName);
    }

    /// <summary>
    /// Tests that <see cref="SecureNumericBufferExtensions.ToInt32Unprotected"/> throws
    /// <see cref="ArgumentNullException"/> for a <see langword="null"/> source.
    /// </summary>
    [Fact]
    public void ToInt32Unprotected_FromNull_ThrowsArgumentNullException()
    {
        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => ((PinnedPoolArray<byte>)null).ToInt32Unprotected());
    }

    /// <summary>
    /// Tests that <see cref="SecureNumericBufferExtensions.ToBigIntegerUnprotected"/> decodes
    /// a little-endian two's-complement pinned buffer back into the matching
    /// <see cref="BigInteger"/> value — the reverse of
    /// <see cref="ToPinnedSecureBytes_FromBigInteger_ProducesMinimalLittleEndianTwosComplement"/>.
    /// </summary>
    /// <param name="sourceBytes">The LE 2c-encoded source bytes.</param>
    /// <param name="expectedLong">The expected decoded value, as <see cref="long"/>
    /// (widened to <see cref="BigInteger"/> inside the test).</param>
    [Theory]
    [InlineData(new byte[] { 0x2A },                         42L)]
    [InlineData(new byte[] { 0x7F },                         127L)]
    [InlineData(new byte[] { 0x80, 0x00 },                   128L)]
    [InlineData(new byte[] { 0xFF, 0x00 },                   255L)]
    [InlineData(new byte[] { 0x00, 0x01 },                   256L)]
    [InlineData(new byte[] { 0xFF },                         -1L)]
    [InlineData(new byte[] { 0x80 },                         -128L)]
    [InlineData(new byte[] { 0xEF, 0xBE, 0xAD, 0xDE, 0x00 }, 0xDEADBEEFL)]
    public void ToBigIntegerUnprotected_FromValidBytes_DecodesLittleEndianTwosComplement(byte[] sourceBytes, long expectedLong)
    {
        // Arrange
        using var source = sourceBytes.ToPinnedSecureBytesClearing();
        BigInteger expected = expectedLong;

        // Act
        BigInteger actual = source.ToBigIntegerUnprotected();

        // Assert
        Assert.Equal(expected, actual);
    }

    /// <summary>
    /// Tests that <see cref="SecureNumericBufferExtensions.ToBigIntegerUnprotected"/> maps
    /// an empty pinned buffer to <see cref="BigInteger.Zero"/> rather than throwing.
    /// </summary>
    [Fact]
    public void ToBigIntegerUnprotected_FromEmptyBuffer_ReturnsZero()
    {
        // Arrange
        using var source = new PinnedPoolArray<byte>(0);

        // Act
        BigInteger actual = source.ToBigIntegerUnprotected();

        // Assert
        Assert.Equal(BigInteger.Zero, actual);
    }

    /// <summary>
    /// Tests that <see cref="SecureNumericBufferExtensions.ToBigIntegerUnprotected"/> throws
    /// <see cref="ArgumentNullException"/> for a <see langword="null"/> source.
    /// </summary>
    [Fact]
    public void ToBigIntegerUnprotected_FromNull_ThrowsArgumentNullException()
    {
        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => ((PinnedPoolArray<byte>)null).ToBigIntegerUnprotected());
    }

    /// <summary>
    /// Tests that <see cref="SecureNumericBufferExtensions.ToPinnedSecureBytes(long)"/>
    /// produces a fixed 8-byte little-endian encoding, mirroring the
    /// <see cref="ToPinnedSecureBytes_FromInt_ProducesFourByteLittleEndianEncoding"/> contract
    /// at 64-bit width. Bridge values across the 32-bit boundary (e.g. <c>int.MaxValue + 1</c>)
    /// confirm the upper half is populated correctly.
    /// </summary>
    /// <param name="source">The <see cref="long"/> value to encode.</param>
    /// <param name="expected">The expected 8-byte little-endian encoding.</param>
    [Theory]
    [InlineData(0L,                  new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 })]
    [InlineData(1L,                  new byte[] { 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 })]
    [InlineData(42L,                 new byte[] { 0x2A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 })]
    [InlineData(0x12345678L,         new byte[] { 0x78, 0x56, 0x34, 0x12, 0x00, 0x00, 0x00, 0x00 })]
    [InlineData((long)int.MaxValue,  new byte[] { 0xFF, 0xFF, 0xFF, 0x7F, 0x00, 0x00, 0x00, 0x00 })]
    [InlineData(1L + int.MaxValue,   new byte[] { 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00 })]
    [InlineData(long.MaxValue,       new byte[] { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F })]
    [InlineData(-1L,                 new byte[] { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF })]
    [InlineData(long.MinValue,       new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80 })]
    public void ToPinnedSecureBytes_FromLong_ProducesEightByteLittleEndianEncoding(long source, byte[] expected)
    {
        // Act
        using var pinned = source.ToPinnedSecureBytes();

        // Assert
        Assert.Equal(expected, pinned.PoolArray.Take(pinned.Length));
    }

    /// <summary>
    /// Tests that <see cref="SecureNumericBufferExtensions.ToInt64Unprotected"/> decodes an
    /// 8-byte little-endian pinned buffer back into the matching <see cref="long"/> value —
    /// the reverse of <see cref="ToPinnedSecureBytes_FromLong_ProducesEightByteLittleEndianEncoding"/>.
    /// </summary>
    /// <param name="sourceBytes">The LE-encoded source bytes.</param>
    /// <param name="expected">The expected decoded <see cref="long"/>.</param>
    [Theory]
    [InlineData(new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, 0L)]
    [InlineData(new byte[] { 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, 1L)]
    [InlineData(new byte[] { 0x2A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, 42L)]
    [InlineData(new byte[] { 0x78, 0x56, 0x34, 0x12, 0x00, 0x00, 0x00, 0x00 }, 0x12345678L)]
    [InlineData(new byte[] { 0xFF, 0xFF, 0xFF, 0x7F, 0x00, 0x00, 0x00, 0x00 }, (long)int.MaxValue)]
    [InlineData(new byte[] { 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00 }, 1L + int.MaxValue)]
    [InlineData(new byte[] { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F }, long.MaxValue)]
    [InlineData(new byte[] { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF }, -1L)]
    [InlineData(new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80 }, long.MinValue)]
    public void ToInt64Unprotected_FromValidLength8_DecodesLittleEndian(byte[] sourceBytes, long expected)
    {
        // Arrange
        using var source = sourceBytes.ToPinnedSecureBytesClearing();

        // Act
        long actual = source.ToInt64Unprotected();

        // Assert
        Assert.Equal(expected, actual);
    }

    /// <summary>
    /// Tests that <see cref="SecureNumericBufferExtensions.ToInt64Unprotected"/> rejects
    /// any pinned buffer whose length is not exactly 8 with
    /// <see cref="ArgumentException"/> — no implicit padding or truncation.
    /// </summary>
    /// <param name="badLength">A buffer length other than 8.</param>
    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(4)]
    [InlineData(7)]
    [InlineData(9)]
    [InlineData(16)]
    public void ToInt64Unprotected_FromWrongLength_ThrowsArgumentException(int badLength)
    {
        // Arrange
        using var source = new PinnedPoolArray<byte>(badLength);

        // Act & Assert
        var ex = Assert.Throws<ArgumentException>(() => source.ToInt64Unprotected());
        Assert.Equal("source", ex.ParamName);
    }

    /// <summary>
    /// Tests that <see cref="SecureNumericBufferExtensions.ToInt64Unprotected"/> throws
    /// <see cref="ArgumentNullException"/> for a <see langword="null"/> source.
    /// </summary>
    [Fact]
    public void ToInt64Unprotected_FromNull_ThrowsArgumentNullException()
    {
        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => ((PinnedPoolArray<byte>)null).ToInt64Unprotected());
    }

    /// <summary>
    /// Tests the forward+reverse round trip for <see cref="long"/>: encoding via
    /// <see cref="SecureNumericBufferExtensions.ToPinnedSecureBytes(long)"/> and then decoding
    /// via <see cref="SecureNumericBufferExtensions.ToInt64Unprotected"/> must yield the
    /// original value, including across the int boundary and at <c>long.Max/MinValue</c>.
    /// </summary>
    /// <param name="value">The source <see cref="long"/> to round-trip.</param>
    [Theory]
    [InlineData(0L)]
    [InlineData(1L)]
    [InlineData(42L)]
    [InlineData(-1L)]
    [InlineData((long)int.MaxValue)]
    [InlineData(1L + int.MaxValue)]
    [InlineData(long.MaxValue)]
    [InlineData(long.MinValue)]
    public void Int64_RoundTripsThroughPinnedBytes(long value)
    {
        // Arrange & Act
        using var pinned = value.ToPinnedSecureBytes();
        long roundTripped = pinned.ToInt64Unprotected();

        // Assert
        Assert.Equal(value, roundTripped);
    }

    /// <summary>
    /// Tests the forward+reverse round trip for <see cref="int"/>: encoding via
    /// <see cref="SecureNumericBufferExtensions.ToPinnedSecureBytes(int)"/> and then decoding
    /// via <see cref="SecureNumericBufferExtensions.ToInt32Unprotected"/> must yield the
    /// original value, including <c>int.Max/MinValue</c>.
    /// </summary>
    /// <param name="value">The source <see cref="int"/> to round-trip.</param>
    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(42)]
    [InlineData(-1)]
    [InlineData(int.MaxValue)]
    [InlineData(int.MinValue)]
    public void Int32_RoundTripsThroughPinnedBytes(int value)
    {
        // Arrange & Act
        using var pinned = value.ToPinnedSecureBytes();
        int roundTripped = pinned.ToInt32Unprotected();

        // Assert
        Assert.Equal(value, roundTripped);
    }

    /// <summary>
    /// Tests the forward+reverse round trip for a large positive <see cref="BigInteger"/>
    /// that exceeds the <see cref="long"/> range — verifying the multi-byte LE 2c path
    /// preserves the value end-to-end.
    /// </summary>
    [Fact]
    public void BigInteger_RoundTripsThroughPinnedBytes_PositiveLarge()
    {
        // Arrange
        BigInteger value = BigInteger.Parse("123456789012345678901234567890");

        // Act
        using var pinned = value.ToPinnedSecureBytes();
        BigInteger roundTripped = pinned.ToBigIntegerUnprotected();

        // Assert
        Assert.Equal(value, roundTripped);
    }

    /// <summary>
    /// Tests the forward+reverse round trip for a large negative <see cref="BigInteger"/>
    /// that exceeds the <see cref="long"/> range — verifying sign propagation through the
    /// LE 2c encoding survives the multi-byte path.
    /// </summary>
    [Fact]
    public void BigInteger_RoundTripsThroughPinnedBytes_NegativeLarge()
    {
        // Arrange
        BigInteger value = BigInteger.Parse("-987654321098765432109876543210");

        // Act
        using var pinned = value.ToPinnedSecureBytes();
        BigInteger roundTripped = pinned.ToBigIntegerUnprotected();

        // Assert
        Assert.Equal(value, roundTripped);
    }
}