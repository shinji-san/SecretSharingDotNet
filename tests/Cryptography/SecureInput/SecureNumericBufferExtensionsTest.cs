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
using System.Numerics;
using SecretSharingDotNet.Cryptography.SecureArray;
using SecretSharingDotNet.Cryptography.SecureInput;
using Xunit;

public class SecureNumericBufferExtensionsTest
{
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
        Assert.Equal(sizeof(int), pinned.Length);
        for (int i = 0; i < expected.Length; i++)
        {
            Assert.Equal(expected[i], pinned[i]);
        }
    }

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
        Assert.Equal(expected.Length, pinned.Length);
        for (int i = 0; i < expected.Length; i++)
        {
            Assert.Equal(expected[i], pinned[i]);
        }
    }

    [Fact]
    public void ToPinnedSecureBytes_FromBigInteger_RoundTripsThroughBigIntegerCtor()
    {
        // Arrange — random-ish positive value larger than long to cover the multi-limb path.
        BigInteger source = BigInteger.Parse("123456789012345678901234567890");

        // Act
        using var pinned = source.ToPinnedSecureBytes();
        byte[] copy = new byte[pinned.Length];
        for (int i = 0; i < pinned.Length; i++) { copy[i] = pinned[i]; }
        var roundTripped = new BigInteger(copy);

        // Assert
        Assert.Equal(source, roundTripped);
    }

    [Fact]
    public void ToPinnedSecureBytesClearing_FromValidArray_CopiesAllBytesAndWipesSource()
    {
        // Arrange
        byte[] source = { 0xDE, 0xAD, 0xBE, 0xEF };
        byte[] originalCopy = { 0xDE, 0xAD, 0xBE, 0xEF };

        // Act
        using var pinned = source.ToPinnedSecureBytesClearing();

        // Assert — destination matches originals; source is zeroed.
        Assert.Equal(originalCopy.Length, pinned.Length);
        for (int i = 0; i < originalCopy.Length; i++)
        {
            Assert.Equal(originalCopy[i], pinned[i]);
        }

        for (int i = 0; i < source.Length; i++)
        {
            Assert.Equal(0x00, source[i]);
        }
    }

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

    [Fact]
    public void ToPinnedSecureBytesClearing_FromNullArray_ThrowsArgumentNullException()
    {
        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => ((byte[])null).ToPinnedSecureBytesClearing());
    }

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

    [Fact]
    public void ToInt32Unprotected_FromNull_ThrowsArgumentNullException()
    {
        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => ((PinnedPoolArray<byte>)null).ToInt32Unprotected());
    }

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

    [Fact]
    public void ToBigIntegerUnprotected_FromNull_ThrowsArgumentNullException()
    {
        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => ((PinnedPoolArray<byte>)null).ToBigIntegerUnprotected());
    }

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