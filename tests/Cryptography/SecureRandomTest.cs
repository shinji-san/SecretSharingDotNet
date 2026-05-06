// ----------------------------------------------------------------------------
// <copyright file="SecureRandomTest.cs" company="Private">
// Copyright (c) 2026 All Rights Reserved
// </copyright>
// <author>Sebastian Walther</author>
// <date>05/03/2026 00:00:00 AM</date>
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


namespace SecretSharingDotNetTest.Cryptography;

using SecretSharingDotNet.Cryptography;
using System;
using Xunit;

public class SecureRandomTest
{
    [Fact]
    public void Fill_NullBuffer_ThrowsArgumentNullException()
    {
        // Act & Assert
        var ex = Assert.Throws<ArgumentNullException>(() => SecureRandom.Fill(null!, 0, 0));
        Assert.Equal("buffer", ex.ParamName);
    }

    [Fact]
    public void Fill_NegativeOffset_ThrowsArgumentOutOfRangeException()
    {
        // Arrange
        var buffer = new byte[8];

        // Act & Assert
        var ex = Assert.Throws<ArgumentOutOfRangeException>(() => SecureRandom.Fill(buffer, -1, 0));
        Assert.Equal("offset", ex.ParamName);
    }

    [Fact]
    public void Fill_RangePastEndOfBuffer_ThrowsArgumentOutOfRangeException()
    {
        // Arrange
        var buffer = new byte[8];

        // Act & Assert
        var ex = Assert.Throws<ArgumentOutOfRangeException>(() => SecureRandom.Fill(buffer, 4, 5));
        Assert.Equal("count", ex.ParamName);
    }

    [Fact]
    public void Fill_WritesOnlyTheRequestedRange()
    {
        // Arrange — sentinel-fill the surrounding bytes so we can verify Fill leaves them alone.
        var buffer = new byte[16];
        for (int i = 0; i < buffer.Length; i++)
        {
            buffer[i] = 0xCD;
        }

        // Act
        SecureRandom.Fill(buffer, 4, 8);

        // Assert — bytes outside [4, 12) untouched.
        for (int i = 0; i < 4; i++)
        {
            Assert.Equal((byte)0xCD, buffer[i]);
        }

        for (int i = 12; i < buffer.Length; i++)
        {
            Assert.Equal((byte)0xCD, buffer[i]);
        }
    }

    [Fact]
    public void NextInt32_BoundsInverted_ThrowsArgumentOutOfRangeException()
    {
        // Act & Assert
        var ex = Assert.Throws<ArgumentOutOfRangeException>(() => SecureRandom.NextInt32(10, 5));
        Assert.Equal("toExclusive", ex.ParamName);
    }

    [Fact]
    public void NextInt32_BoundsEqual_ThrowsArgumentOutOfRangeException()
    {
        // Act & Assert
        var ex = Assert.Throws<ArgumentOutOfRangeException>(() => SecureRandom.NextInt32(7, 7));
        Assert.Equal("toExclusive", ex.ParamName);
    }

    [Fact]
    public void NextInt32_StaysWithinRange_TerminationByteSmall()
    {
        // Act & Assert — [1, 32) is the small-mark-byte termination range. Sample many draws
        // and confirm every result lies in the requested range.
        for (int i = 0; i < 1024; i++)
        {
            int value = SecureRandom.NextInt32(1, 32);
            Assert.InRange(value, 1, 31);
        }
    }

    [Fact]
    public void NextInt32_StaysWithinRange_TerminationByteLarge()
    {
        // Act & Assert — [1, 128) is the large-mark-byte termination range.
        for (int i = 0; i < 1024; i++)
        {
            int value = SecureRandom.NextInt32(1, 128);
            Assert.InRange(value, 1, 127);
        }
    }

    [Fact]
    public void NextInt32_SingletonRange_AlwaysReturnsLowerBound()
    {
        // Act & Assert — [42, 43) has exactly one valid result.
        for (int i = 0; i < 16; i++)
        {
            Assert.Equal(42, SecureRandom.NextInt32(42, 43));
        }
    }
}