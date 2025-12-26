// ----------------------------------------------------------------------------
// <copyright file="FinitePointTest.cs" company="Private">
// Copyright (c) 2023 All Rights Reserved
// </copyright>
// <author>Sebastian Walther</author>
// <date>05/27/2023 06:05:12 PM</date>
// ----------------------------------------------------------------------------

#region License

// ----------------------------------------------------------------------------
// Copyright 2019 Sebastian Walther
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
using System.Globalization;
using System.Numerics;
using Xunit;

public class FinitePointTest
{
    private static readonly FinitePoint<BigInteger> FinitePoint1UnderTest = new(new BigInteger(1),
        BigInteger.Parse("2929AA3E809003D578AA69B1C3E6F62C517437FEFBAD5BFBB240", NumberStyles.HexNumber));

    private static readonly FinitePoint<BigInteger> FinitePoint2UnderTest = new(new BigInteger(2),
        BigInteger.Parse("665C74ED38FDFF095B2FC9319A272A75", NumberStyles.HexNumber));


    [Fact]
    public void Constructor_ValidParameters_PropertiesSetCorrectly()
    {
        // Arrange
        var x = new BigInteger(5);
        var y = BigInteger.Parse("1234567890ABCDEF", NumberStyles.HexNumber);

        // Act
        var finitePoint = new FinitePoint<BigInteger>(x, y);

        // Assert
        Assert.Equal(x, finitePoint.X.Value);
        Assert.Equal(y, finitePoint.Y.Value);
    }

    [Fact]
    public void Constructor_NullX_ThrowsArgumentNullException()
    {
        // Arrange
        BigInteger? x = null;
        var y = BigInteger.Parse("1234567890ABCDEF", NumberStyles.HexNumber);

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => new FinitePoint<BigInteger>(x!, y));
    }

    [Fact]
    public void Constructor_NullY_ThrowsArgumentNullException()
    {
        // Arrange
        var x = new BigInteger(5);
        BigInteger? y = null;

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => new FinitePoint<BigInteger>(x, y!));
    }
    
    [Fact]
    public void ToString_ValidFinitePoint_ReturnsCorrectStringRepresentation()
    {
        // Arrange
#if DEBUG
        const string expectedString = "(BigIntCalculator(1), BigIntCalculator(66145995360161795056928953403445996185990931982120007327527488))";
#else
        const string expectedString = "*** Secured Value ***";
#endif

        // Act
        string actualString = FinitePoint1UnderTest.ToString();

        // Assert
        Assert.Equal(expectedString, actualString);
    }

    [Fact]
    public void CompareTo_BigFinitePointToSmallFinitePoint_ReturnsOne()
    {
        // Arrange & Act
        int actual = FinitePoint1UnderTest.CompareTo(FinitePoint2UnderTest);

        // Assert
        Assert.Equal(1, actual);
    }

    [Fact]
    public void CompareTo_SmallFinitePointToBigFinitePoint_ReturnsMinusOne()
    {
        // Arrange & Act
        int actual = FinitePoint2UnderTest.CompareTo(FinitePoint1UnderTest);

        // Assert
        Assert.Equal(-1, actual);
    }

    [Fact]
    public void CompareTo_FinitePointToSameFinitePoint_ReturnsZero()
    {
        // Arrange & Act
        int actual = FinitePoint1UnderTest.CompareTo(FinitePoint1UnderTest);

        // Assert
        Assert.Equal(0, actual);
    }

    [Fact]
    public void Equals_FinitePointToSameFinitePoint_ReturnsTrue()
    {
        // Arrange & Act
        bool actual = FinitePoint1UnderTest.Equals(FinitePoint1UnderTest);

        // Assert
        Assert.True(actual);
    }

    [Fact]
    public void Equals_FinitePointToDifferentFinitePoint_ReturnsFalse()
    {
        // Arrange & Act
        bool actual = FinitePoint1UnderTest.Equals(FinitePoint2UnderTest);

        // Assert
        Assert.False(actual);
    }

    [Fact]
    public void Equals_FinitePointToNull_ReturnsFalse()
    {
        // Arrange & Act
        bool actual = FinitePoint1UnderTest.Equals(null);

        // Assert
        Assert.False(actual);
    }

    [Fact]
    public void Equals_FinitePointToSameFinitePointAsObject_ReturnsTrue()
    {
        // Arrange
        object finitePointAsObject = FinitePoint1UnderTest;

        // Act
        bool actual = FinitePoint1UnderTest.Equals(finitePointAsObject);

        // Assert
        Assert.True(actual);
    }

    [Fact]
    public void Equals_FinitePointToDifferentFinitePointAsObject_ReturnsFalse()
    {
        // Arrange
        object finitePointAsObject = FinitePoint2UnderTest;

        // Act
        bool actual = FinitePoint1UnderTest.Equals(finitePointAsObject);

        // Assert
        Assert.False(actual);
    }
}