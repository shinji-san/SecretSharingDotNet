// ----------------------------------------------------------------------------
// <copyright file="SharesTest.cs" company="Private">
// Copyright (c) 2019 All Rights Reserved
// </copyright>
// <author>Sebastian Walther</author>
// <date>04/20/2019 10:52:28 PM</date>
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
using System.Collections;
using System.Linq;
using System.Numerics;
using Xunit;

/// <summary>
/// Unit test of the <see cref="Shares{TNumber}"/> class.
/// </summary>
public class SharesTest
{
    /// <summary>
    /// Tests the Contains method of the <see cref="Shares{TNumber}"/> class
    /// to verify that it returns true when a specified share exists
    /// within the collection.
    /// </summary>
    /// <param name="index">The index of the share in the predefined shares collection to validate its presence in the collection.</param>
    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    public void Contains_ShareExists_ReturnsTrue(int index)
    {
        // Arrange
        var stringArray = TestData.GetPredefinedShares();
        Shares<BigInteger> sharesCollection = stringArray;

        // Act & Assert
        Assert.Contains(new Share<BigInteger>(TestData.GetPredefinedShares()[index]), sharesCollection);
    }

    /// <summary>
    /// Tests the Contains method of the <see cref="Shares{TNumber}"/> class
    /// to verify that it returns false when a specified share does not exist
    /// within the collection.
    /// </summary>
    [Fact]
    public void Contains_ShareDoesNotExist_ReturnsFalse()
    {
        // Arrange
        var stringArray = TestData.GetPredefinedShares();
        Shares<BigInteger> sharesCollection = stringArray;
        var nonExistingShare = new Share<BigInteger>("4-9999999999999999999999");

        // Act & Assert
        Assert.DoesNotContain(nonExistingShare, sharesCollection);
    }

    /// <summary>
    /// Validates the explicit cast operation from the <see cref="Shares{TNumber}"/> class to a string array.
    /// </summary>
    /// <remarks>
    /// Ensures that the explicit cast produces the expected array of shares in string format,
    /// verifying correctness in transformation.
    /// </remarks>
    [Fact]
    public void ExplicitCastToStringArray_ReturnsExpectedArray()
    {
        // Arrange
        var stringArray = TestData.GetPredefinedShares();
        Shares<BigInteger> shares = stringArray;

        // Act & Assert
        Assert.Equal(TestData.GetPredefinedShares(), (string[])shares);
    }

    /// <summary>
    /// Verifies that the <see cref="Shares{TNumber}.ToString"/> method returns a string representation
    /// that accurately reflects the expected format and content of the shares.
    /// </summary>
    [Fact]
    public void ToString_ReturnsExpectedString()
    {
        // Arrange
        var text = string.Join(Environment.NewLine, TestData.GetPredefinedShares()) + Environment.NewLine;
        Shares<BigInteger> shares = text;

        // Act & Assert
        Assert.Equal(text, shares.ToString());
    }

    /// <summary>
    /// Verifies that the <see cref="Shares{TNumber}"/> class implements the
    /// <see cref="IEnumerable"/> interface correctly and returns an enumerator
    /// that iterates through the collection as expected.
    /// </summary>
    [Fact]
    public void GetEnumerator_ReturnsExpectedEnumerator()
    {
        // Arrange
        Shares<BigInteger> shares = TestData.GetPredefinedShares();
        var testDataSequence = TestData.GetPredefinedShares().Select(entry => new Share<BigInteger>(entry));
        var testDataArray = testDataSequence as Share<BigInteger>[] ?? testDataSequence.ToArray();

        // Act
        var actual = ((IEnumerable)shares).GetEnumerator();
        using var disposable = actual as IDisposable;
        var expected = testDataArray.GetEnumerator();

        // Assert
        for (var i = 0; i < testDataArray.Length; i++)
        {
            Assert.Equal(expected.MoveNext(), actual.MoveNext());
            Assert.Equal(expected.Current, actual.Current);
        }

        Assert.True(shares.SequenceEqual(testDataArray));
    }
    
    [Fact]
    public void Count_ReturnsExpectedCount()
    {
        // Arrange
        Shares<BigInteger> shares = TestData.GetPredefinedShares();
        var expectedCount = TestData.GetPredefinedShares().Length;

        // Act
        var actualCount = shares.Count;

        // Assert
        Assert.Equal(expectedCount, actualCount);
    }

    [Fact]
    public void Indexer_ReturnsExpectedShare()
    {
        // Arrange
        Shares<BigInteger> shares = TestData.GetPredefinedShares();
        var expectedShares = TestData.GetPredefinedShares()
            .Select(entry => new Share<BigInteger>(entry))
            .ToArray();

        // Act & Assert
        for (int i = 0; i < shares.Count; i++)
        {
            Assert.Equal(expectedShares[i], shares[i]);
        }
    }
    
    [Fact]
    public void CopyTo_CopiesSharesToArray()
    {
        // Arrange
        Shares<BigInteger> shares = TestData.GetPredefinedShares();
        var sharesArray = new Share<BigInteger>[shares.Count];
        
        // Act
        shares.CopyTo(sharesArray, 0);
        
        // Assert
        for (int i = 0; i < shares.Count; i++)
        {
            Assert.Equal(shares[i], sharesArray[i]);
        }
    }

    [Fact]
    public void IsReadOnly_ReturnsTrue()
    {
        // Arrange
        Shares<BigInteger> shares = TestData.GetPredefinedShares();

        // Act
        var isReadOnly = shares.IsReadOnly;

        // Assert
        Assert.True(isReadOnly);
    }
    
    [Fact]
    public void Constructor_WithStringArray_InitializesShares()
    {
        // Arrange
        var stringArray = TestData.GetPredefinedShares();

        // Act
        Shares<BigInteger> shares = stringArray;

        // Assert
        Assert.Equal(stringArray.Length, shares.Count);
        for (int i = 0; i < stringArray.Length; i++)
        {
            Assert.Equal(new Share<BigInteger>(stringArray[i]), shares[i]);
        }
    }
    
    [Fact]
    public void AscendingOrder_WithStringArray_SortsSharesByIndex()
    {
        // Arrange
        var stringArray = new[]
        {
            "3-300",
            "1-100",
            "2-200"
        };

        // Act
        Shares<BigInteger> sortedShares = stringArray;

        // Assert
        Assert.Equal(new Share<BigInteger>("1-100"), sortedShares[0]);
        Assert.Equal(new Share<BigInteger>("2-200"), sortedShares[1]);
        Assert.Equal(new Share<BigInteger>("3-300"), sortedShares[2]);
    }
    
    [Fact]
    public void AscendingOrder_WithStringInput_SortsSharesByIndex()
    {
        // Arrange
        var input =
            "3-300" + Environment.NewLine +
            "1-100" + Environment.NewLine +
            "2-200";

        // Act
        Shares<BigInteger> sortedShares = input;

        // Assert
        Assert.Equal(new Share<BigInteger>("1-100"), sortedShares[0]);
        Assert.Equal(new Share<BigInteger>("2-200"), sortedShares[1]);
        Assert.Equal(new Share<BigInteger>("3-300"), sortedShares[2]);
    }
}