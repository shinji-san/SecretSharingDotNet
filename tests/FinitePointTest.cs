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

namespace SecretSharingDotNetTest
{
    using SecretSharingDotNet.Cryptography;
    using System.Numerics;
    using Xunit;

    public class FinitePointTest
    {
        private const string FinitePointTextRepresentation1 = "01-2929AA3E809003D578AA69B1C3E6F62C517437FEFBAD5BFBB240";
        private const string FinitePointTextRepresentation2 = "02-665C74ED38FDFF095B2FC9319A272A75";

        /// <summary>
        /// Check <see cref="FinitePoint{TNumber}"/> to <see cref="string"/> conversion and vice vera.
        /// </summary>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Performance", "CA1822:MarkMembersAsStatic")]
        [Theory]
        [InlineData(FinitePointTextRepresentation1, FinitePointTextRepresentation1)]
        [InlineData(FinitePointTextRepresentation2, FinitePointTextRepresentation2)]
        public void ToString_FromValidFinitePoint_ReturnsCoordinatesSeparatedWithMinus(string input, string expected)
        {
            // Arrange
            var finitePointUnderTest = new FinitePoint<BigInteger>(input);

            // Act
            string actual = finitePointUnderTest.ToString();

            // Assert
            Assert.Equal(expected, actual);
        }

        [Fact]
        public void CompareTo_BigFinitePointToSmallFinitePoint_ReturnsOne()
        {
            // Arrange
            var finitePointUnder1Test = new FinitePoint<BigInteger>(FinitePointTextRepresentation1);
            var finitePointUnder2Test = new FinitePoint<BigInteger>(FinitePointTextRepresentation2);

            // Act
            int actual = finitePointUnder1Test.CompareTo(finitePointUnder2Test);

            // Assert
            Assert.Equal(1, actual);
        }

        [Fact]
        public void CompareTo_SmallFinitePointToBigFinitePoint_ReturnsMinusOne()
        {
            // Arrange
            var finitePointUnder1Test = new FinitePoint<BigInteger>(FinitePointTextRepresentation1);
            var finitePointUnder2Test = new FinitePoint<BigInteger>(FinitePointTextRepresentation2);

            // Act
            int actual = finitePointUnder2Test.CompareTo(finitePointUnder1Test);

            // Assert
            Assert.Equal(-1, actual);
        }

        [Fact]
        public void CompareTo_FinitePointToSameFinitePoint_ReturnsZero()
        {
            // Arrange
            var finitePointUnderTest = new FinitePoint<BigInteger>(FinitePointTextRepresentation1);

            // Act
            int actual = finitePointUnderTest.CompareTo(finitePointUnderTest);

            // Assert
            Assert.Equal(0, actual);
        }

        [Fact]
        public void Equals_FinitePointToSameFinitePoint_ReturnsTrue()
        {
            // Arrange
            var finitePointUnderTest1 = new FinitePoint<BigInteger>(FinitePointTextRepresentation1);
            var finitePointUnderTest2 = new FinitePoint<BigInteger>(FinitePointTextRepresentation1);

            // Act
            bool actual = finitePointUnderTest1.Equals(finitePointUnderTest2);

            // Assert
            Assert.True(actual);
        }

        [Fact]
        public void Equals_FinitePointToDifferentFinitePoint_ReturnsFalse()
        {
            // Arrange
            var finitePointUnderTest1 = new FinitePoint<BigInteger>(FinitePointTextRepresentation1);
            var finitePointUnderTest2 = new FinitePoint<BigInteger>(FinitePointTextRepresentation2);

            // Act
            bool actual = finitePointUnderTest1.Equals(finitePointUnderTest2);

            // Assert
            Assert.False(actual);
        }

        [Fact]
        public void Equals_FinitePointToNull_ReturnsFalse()
        {
            // Arrange
            var finitePointUnderTest1 = new FinitePoint<BigInteger>(FinitePointTextRepresentation1);

            // Act
            bool actual = finitePointUnderTest1.Equals(null);

            // Assert
            Assert.False(actual);
        }

        [Fact]
        public void Equals_FinitePointToSameFinitePointAsObject_ReturnsTrue()
        {
            // Arrange
            var finitePointUnderTest1 = new FinitePoint<BigInteger>(FinitePointTextRepresentation1);
            object finitePointUnderTest2 = finitePointUnderTest1;

            // Act
            bool actual = finitePointUnderTest1.Equals(finitePointUnderTest2);

            // Assert
            Assert.True(actual);
        }

        [Fact]
        public void Equals_FinitePointToDifferentFinitePointAsObject_ReturnsFalse()
        {
            // Arrange
            var finitePointUnderTest1 = new FinitePoint<BigInteger>(FinitePointTextRepresentation1);
            object finitePointUnderTest2 = new FinitePoint<BigInteger>(FinitePointTextRepresentation2);

            // Act
            bool actual = finitePointUnderTest1.Equals(finitePointUnderTest2);

            // Assert
            Assert.False(actual);
        }
    }
}
