// ----------------------------------------------------------------------------
// <copyright file="SecretTest.cs" company="Private">
// Copyright (c) 2022 All Rights Reserved
// </copyright>
// <author>Sebastian Walther</author>
// <date>04/20/2019 10:52:28 PM</date>
// ----------------------------------------------------------------------------

#region License
// ----------------------------------------------------------------------------
// Copyright 2022 Sebastian Walther
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
    using SecretSharingDotNet.Math;
    using System.Linq;
    using System.Numerics;
    using Xunit;

    public class SecretTest
    {
        private readonly Secret<BigInteger> one = new Secret<BigInteger>(Calculator<BigInteger>.One);
        private readonly Secret<BigInteger> two = new Secret<BigInteger>(Calculator<BigInteger>.Two);

        [Fact]
        public void TestSecretEqual()
        {
            var s2 = new Secret<BigInteger>(Calculator<BigInteger>.One);
            Secret<BigInteger> leftNull = null;
            Secret<BigInteger> rightNull = null;

            Assert.NotEqual(this.one, this.two);
            Assert.False(this.one == this.two);

            Assert.Equal(this.one, s2);
            Assert.True(this.one == s2);

            Assert.Equal(leftNull, rightNull);
            Assert.True(leftNull == rightNull);

            Assert.NotEqual(leftNull, s2);
            Assert.False(leftNull == s2);

            Assert.NotEqual(s2, rightNull);
            Assert.False(s2 == rightNull);
        }

        [Fact]
        public void TestSecretNotEqual()
        {
            var s2 = new Secret<BigInteger>(Calculator<BigInteger>.Two);
            Secret<BigInteger> leftNull = null;
            Secret<BigInteger> rightNull = null;

            Assert.NotEqual(this.one, s2);
            Assert.True(this.one != s2);

            Assert.False(leftNull != rightNull);

            Assert.NotEqual(this.one, rightNull);
            Assert.True(this.one != rightNull);

            Assert.NotEqual(leftNull, this.one);
            Assert.True(leftNull != this.one);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <remarks>For details see https://docs.microsoft.com/en-us/dotnet/csharp/language-reference/builtin-types/nullable-value-types#sectionToggle4</remarks>
        [Fact]
        public void TestSecretLowerOrEqualThan()
        {
            Secret<BigInteger> leftEqual = this.one;
            Secret<BigInteger> rightEqual = this.one;
            Secret<BigInteger> leftLower = this.one;
            Secret<BigInteger> rightGreater = this.two;
            Secret<BigInteger> leftNull = null;
            Secret<BigInteger> rightNull = null;

            Assert.True(leftEqual <= rightEqual);
            Assert.True(rightEqual <= leftEqual);
            Assert.True(leftLower <= rightGreater);
            Assert.False(rightGreater <= leftLower);
            Assert.False(leftNull <= rightNull);
            Assert.False(leftNull <= rightEqual);
            Assert.False(leftEqual <= rightNull);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <remarks>For details see https://docs.microsoft.com/en-us/dotnet/csharp/language-reference/builtin-types/nullable-value-types#sectionToggle4</remarks>
        [Fact]
        public void TestSecretLowerThan()
        {
            Secret<BigInteger> leftEqual = this.one;
            Secret<BigInteger> rightEqual = this.one;
            Secret<BigInteger> leftLower = this.one;
            Secret<BigInteger> rightGreater = this.two;
            Secret<BigInteger> leftNull = null;
            Secret<BigInteger> rightNull = null;

            Assert.False(leftEqual < rightEqual);
            Assert.False(rightEqual < leftEqual);
            Assert.True(leftLower < rightGreater);
            Assert.False(rightGreater < leftLower);
            Assert.False(leftNull < rightNull);
            Assert.False(leftNull < rightEqual);
            Assert.False(leftEqual < rightNull);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <remarks>For details see https://docs.microsoft.com/en-us/dotnet/csharp/language-reference/builtin-types/nullable-value-types#sectionToggle4</remarks>
        [Fact]
        public void TestSecretGreaterOrEqualThan()
        {
            Secret<BigInteger> leftEqual = this.one;
            Secret<BigInteger> rightEqual = this.one;
            Secret<BigInteger> leftGreater = this.two;
            Secret<BigInteger> rightLower = this.one;
            Secret<BigInteger> leftNull = null;
            Secret<BigInteger> rightNull = null;

            Assert.True(leftEqual >= rightEqual);
            Assert.True(rightEqual >= leftEqual);
            Assert.True(leftGreater >= rightLower);
            Assert.False(rightLower >= leftGreater);
            Assert.False(leftNull >= rightNull);
            Assert.False(leftNull >= rightEqual);
            Assert.False(leftEqual >= rightNull);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <remarks>For details see https://docs.microsoft.com/en-us/dotnet/csharp/language-reference/builtin-types/nullable-value-types#sectionToggle4</remarks>
        [Fact]
        public void TestSecretGreaterThan()
        {
            Secret<BigInteger> leftEqual = this.one;
            Secret<BigInteger> rightEqual = this.one;
            Secret<BigInteger> leftGreater = this.two;
            Secret<BigInteger> rightLower = this.one;
            Secret<BigInteger> leftNull = null;
            Secret<BigInteger> rightNull = null;

            Assert.False(leftEqual > rightEqual);
            Assert.False(rightEqual > leftEqual);
            Assert.True(leftGreater > rightLower);
            Assert.False(rightLower > leftGreater);
            Assert.False(leftNull > rightNull);
            Assert.False(leftNull > rightEqual);
            Assert.False(leftEqual > rightNull);
        }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Performance", "CA1822:MarkMembersAsStatic")]
        [Fact]
        public void TestSecretToString()
        {
            const string secretText = "P&ssw0rd!";
            Secret<BigInteger> secret = secretText;
            Assert.Equal(secretText, secret.ToString());
        }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Performance", "CA1822:MarkMembersAsStatic")]
        [Theory]
        [MemberData(nameof(TestData.MixedSecrets), MemberType = typeof(TestData))]
        public void TestSecretSourceConversion(object secretSource)
        {
            Secret<BigInteger> secret1 = null;
            switch (secretSource)
            {
                case string password:
                    secret1 = password;
                    Assert.Equal(password, secret1);
                    break;
                case BigInteger bigNumber:
                    secret1 = bigNumber;
                    Assert.Equal(bigNumber, (BigInteger)secret1);
                    break;
                case int number:
                    secret1 = (BigInteger)number;
                    Assert.Equal(number, (BigInteger)secret1);
                    break;
                case byte[] bytes1:
                    secret1 = new Secret<BigInteger>(bytes1);
                    byte[] bytes2 = secret1;
                    Assert.True(bytes1.SequenceEqual(bytes2));
                    break;
                case null:
                    return;
            }

            string base64 = secret1?.ToBase64();
            Secret<BigInteger> secret2 = new Secret<BigInteger>(base64);
            Assert.Equal(base64, secret2.ToBase64());
        }
    }
}