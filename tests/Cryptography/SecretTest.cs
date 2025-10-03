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

namespace SecretSharingDotNetTest.Cryptography;

using SecretSharingDotNet.Cryptography;
using SecretSharingDotNet.Math;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using Xunit;

public class SecretTest
{
    private static readonly Secret<BigInteger> Zero = new Secret<BigInteger>(Calculator<BigInteger>.Zero);
    private static readonly Secret<BigInteger> One = new Secret<BigInteger>(Calculator<BigInteger>.One);
    private static readonly Secret<BigInteger> Two = new Secret<BigInteger>(Calculator<BigInteger>.Two);
        
    /// <summary>
    /// Equal secrets for testing.
    /// </summary>
    public static IEnumerable<object[]> EqualSecrets =>
        new List<object[]>
        {
            new object[] { Zero, Zero},
            new object[] { Zero, new Secret<BigInteger>(Calculator<BigInteger>.Zero)},
            new object[] { One, One},
            new object[] { One, new Secret<BigInteger>(Calculator<BigInteger>.One)},
            new object[] { Two, Two},
            new object[] { Two, new Secret<BigInteger>(Calculator<BigInteger>.Two)},
        };

    /// <summary>
    ///  Tests the equality of two <see cref="Secret{TNumber}"/> objects with
    ///  the <see cref="Secret{TNumber}.Equals(object)"/> method.
    /// </summary>
    /// <param name="left">left secret</param>
    /// <param name="right">right secret</param>
    [Theory]
    [MemberData(nameof(EqualSecrets), MemberType = typeof(SecretTest))]
    public void Equal_WithEqualSecrets_ReturnsTrue(Secret<BigInteger> left, Secret<BigInteger> right)
    {
        // Arrange, Act & Assert
        Assert.True(left.Equals(right));
    }

    /// <summary>
    /// Tests the equality of two <see cref="Secret{TNumber}"/> objects with the equal operator.
    /// </summary>
    /// <param name="left">left secret</param>
    /// <param name="right">right secret</param>
    [Theory]
    [MemberData(nameof(EqualSecrets), MemberType = typeof(SecretTest))]
    public void EqualOperator_WithEqualSecrets_ReturnsTrue(Secret<BigInteger> left, Secret<BigInteger> right)
    {
        // Arrange, Act & Assert
        Assert.True(left == right);
    }

    /// <summary>
    /// Not equal secrets for testing.
    /// </summary>
    public static IEnumerable<object[]> NotEqualSecrets =>
        new List<object[]>
        {
            new object[] { Zero, One},
            new object[] { Zero, Two},
            new object[] { Zero, new Secret<BigInteger>(Calculator<BigInteger>.One)},
            new object[] { Zero, new Secret<BigInteger>(Calculator<BigInteger>.Two)},
            new object[] { One, Zero},
            new object[] { One, Two},
            new object[] { One, new Secret<BigInteger>(Calculator<BigInteger>.Zero)},
            new object[] { One, new Secret<BigInteger>(Calculator<BigInteger>.Two)},
            new object[] { Two, Zero},
            new object[] { Two, One},
            new object[] { Two, new Secret<BigInteger>(Calculator<BigInteger>.Zero)},
            new object[] { Two, new Secret<BigInteger>(Calculator<BigInteger>.One)},
        };

    /// <summary>
    /// Tests the inequality of two <see cref="Secret{TNumber}"/> objects with
    /// the <see cref="Secret{TNumber}.Equals(object)"/> method.
    /// </summary>
    /// <param name="left">left secret</param>
    /// <param name="right">right secret</param>
    [Theory]
    [MemberData(nameof(NotEqualSecrets), MemberType = typeof(SecretTest))]
    public void Equal_WithNotEqualSecrets_ReturnsFalse(Secret<BigInteger> left, Secret<BigInteger> right)
    {
        // Arrange, Act & Assert
        Assert.False(left.Equals(right));
    }

    /// <summary>
    /// Tests the inequality of two <see cref="Secret{TNumber}"/> objects with the equal operator.
    /// </summary>
    /// <param name="left">left secret</param>
    /// <param name="right">right secret</param>
    [Theory]
    [MemberData(nameof(NotEqualSecrets), MemberType = typeof(SecretTest))]
    public void NotEqualOperator_WithNotEqualSecrets_ReturnsTrue(Secret<BigInteger> left, Secret<BigInteger> right)
    {
        // Arrange, Act & Assert
        Assert.True(left != right);
    }

    /// <summary>
    /// Lower or equal than secrets for testing.
    /// </summary>
    public static IEnumerable<object[]> LowerOrEqualThanSecrets =>
        new List<object[]>
        {
            new object[] { Zero, Zero},
            new object[] { Zero, One},
            new object[] { Zero, Two},
            new object[] { Zero, new Secret<BigInteger>(Calculator<BigInteger>.Zero)},
            new object[] { Zero, new Secret<BigInteger>(Calculator<BigInteger>.One)},
            new object[] { Zero, new Secret<BigInteger>(Calculator<BigInteger>.Two)},
            new object[] { One, One},
            new object[] { One, Two},
            new object[] { One, new Secret<BigInteger>(Calculator<BigInteger>.One)},
            new object[] { One, new Secret<BigInteger>(Calculator<BigInteger>.Two)},
            new object[] { Two, Two},
            new object[] { Two, new Secret<BigInteger>(Calculator<BigInteger>.Two)},
        };

    /// <summary>
    /// Tests the lower or equal than operator with lower or equal than secrets. 
    /// </summary>
    /// <param name="left">left secret</param>
    /// <param name="right">right secret</param>
    [Theory]
    [MemberData(nameof(LowerOrEqualThanSecrets), MemberType = typeof(SecretTest))]
    public void LowerOrEqualThanOperator_WithLowerOrEqualThanSecrets_ReturnsTrue(
        Secret<BigInteger> left,
        Secret<BigInteger> right)
    {
        // Arrange, Act & Assert
        Assert.True(left <= right);
    }

    /// <summary>
    /// Greater than secrets for testing.
    /// </summary>
    public static IEnumerable<object[]> GreaterThanSecrets =>
        new List<object[]>
        {
            new object[] { One, Zero},
            new object[] { Two, Zero},
            new object[] { Two, One},
            new object[] { One, new Secret<BigInteger>(Calculator<BigInteger>.Zero)},
            new object[] { Two, new Secret<BigInteger>(Calculator<BigInteger>.Zero)},
            new object[] { Two, new Secret<BigInteger>(Calculator<BigInteger>.One)},
            new object[] { (BigInteger)20001, (BigInteger)20000},
        };

    /// <summary>
    /// Tests the lower or equal than operator with greater than secrets.
    /// </summary>
    /// <param name="left">left secret</param>
    /// <param name="right">right secret</param>
    [Theory]
    [MemberData(nameof(GreaterThanSecrets), MemberType = typeof(SecretTest))]
    public void LowerOrEqualThanOperator_WithGreaterThanSecrets_ReturnsFalse(
        Secret<BigInteger> left,
        Secret<BigInteger> right)
    {
        // Arrange, Act & Assert
        Assert.False(left <= right);
    }

    /// <summary>
    /// Lower than secrets for testing.
    /// </summary>
    public static IEnumerable<object[]> LowerThanSecrets =>
        new List<object[]>
        {
            new object[] { Zero, One},
            new object[] { Zero, Two},
            new object[] { Zero, new Secret<BigInteger>(Calculator<BigInteger>.One)},
            new object[] { Zero, new Secret<BigInteger>(Calculator<BigInteger>.Two)},
            new object[] { One, Two},
            new object[] { One, new Secret<BigInteger>(Calculator<BigInteger>.Two)},
        };

    /// <summary>
    /// Lower than operator with lower than secrets.
    /// </summary>
    /// <param name="left">left secret</param>
    /// <param name="right">right secret</param>
    [Theory]
    [MemberData(nameof(LowerThanSecrets), MemberType = typeof(SecretTest))]
    public void LowerThanOperator_WithLowerThanSecrets_ReturnsTrue(
        Secret<BigInteger> left,
        Secret<BigInteger> right)
    {
        // Arrange, Act & Assert
        Assert.True(left < right);
    }

    /// <summary>
    /// Greater or equal than secrets for testing.
    /// </summary>
    public static IEnumerable<object[]> GreaterOrEqualThanSecrets =>
        new List<object[]>
        {
            new object[] { Zero, Zero},
            new object[] { One, Zero},
            new object[] { Two, Zero},
            new object[] { One, One},
            new object[] { Two, One},
            new object[] { Two, Two},
            new object[] { Zero, new Secret<BigInteger>(Calculator<BigInteger>.Zero)},
            new object[] { One, new Secret<BigInteger>(Calculator<BigInteger>.Zero)},
            new object[] { Two, new Secret<BigInteger>(Calculator<BigInteger>.Zero)},
            new object[] { One, new Secret<BigInteger>(Calculator<BigInteger>.One)},
            new object[] { Two, new Secret<BigInteger>(Calculator<BigInteger>.Zero)},
            new object[] { Two, new Secret<BigInteger>(Calculator<BigInteger>.One)},
            new object[] { Two, new Secret<BigInteger>(Calculator<BigInteger>.Two)},
        };

    /// <summary>
    /// Tests the lower than operator with greater or equal than secrets.
    /// </summary>
    /// <param name="left">left secret</param>
    /// <param name="right">right secret</param>
    [Theory]
    [MemberData(nameof(GreaterOrEqualThanSecrets), MemberType = typeof(SecretTest))]
    public void LowerThanOperator_WithGreaterOrEqualThanSecrets_ReturnsFalse(
        Secret<BigInteger> left,
        Secret<BigInteger> right)
    {
        // Arrange, Act & Assert
        Assert.False(left < right);
    }

    /// <summary>
    /// Tests the greater or equal than operator with greater or equal than secrets.
    /// </summary>
    /// <param name="left">left secret</param>
    /// <param name="right">right secret</param>
    [Theory]
    [MemberData(nameof(GreaterOrEqualThanSecrets), MemberType = typeof(SecretTest))]
    public void GreaterOrEqualThanOperator_WithGreaterOrEqualThanSecrets_ReturnsTrue(
        Secret<BigInteger> left,
        Secret<BigInteger> right)
    {
        // Arrange, Act & Assert
        Assert.True(left >= right);
    }

    /// <summary>
    /// Tests the greater or equal than operator with lower than secrets. 
    /// </summary>
    /// <param name="left">left secret</param>
    /// <param name="right">right secret</param>
    [Theory]
    [MemberData(nameof(LowerThanSecrets), MemberType = typeof(SecretTest))]
    public void GreaterOrEqualThanOperator_WithLowerThanSecrets_ReturnsFalse(
        Secret<BigInteger> left,
        Secret<BigInteger> right)
    {
        // Arrange, Act & Assert
        Assert.False(left >= right);
    }

    /// <summary>
    /// Tests the greater than operator with greater than secrets.
    /// </summary>
    /// <param name="left">left secret</param>
    /// <param name="right">right secret</param>
    [Theory]
    [MemberData(nameof(GreaterThanSecrets), MemberType = typeof(SecretTest))]
    public void GreaterThanOperator_WithGreaterThanSecrets_ReturnsTrue(
        Secret<BigInteger> left,
        Secret<BigInteger> right)
    {
        // Arrange, Act & Assert
        Assert.True(left > right);
    }

    /// <summary>
    /// Tests the ToString method of the <see cref="Secret{TNumber}"/> class.
    /// </summary>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Performance", "CA1822:MarkMembersAsStatic")]
    [Fact]
    public void ToString_FromValidSecret_ReturnsSecretAsString()
    {
        // Arrange
        const string secretText = "P&ssw0rd!";

        // Act
        Secret<BigInteger> secret = secretText;

        // Assert
        Assert.Equal(secretText, secret.ToString());
    }

    /// <summary>
    /// Tests the ToBase64 method of the <see cref="Secret{TNumber}"/> class.
    /// </summary>
    /// <param name="base64Secret">Secret as base64 string</param>
    [Theory]
    [InlineData("UG9seWZvbiB6d2l0c2NoZXJuZCBhw59lbiBNw6R4Y2hlbnMgVsO2Z2VsIFLDvGJlbiwgSm9naHVydCB1bmQgUXVhcms=")]
    [InlineData("TWFueSBoYW5kcyBtYWtlIGxpZ2h0IHdvcmsu")]
    [InlineData("bGlnaHQgd29yaw==")]
    [InlineData("bGlnaHQgd29yay4=")]
    public void ToBase64_FromValidSecret_ReturnsSecretAsBase64String(string base64Secret)
    {
        // Arrange
        var secret = new Secret<BigInteger>(base64Secret);

        // Act
        string actualBase64Secret = secret.ToBase64();

        // Assert
        Assert.Equal(base64Secret, actualBase64Secret);
    }

    /// <summary>
    /// Tests the cast of the <see cref="Secret{TNumber}"/> class.
    /// </summary>
    /// <param name="secretSource">Secret as string, BigInteger, int or byte array</param>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Performance", "CA1822:MarkMembersAsStatic")]
    [Theory]
    [MemberData(nameof(TestData.MixedSecrets), MemberType = typeof(TestData))]
    public void CastObjectToSecret_FromSupportedType_ReturnsSecret(object secretSource)
    {
        Secret<BigInteger> secret;
        switch (secretSource)
        {
            case string password:
                secret = password;
                Assert.Equal(password, secret);
                break;
            case BigInteger bigNumber:
                secret = bigNumber;
                Assert.Equal(bigNumber, (BigInteger)secret);
                break;
            case int number:
                secret = (BigInteger)number;
                Assert.Equal(number, (BigInteger)secret);
                break;
            case byte[] bytes1:
                secret = new Secret<BigInteger>(bytes1);
                byte[] bytes2 = secret;
                Assert.True(bytes1.SequenceEqual(bytes2));
                break;
            case null:
                return;
        }
    }

#if NET6_0_OR_GREATER
    /// <summary>
    /// Tests ReadOnlySpan cast of the <see cref="Secret{TNumber}"/> class.
    /// </summary>
    [Fact]
    public void CastToReadOnlySpan_FromValidSecret_ReturnsSecretAsReadOnlySpan()
    {
        // Arrange
        byte[] bytes = [0x1, 0x2, 0x3, 0x4];
        var secret = new Secret<BigInteger>(bytes);

        // Act
        ReadOnlySpan<byte> readOnlySpan = secret;

        // Assert
        Assert.Equal(bytes, readOnlySpan.ToArray());
    }
#endif
}
