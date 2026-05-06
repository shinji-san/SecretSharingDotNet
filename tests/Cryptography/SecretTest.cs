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
using SecretSharingDotNet.Cryptography.SecureArray;
using SecretSharingDotNet.Cryptography.SecureInput;
using SecretSharingDotNet.Math;
using System;
using System.Collections.Generic;
using System.Numerics;
using System.Text;
using Xunit;

public class SecretTest
{
    /// <summary>
    /// Equal secrets for testing.
    /// </summary>
    public static IEnumerable<object[]> EqualSecrets =>
        new List<object[]>
        {
            new object[]
            {
                new Secret<BigInteger>(Calculator<BigInteger>.Zero), new Secret<BigInteger>(Calculator<BigInteger>.Zero)
            },
            new object[]
            {
                new Secret<BigInteger>(Calculator<BigInteger>.One), new Secret<BigInteger>(Calculator<BigInteger>.One)
            },
            new object[]
            {
                new Secret<BigInteger>(Calculator<BigInteger>.Two), new Secret<BigInteger>(Calculator<BigInteger>.Two)
            }
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
            new object[]
            {
                new Secret<BigInteger>(Calculator<BigInteger>.Zero), new Secret<BigInteger>(Calculator<BigInteger>.One)
            },
            new object[]
            {
                new Secret<BigInteger>(Calculator<BigInteger>.Zero), new Secret<BigInteger>(Calculator<BigInteger>.Two)
            },
            new object[]
            {
                new Secret<BigInteger>(Calculator<BigInteger>.One), new Secret<BigInteger>(Calculator<BigInteger>.Zero)
            },
            new object[]
            {
                new Secret<BigInteger>(Calculator<BigInteger>.One), new Secret<BigInteger>(Calculator<BigInteger>.Two)
            },
            new object[]
            {
                new Secret<BigInteger>(Calculator<BigInteger>.Two), new Secret<BigInteger>(Calculator<BigInteger>.Zero)
            },
            new object[]
            {
                new Secret<BigInteger>(Calculator<BigInteger>.Two), new Secret<BigInteger>(Calculator<BigInteger>.One)
            }
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
            new object[]
            {
                new Secret<BigInteger>(Calculator<BigInteger>.Zero), new Secret<BigInteger>(Calculator<BigInteger>.Zero)
            },
            new object[]
            {
                new Secret<BigInteger>(Calculator<BigInteger>.Zero), new Secret<BigInteger>(Calculator<BigInteger>.One)
            },
            new object[]
            {
                new Secret<BigInteger>(Calculator<BigInteger>.Zero), new Secret<BigInteger>(Calculator<BigInteger>.Two)
            },
            new object[]
            {
                new Secret<BigInteger>(Calculator<BigInteger>.One), new Secret<BigInteger>(Calculator<BigInteger>.One)
            },
            new object[]
            {
                new Secret<BigInteger>(Calculator<BigInteger>.One), new Secret<BigInteger>(Calculator<BigInteger>.Two)
            },
            new object[]
            {
                new Secret<BigInteger>(Calculator<BigInteger>.Two), new Secret<BigInteger>(Calculator<BigInteger>.Two)
            }
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
            new object[]
            {
                new Secret<BigInteger>(Calculator<BigInteger>.One), new Secret<BigInteger>(Calculator<BigInteger>.Zero)
            },
            new object[]
            {
                new Secret<BigInteger>(Calculator<BigInteger>.Two), new Secret<BigInteger>(Calculator<BigInteger>.Zero)
            },
            new object[]
            {
                new Secret<BigInteger>(Calculator<BigInteger>.Two), new Secret<BigInteger>(Calculator<BigInteger>.One)
            },
            new object[] { (BigInteger)20001, (BigInteger)20000 }
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
            new object[]
            {
                new Secret<BigInteger>(Calculator<BigInteger>.Zero), new Secret<BigInteger>(Calculator<BigInteger>.One)
            },
            new object[]
            {
                new Secret<BigInteger>(Calculator<BigInteger>.Zero), new Secret<BigInteger>(Calculator<BigInteger>.Two)
            },
            new object[]
            {
                new Secret<BigInteger>(Calculator<BigInteger>.One), new Secret<BigInteger>(Calculator<BigInteger>.Two)
            }
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
            new object[]
            {
                new Secret<BigInteger>(Calculator<BigInteger>.Zero), new Secret<BigInteger>(Calculator<BigInteger>.Zero)
            },
            new object[]
            {
                new Secret<BigInteger>(Calculator<BigInteger>.One), new Secret<BigInteger>(Calculator<BigInteger>.Zero)
            },
            new object[]
            {
                new Secret<BigInteger>(Calculator<BigInteger>.Two), new Secret<BigInteger>(Calculator<BigInteger>.Zero)
            },
            new object[]
            {
                new Secret<BigInteger>(Calculator<BigInteger>.One), new Secret<BigInteger>(Calculator<BigInteger>.One)
            },
            new object[]
            {
                new Secret<BigInteger>(Calculator<BigInteger>.Two), new Secret<BigInteger>(Calculator<BigInteger>.Zero)
            },
            new object[]
            {
                new Secret<BigInteger>(Calculator<BigInteger>.Two), new Secret<BigInteger>(Calculator<BigInteger>.One)
            },
            new object[]
            {
                new Secret<BigInteger>(Calculator<BigInteger>.Two), new Secret<BigInteger>(Calculator<BigInteger>.Two)
            }
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
        try
        {
            // Arrange, Act & Assert
            Assert.False(left < right);
        }
        finally
        {
            left.Dispose();
            right.Dispose();
        }
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
        try
        {
            // Arrange, Act & Assert
            Assert.True(left >= right);
        }
        finally
        {
            left.Dispose();
            right.Dispose();
        }
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
        try
        {
            // Arrange, Act & Assert
            Assert.False(left >= right);
        }
        finally
        {
            left.Dispose();
            right.Dispose();
        }
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
        try
        {
            // Arrange, Act & Assert
            Assert.True(left > right);
        }
        finally
        {
            left.Dispose();
            right.Dispose();
        }
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
        using var pinnedText = secretText.ToPinnedSecure();
        using var secret = Secret<BigInteger>.FromText(pinnedText);

        // Assert
#if DEBUG
        Assert.Equal(secretText, secret.ToString());
#else
        Assert.Equal("*** Secured Value ***", secret.ToString());
#endif
    }

    /// <summary>
    /// Tests the ToCharArray method of the <see cref="Secret{TNumber}"/> class.
    /// </summary>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Performance", "CA1822:MarkMembersAsStatic")]
    [Fact]
    public void ToCharArray_FromValidSecret_ReturnsSecretAsCharArray()
    {
        // Arrange
        const string secretText = "P&ssw0rd!";
        char[] expectedChars = secretText.ToCharArray();

        // Act
        using var pinnedText = secretText.ToPinnedSecure();
        using var secret = Secret<BigInteger>.FromText(pinnedText);
        using var charArray = secret.ToCharArray();

        // Assert
        Assert.Equal(expectedChars.Length, charArray.Length);
        for (int i = 0; i < expectedChars.Length; i++)
        {
            Assert.Equal(expectedChars[i], charArray[i]);
        }
    }

    /// <summary>
    /// Tests the ToCharArray method of the <see cref="Secret{TNumber}"/> class with an uninitialized (default) secret.
    /// The guard in ToCharArray() triggers when secretNumber is null, i.e. for a default struct value.
    /// </summary>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Performance", "CA1822:MarkMembersAsStatic")]
    [Fact]
    public void ToCharArray_FromDefaultSecret_ReturnsEmptyCharArray()
    {
        // Arrange
        Secret<BigInteger> emptySecret = default;

        // Act
        using var charArray = emptySecret.ToCharArray();

        // Assert
        Assert.Equal(0, charArray.Length);
    }

    /// <summary>
    /// Tests that <see cref="Secret{TNumber}.ToCharArray()"/> throws
    /// <see cref="ObjectDisposedException"/> after the secret has been disposed.
    /// </summary>
    [Fact]
    public void ToCharArray_AfterDispose_ThrowsObjectDisposedException()
    {
        // Arrange
        const string secretText = "P&ssw0rd!";
        using var pinnedText = secretText.ToPinnedSecure();
        var secret = Secret<BigInteger>.FromText(pinnedText);
        secret.Dispose();

        // Act & Assert
        Assert.Throws<ObjectDisposedException>(secret.ToCharArray);
    }

    /// <summary>
    /// Tests that <see cref="Secret{TNumber}.ToCharArray(Encoding)"/> rejects a
    /// <see langword="null"/> encoding.
    /// </summary>
    [Fact]
    public void ToCharArray_WithNullEncoding_ThrowsArgumentNullException()
    {
        // Arrange
        const string secretText = "P&ssw0rd!";
        using var pinnedText = secretText.ToPinnedSecure();
        using var secret = Secret<BigInteger>.FromText(pinnedText);

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => secret.ToCharArray(null));
    }

    /// <summary>
    /// Tests that <see cref="Secret{TNumber}.ToCharArray(Encoding)"/> roundtrips a non-default
    /// encoding (UTF-16 LE) when the secret was constructed with the matching encoding.
    /// </summary>
    [Fact]
    public void ToCharArray_WithCallerEncoding_RoundTripsThroughFromText()
    {
        // Arrange
        const string secretText = "Roundtrip via UTF-16 LE: Mäxchens Vögel.";
        using var pinnedText = secretText.ToPinnedSecure();
        using var secret = Secret<BigInteger>.FromText(pinnedText, Encoding.Unicode);

        // Act
        using var roundTrip = secret.ToCharArray(Encoding.Unicode);

        // Assert
        Assert.Equal(secretText.Length, roundTrip.Length);
        for (int i = 0; i < secretText.Length; i++)
        {
            Assert.Equal(secretText[i], roundTrip[i]);
        }
    }

    /// <summary>
    /// Tests the ToBase64String method of the <see cref="Secret{TNumber}"/> class.
    /// </summary>
    /// <param name="base64Secret">Secret as base64 string</param>
    [Theory]
    [InlineData("UG9seWZvbiB6d2l0c2NoZXJuZCBhw59lbiBNw6R4Y2hlbnMgVsO2Z2VsIFLDvGJlbiwgSm9naHVydCB1bmQgUXVhcms=")]
    [InlineData("TWFueSBoYW5kcyBtYWtlIGxpZ2h0IHdvcmsu")]
    [InlineData("bGlnaHQgd29yaw==")]
    [InlineData("bGlnaHQgd29yay4=")]
    public void ToBase64String_FromValidSecret_ReturnsSecretAsBase64String(string base64Secret)
    {
        // Arrange
        using var pinnedBase64 = base64Secret.ToPinnedSecure();
        using var secret = Secret<BigInteger>.FromBase64(pinnedBase64);

        // Act
#if DEBUG
        string actualBase64Secret = secret.ToBase64String();

        // Assert
        Assert.Equal(base64Secret, actualBase64Secret);
#else
        // Assert
        Assert.Equal("*** Secured Value ***", secret.ToBase64String());
#endif
    }

    /// <summary>
    /// Tests the ToBase64CharArray method of the <see cref="Secret{TNumber}"/> class.
    /// </summary>
    /// <param name="base64Secret">Secret as base64 string</param>
    [Theory]
    [InlineData("UG9seWZvbiB6d2l0c2NoZXJuZCBhw59lbiBNw6R4Y2hlbnMgVsO2Z2VsIFLDvGJlbiwgSm9naHVydCB1bmQgUXVhcms=")]
    [InlineData("TWFueSBoYW5kcyBtYWtlIGxpZ2h0IHdvcmsu")]
    [InlineData("bGlnaHQgd29yaw==")]
    [InlineData("bGlnaHQgd29yay4=")]
    public void ToBase64CharArray_FromValidSecret_ReturnsSecretAsBase64CharArray(string base64Secret)
    {
        // Arrange
        using var pinnedBase64 = base64Secret.ToPinnedSecure();
        using var secret = Secret<BigInteger>.FromBase64(pinnedBase64);
        char[] expectedChars = base64Secret.ToCharArray();

        // Act
        using var charArray = secret.ToBase64CharArray();

        // Assert
        Assert.Equal(expectedChars.Length, charArray.Length);
        for (int i = 0; i < expectedChars.Length; i++)
        {
            Assert.Equal(expectedChars[i], charArray[i]);
        }
    }

    /// <summary>
    /// Tests the ToBase64CharArray method of the <see cref="Secret{TNumber}"/> class with an uninitialized (default) secret.
    /// </summary>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Performance", "CA1822:MarkMembersAsStatic")]
    [Fact]
    public void ToBase64CharArray_FromDefaultSecret_ReturnsEmptyCharArray()
    {
        // Arrange
        Secret<BigInteger> emptySecret = default;

        // Act
        using var charArray = emptySecret.ToBase64CharArray();

        // Assert
        Assert.Equal(0, charArray.Length);
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
        // Arrange
        Secret<BigInteger> secret;
        try
        {
            // Act & Assert
            switch (secretSource)
            {
                case string password:
                    using (var pinnedPassword = password.ToPinnedSecure())
                    {
                        secret = Secret<BigInteger>.FromText(pinnedPassword);
                    }
                    SecretAssertions.AssertSecretEqualsString(password, secret);
                    break;
                case BigInteger bigNumber:
                    secret = bigNumber;
                    Assert.Equal(bigNumber, (BigInteger)secret);
                    break;
                case int number:
                    secret = (BigInteger)number;
                    Assert.Equal(number, (BigInteger)secret);
                    break;
                case byte[] byteArray:
                    secret = new Secret<BigInteger>(byteArray, byteArray.Length);
                    var pinnedPoolArray = secret.ToByteArray();
                    var countedEqualityComparer = new CountedEqualityComparer<byte>(count: byteArray.Length);
                    Assert.True(pinnedPoolArray.Equals(byteArray, countedEqualityComparer));
                    break;
                case null:
                    return;
            }
        }
        finally
        {
            secret.Dispose();
        }
    }

    /// <summary>
    /// Tests that <see cref="Secret{TNumber}.FromText(PinnedPoolArray{char})"/> roundtrips a
    /// UTF-8 secret correctly via <see cref="Secret{TNumber}.ToCharArray()"/>.
    /// </summary>
    [Fact]
    public void FromText_PinnedPoolArrayChar_RoundTripsViaToCharArray()
    {
        // Arrange
        const string secretText = "P&ssw0rd!";
        using var pinnedText = new PinnedPoolArray<char>(secretText.Length);
        secretText.CopyTo(0, pinnedText.PoolArray, 0, secretText.Length);

        // Act
        using var secret = Secret<BigInteger>.FromText(pinnedText);
        using var roundTrip = secret.ToCharArray();

        // Assert
        Assert.Equal(secretText.Length, roundTrip.Length);
        for (int i = 0; i < secretText.Length; i++)
        {
            Assert.Equal(secretText[i], roundTrip[i]);
        }
    }

    /// <summary>
    /// Tests that <see cref="Secret{TNumber}.FromText(PinnedPoolArray{char})"/> roundtrips
    /// non-ASCII characters (multi-byte UTF-8) without corruption.
    /// </summary>
    [Fact]
    public void FromText_PinnedPoolArrayChar_NonAscii_RoundTrips()
    {
        // Arrange
        const string secretText = "Polyfön zwitschernd aßen Mäxchens Vögel Rüben.";
        using var pinnedText = new PinnedPoolArray<char>(secretText.Length);
        secretText.CopyTo(0, pinnedText.PoolArray, 0, secretText.Length);

        // Act
        using var secret = Secret<BigInteger>.FromText(pinnedText);
        using var roundTrip = secret.ToCharArray();

        // Assert
        Assert.Equal(secretText.Length, roundTrip.Length);
        for (int i = 0; i < secretText.Length; i++)
        {
            Assert.Equal(secretText[i], roundTrip[i]);
        }
    }

    /// <summary>
    /// Tests that <see cref="Secret{TNumber}.FromText(PinnedPoolArray{char}, Encoding)"/>
    /// uses the caller-supplied encoding (here UTF-16 little-endian, distinct from the
    /// UTF-8 default).
    /// </summary>
    [Fact]
    public void FromText_PinnedPoolArrayCharEncoding_UsesCallerEncoding()
    {
        // Arrange
        const string secretText = "Encoding!";
        using var pinnedText = new PinnedPoolArray<char>(secretText.Length);
        secretText.CopyTo(0, pinnedText.PoolArray, 0, secretText.Length);
        var encoding = Encoding.Unicode; // UTF-16 LE

        // Act
        using var secret = Secret<BigInteger>.FromText(pinnedText, encoding);
        using var rawBytes = secret.ToByteArray();

        // Assert — bytes must match UTF-16 encoding, not UTF-8.
        byte[] expected = encoding.GetBytes(secretText);
        Assert.Equal(expected.Length, rawBytes.Length);
        for (int i = 0; i < expected.Length; i++)
        {
            Assert.Equal(expected[i], rawBytes[i]);
        }
    }

    /// <summary>
    /// Tests that <see cref="Secret{TNumber}.FromText(PinnedPoolArray{char})"/> does not
    /// consume or disturb the caller-owned input buffer.
    /// </summary>
    [Fact]
    public void FromText_PinnedPoolArrayChar_DoesNotConsumeInput()
    {
        // Arrange
        const string secretText = "OwnedByCaller";
        using var pinnedText = new PinnedPoolArray<char>(secretText.Length);
        secretText.CopyTo(0, pinnedText.PoolArray, 0, secretText.Length);

        // Act
        using (Secret<BigInteger>.FromText(pinnedText))

        // Assert — input buffer remains intact and usable.
        Assert.Equal(secretText.Length, pinnedText.Length);
        for (int i = 0; i < secretText.Length; i++)
        {
            Assert.Equal(secretText[i], pinnedText[i]);
        }
    }

    /// <summary>
    /// Tests that <see cref="Secret{TNumber}.FromText(PinnedPoolArray{char})"/> rejects
    /// <see langword="null"/> input.
    /// </summary>
    [Fact]
    public void FromText_PinnedPoolArrayChar_NullText_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() => Secret<BigInteger>.FromText(null));
    }

    /// <summary>
    /// Tests that <see cref="Secret{TNumber}.FromText(PinnedPoolArray{char}, Encoding)"/>
    /// rejects a <see langword="null"/> encoding.
    /// </summary>
    [Fact]
    public void FromText_PinnedPoolArrayCharEncoding_NullEncoding_ThrowsArgumentNullException()
    {
        // Arrange
        using var pinnedText = new PinnedPoolArray<char>(1);
        pinnedText.PoolArray[0] = 'X';

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => Secret<BigInteger>.FromText(pinnedText, null));
    }

    /// <summary>
    /// Tests that <see cref="Secret{TNumber}.FromText(PinnedPoolArray{char})"/> rejects a
    /// buffer of length zero.
    /// </summary>
    [Fact]
    public void FromText_PinnedPoolArrayChar_EmptyText_ThrowsArgumentException()
    {
        // Arrange
        using var pinnedText = new PinnedPoolArray<char>(0);

        // Act & Assert
        Assert.Throws<ArgumentException>(() => Secret<BigInteger>.FromText(pinnedText));
    }

    /// <summary>
    /// Tests that <see cref="Secret{TNumber}.FromText(PinnedPoolArray{char})"/> propagates
    /// <see cref="ObjectDisposedException"/> when the input buffer has already been disposed.
    /// </summary>
    [Fact]
    public void FromText_PinnedPoolArrayChar_DisposedText_ThrowsObjectDisposedException()
    {
        // Arrange
        var pinnedText = new PinnedPoolArray<char>(4);
        pinnedText.Dispose();

        // Act & Assert
        Assert.Throws<ObjectDisposedException>(() => Secret<BigInteger>.FromText(pinnedText));
    }

    [Theory]
    [InlineData("UG9seWZvbiB6d2l0c2NoZXJuZCBhw59lbiBNw6R4Y2hlbnMgVsO2Z2VsIFLDvGJlbiwgSm9naHVydCB1bmQgUXVhcms=")]
    [InlineData("TWFueSBoYW5kcyBtYWtlIGxpZ2h0IHdvcmsu")]
    [InlineData("bGlnaHQgd29yaw==")]
    [InlineData("bGlnaHQgd29yay4=")]
    public void FromBase64_PinnedPoolArrayChar_RoundTripsViaToBase64CharArray(string base64)
    {
        // Arrange
        using var pinnedBase64 = base64.ToPinnedSecure();

        // Act
        using var secret = Secret<BigInteger>.FromBase64(pinnedBase64);
        using var roundTrip = secret.ToBase64CharArray();

        // Assert
        Assert.Equal(base64.Length, roundTrip.Length);
        for (int i = 0; i < base64.Length; i++)
        {
            Assert.Equal(base64[i], roundTrip[i]);
        }
    }

    [Fact]
    public void FromBase64_PinnedPoolArrayChar_IgnoresInteriorWhitespace()
    {
        // Arrange — same payload as the bare-string Theory case, but split across "lines"
        // and with miscellaneous whitespace types (LF, CR, space, tab, FF, VT) injected.
        const string raw = "TWFueSBoYW5kcyBtYWtlIGxpZ2h0IHdvcmsu";
        var paddedBuilder = new StringBuilder();
        var whitespaces = new[] { "\n", "\r", " ", "\t", "\f", "\v", "\r\n" };
        for (int i = 0; i < raw.Length; i += 4)
        {
            if (i > 0)
            {
                paddedBuilder.Append(whitespaces[(i / 4) % whitespaces.Length]);
            }
            paddedBuilder.Append(raw, i, Math.Min(4, raw.Length - i));
        }
        var padded = paddedBuilder.ToString();
        Assert.Equal(raw.Length, CountNonWhitespace(padded));
        using var pinnedBase64 = padded.ToPinnedSecure();

        // Act
        using var secret = Secret<BigInteger>.FromBase64(pinnedBase64);
        using var roundTrip = secret.ToBase64CharArray();

        // Assert
        Assert.Equal(raw.Length, roundTrip.Length);
        for (int i = 0; i < raw.Length; i++)
        {
            Assert.Equal(raw[i], roundTrip[i]);
        }
    }

    [Fact]
    public void FromBase64_PinnedPoolArrayChar_EquivalentToConvertFromBase64String()
    {
        // Arrange
        // Independent oracle: bytes must match Convert.FromBase64String exactly.
        const string base64 = "UG9seWZvbiB6d2l0c2NoZXJuZCBhw59lbiBNw6R4Y2hlbnMgVsO2Z2VsIFLDvGJlbiwgSm9naHVydCB1bmQgUXVhcms=";
        byte[] expected = Convert.FromBase64String(base64);

        // Act
        using var pinnedBase64 = base64.ToPinnedSecure();
        using var secret = Secret<BigInteger>.FromBase64(pinnedBase64);
        using var bytes = secret.ToByteArray();

        // Assert
        Assert.Equal(expected.Length, bytes.Length);
        for (int i = 0; i < expected.Length; i++)
        {
            Assert.Equal(expected[i], bytes[i]);
        }
    }

    [Fact]
    public void FromBase64_PinnedPoolArrayChar_InvalidChar_ThrowsFormatExceptionWithPosition()
    {
        // Arrange
        // '!' at position 4 is not a Base64 alphabet character.
        const string bad = "ABCD!FGH";
        using var pinnedBase64 = bad.ToPinnedSecure();

        // Act
        var ex = Assert.Throws<FormatException>(() => Secret<BigInteger>.FromBase64(pinnedBase64));

        // Assert
        Assert.Contains("'!'", ex.Message);
        Assert.Contains("4", ex.Message);
    }

    [Fact]
    public void FromBase64_PinnedPoolArrayChar_NotMultipleOfFour_ThrowsFormatException()
    {
        // Arrange
        using var pinnedBase64 = "ABC".ToPinnedSecure();

        // Act & Assert
        Assert.Throws<FormatException>(() => Secret<BigInteger>.FromBase64(pinnedBase64));
    }

    [Fact]
    public void FromBase64_PinnedPoolArrayChar_TooManyPads_ThrowsFormatException()
    {
        // Arrange
        using var pinnedBase64 = "A===".ToPinnedSecure();

        // Act & Assert
        Assert.Throws<FormatException>(() => Secret<BigInteger>.FromBase64(pinnedBase64));
    }

    [Fact]
    public void FromBase64_PinnedPoolArrayChar_NonPadAfterPad_ThrowsFormatException()
    {
        // Arrange
        // 'B' appears after a '=' in the same group.
        using var pinnedBase64 = "A=B=".ToPinnedSecure();

        // Act & Assert
        Assert.Throws<FormatException>(() => Secret<BigInteger>.FromBase64(pinnedBase64));
    }

    [Fact]
    public void FromBase64_PinnedPoolArrayChar_OnlyWhitespace_ThrowsArgumentException()
    {
        // Arrange
        using var pinnedBase64 = "   \t\r\n\f\v   ".ToPinnedSecure();

        // Act & Assert
        Assert.Throws<ArgumentException>(() => Secret<BigInteger>.FromBase64(pinnedBase64));
    }

    [Fact]
    public void FromBase64_PinnedPoolArrayChar_EmptyBuffer_ThrowsArgumentException()
    {
        // Arrange
        using var pinnedBase64 = new PinnedPoolArray<char>(0);

        // Act & Assert
        Assert.Throws<ArgumentException>(() => Secret<BigInteger>.FromBase64(pinnedBase64));
    }

    [Fact]
    public void FromBase64_PinnedPoolArrayChar_NullBuffer_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() => Secret<BigInteger>.FromBase64(null));
    }

    [Fact]
    public void FromBase64_PinnedPoolArrayChar_DisposedBuffer_ThrowsObjectDisposedException()
    {
        // Arrange
        var pinnedBase64 = new PinnedPoolArray<char>(4);
        pinnedBase64.Dispose();

        // Act & Assert
        Assert.Throws<ObjectDisposedException>(() => Secret<BigInteger>.FromBase64(pinnedBase64));
    }

    [Fact]
    public void FromBase64_PinnedPoolArrayChar_DoesNotConsumeInput()
    {
        // Arrange
        const string base64 = "TWFueSBoYW5kcyBtYWtlIGxpZ2h0IHdvcmsu";
        using var pinnedBase64 = base64.ToPinnedSecure();

        // Act
        using (Secret<BigInteger>.FromBase64(pinnedBase64))

        // Assert — input buffer must remain intact and usable.
        Assert.Equal(base64.Length, pinnedBase64.Length);
        for (int i = 0; i < base64.Length; i++)
        {
            Assert.Equal(base64[i], pinnedBase64[i]);
        }
    }

    private static int CountNonWhitespace(string s)
    {
        int n = 0;
        foreach (char c in s)
        {
            if (c != ' ' && c != '\t' && c != '\r' && c != '\n' && c != '\f' && c != '\v')
            {
                n++;
            }
        }

        return n;
    }

#if NET8_0_OR_GREATER
    /// <summary>
    /// Tests ReadOnlySpan cast of the <see cref="Secret{TNumber}"/> class.
    /// </summary>
    [Fact]
    public void CastToReadOnlySpan_FromValidSecret_ReturnsSecretAsReadOnlySpan()
    {
        // Arrange
        byte[] bytes = [0x1, 0x2, 0x3, 0x4];
        using var secret = new Secret<BigInteger>(bytes, bytes.Length);

        // Act
        ReadOnlySpan<byte> readOnlySpan = secret;

        // Assert
        Assert.Equal(bytes, readOnlySpan.ToArray());
    }
#endif
}
