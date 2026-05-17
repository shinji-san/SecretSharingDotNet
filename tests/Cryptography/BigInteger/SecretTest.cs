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

namespace SecretSharingDotNetTest.Cryptography.BigInteger;

using SecretSharingDotNet.Cryptography;
using SecretSharingDotNet.Cryptography.SecureArray;
using SecretSharingDotNet.Cryptography.SecureInput;
using SecretSharingDotNet.Math;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Reflection;
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
        try
        {
            // Arrange, Act & Assert
            Assert.True(left.Equals(right));
        }
        finally
        {
            left.Dispose();
            right.Dispose();
        }
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
        try
        {
            // Arrange, Act & Assert
            Assert.True(left == right);
        }
        finally
        {
            left.Dispose();
            right.Dispose();
        }
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
        try
        {
            // Arrange, Act & Assert
            Assert.False(left.Equals(right));
        }
        finally
        {
            left.Dispose();
            right.Dispose();
        }
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
        try
        {
            // Arrange, Act & Assert
            Assert.True(left != right);
        }
        finally
        {
            left.Dispose();
            right.Dispose();
        }
    }

    /// <summary>
    /// Tests that <see cref="Secret{TNumber}.Equals(object)"/> returns
    /// <see langword="false"/> when the argument is not a
    /// <see cref="Secret{TNumber}"/> instance, instead of throwing
    /// <see cref="InvalidCastException"/>.
    /// </summary>
    [Fact]
    public void Equal_WithObjectOfDifferentType_ReturnsFalse()
    {
        // Arrange
        var secret = new Secret<BigInteger>(Calculator<BigInteger>.One);
        try
        {
            // Act
            bool result = secret.Equals((object)"not a secret");

            // Assert
            Assert.False(result);
        }
        finally
        {
            secret.Dispose();
        }
    }

    /// <summary>
    /// Tests that <see cref="Secret{TNumber}.Equals(object)"/> returns
    /// <see langword="false"/> when the argument is <see langword="null"/>.
    /// </summary>
    [Fact]
    public void Equal_WithNullObject_ReturnsFalse()
    {
        // Arrange
        var secret = new Secret<BigInteger>(Calculator<BigInteger>.One);
        try
        {
            // Act
            bool result = secret.Equals((object)null);

            // Assert
            Assert.False(result);
        }
        finally
        {
            secret.Dispose();
        }
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
        try
        {
            // Arrange, Act & Assert
            Assert.True(left <= right);
        }
        finally
        {
            left.Dispose();
            right.Dispose();
        }
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
        try
        {
            // Arrange, Act & Assert
            Assert.False(left <= right);
        }
        finally
        {
            left.Dispose();
            right.Dispose();
        }
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
        try
        {
            // Arrange, Act & Assert
            Assert.True(left < right);
        }
        finally
        {
            left.Dispose();
            right.Dispose();
        }
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
        Assert.Equal(TestData.SecuredValueSentinel, secret.ToString());
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
        Assert.Equal(expectedChars, charArray.PoolArray.Take(charArray.Length));
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
    /// <see cref="ObjectDisposedException"/> after the secret has been disposed,
    /// and that the exception's <see cref="ObjectDisposedException.ObjectName"/>
    /// reports the <c>Secret</c> wrapper type — not the underlying
    /// <c>PinnedPoolArray</c>. The Secret-level <c>ThrowIfDisposed</c> guard runs
    /// before the dereference, translating the buffer's disposed state into a
    /// wrapper-named exception for caller-facing diagnostics.
    /// </summary>
    [Fact]
    public void ToCharArray_AfterDispose_ThrowsObjectDisposedException()
    {
        // Arrange
        const string secretText = "P&ssw0rd!";
        using var pinnedText = secretText.ToPinnedSecure();
        var secret = Secret<BigInteger>.FromText(pinnedText);
        secret.Dispose();

        // Act
        var ex = Assert.Throws<ObjectDisposedException>(secret.ToCharArray);

        // Assert
        Assert.Contains("Secret", ex.ObjectName);
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
        Assert.Equal(secretText, new string(roundTrip.PoolArray, 0, roundTrip.Length));
    }

    /// <summary>
    /// Tests the ToBase64String method of the <see cref="Secret{TNumber}"/> class.
    /// </summary>
    /// <param name="base64Secret">Secret as base64 string</param>
    [Theory]
    [InlineData(TestData.Base64GermanPangram)]
    [InlineData(TestData.Base64SimpleSentence)]
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
        Assert.Equal(TestData.SecuredValueSentinel, secret.ToBase64String());
#endif
    }

    /// <summary>
    /// Tests the ToBase64CharArray method of the <see cref="Secret{TNumber}"/> class.
    /// </summary>
    /// <param name="base64Secret">Secret as base64 string</param>
    [Theory]
    [InlineData(TestData.Base64GermanPangram)]
    [InlineData(TestData.Base64SimpleSentence)]
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
        Assert.Equal(expectedChars, charArray.PoolArray.Take(charArray.Length));
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
    /// Tests that <see cref="Secret{TNumber}.Dispose"/> on a default-constructed
    /// secret (i.e. <see langword="default"/>(Secret&lt;BigInteger&gt;)) is a clean
    /// no-op and idempotent — consistent with ToCharArray / ToBase64CharArray on
    /// a default secret returning empty rather than throwing.
    /// </summary>
    [Fact]
    public void Dispose_OnDefaultSecret_DoesNotThrow()
    {
        // Arrange — default struct: secretNumber is null.
        Secret<BigInteger> emptySecret = default;

        // Act
        var ex = Record.Exception(() =>
        {
            emptySecret.Dispose();
            emptySecret.Dispose();
            emptySecret.Dispose();
        });

        // Assert
        Assert.Null(ex);
    }

    /// <summary>
    /// Regression guard for ultrareview Bug 4: <see cref="Secret{TNumber}.Equals(Secret{TNumber})"/>
    /// on two default-value structs returns <see langword="true"/> rather than dereferencing
    /// the <see langword="null"/> <c>secretNumber</c>.
    /// </summary>
    [Fact]
    public void Equals_BothDefault_ReturnsTrue()
    {
        // Arrange
        Secret<BigInteger> a = default;
        Secret<BigInteger> b = default;

        // Act & Assert
        Assert.True(a.Equals(b));
        Assert.True(a == b);
    }

    /// <summary>
    /// Tests that <see cref="Secret{TNumber}.Equals(Secret{TNumber})"/> between a default
    /// struct and an initialized secret returns <see langword="false"/> (and does not NRE).
    /// </summary>
    [Fact]
    public void Equals_DefaultVsInitialized_ReturnsFalse()
    {
        // Arrange
        Secret<BigInteger> emptySecret = default;
        using var initialized = new Secret<BigInteger>(new byte[] { 1, 2, 3 }, 3);

        // Act & Assert
        Assert.False(emptySecret.Equals(initialized));
        Assert.False(initialized.Equals(emptySecret));
    }

    /// <summary>
    /// Regression guard for ultrareview Bug 4: <see cref="Secret{TNumber}.CompareTo(Secret{TNumber})"/>
    /// on two default-value structs returns <c>0</c> rather than dereferencing
    /// the <see langword="null"/> <c>secretNumber</c>.
    /// </summary>
    [Fact]
    public void CompareTo_BothDefault_ReturnsZero()
    {
        // Arrange
        Secret<BigInteger> a = default;
        Secret<BigInteger> b = default;

        // Act & Assert
        Assert.Equal(0, a.CompareTo(b));
    }

    /// <summary>
    /// Tests that <see cref="Secret{TNumber}.CompareTo(Secret{TNumber})"/> orders the default
    /// struct as smaller than any initialized secret.
    /// </summary>
    [Fact]
    public void CompareTo_DefaultIsSmallerThanInitialized()
    {
        // Arrange
        Secret<BigInteger> emptySecret = default;
        using var initialized = new Secret<BigInteger>(new byte[] { 1, 2, 3 }, 3);

        // Act
        int defaultVsInit = emptySecret.CompareTo(initialized);
        int initVsDefault = initialized.CompareTo(emptySecret);

        // Assert
        Assert.True(defaultVsInit < 0);
        Assert.True(initVsDefault > 0);
    }

    /// <summary>
    /// Regression guard for ultrareview Bug 4: <see cref="Secret{TNumber}.GetHashCode"/>
    /// on a default-value struct returns a defined value rather than NRE on the
    /// <see langword="null"/> <c>secretNumber</c>.
    /// </summary>
    [Fact]
    public void GetHashCode_OnDefaultSecret_DoesNotThrow()
    {
        // Arrange
        Secret<BigInteger> emptySecret = default;

        // Act
        var ex = Record.Exception(() => _ = emptySecret.GetHashCode());

        // Assert
        Assert.Null(ex);
    }

    /// <summary>
    /// Regression guard for ultrareview Bug 4: <see cref="Secret{TNumber}.ToByteArray"/>
    /// on a default-value struct returns an empty <see cref="PinnedPoolArray{Byte}"/>
    /// rather than NRE-ing on the <see langword="null"/> <c>secretNumber</c>. Without
    /// the guard the implicit <c>Secret &#x2192; PinnedPoolArray&lt;byte&gt;</c> operator
    /// (which routes through <c>ToByteArray</c>) would also NRE for default-struct inputs.
    /// </summary>
    [Fact]
    public void ToByteArray_FromDefaultSecret_ReturnsEmptyByteArray()
    {
        // Arrange
        Secret<BigInteger> emptySecret = default;

        // Act
        using var bytes = emptySecret.ToByteArray();

        // Assert
        Assert.Equal(0, bytes.Length);
    }

#if NET8_0_OR_GREATER
    /// <summary>
    /// Regression guard for ultrareview Bug 4: <see cref="Secret{TNumber}.AsReadOnlySpan"/>
    /// on a default-value struct returns <see cref="ReadOnlySpan{Byte}.Empty"/> rather than
    /// NRE-ing on the <see langword="null"/> <c>secretNumber</c>. This also closes the
    /// implicit <c>Secret &#x2192; ReadOnlySpan&lt;byte&gt;</c> operator's cascading-NRE
    /// path for default-struct inputs on NET 8+.
    /// </summary>
    [Fact]
    public void AsReadOnlySpan_FromDefaultSecret_ReturnsEmpty()
    {
        // Arrange
        Secret<BigInteger> emptySecret = default;

        // Act
        var span = emptySecret.AsReadOnlySpan();

        // Assert
        Assert.True(span.IsEmpty);
    }
#endif

    /// <summary>
    /// Regression guard for ultrareview Bug 5: the
    /// <see cref="Secret{TNumber}(Calculator)"/> ctor must surface
    /// <see cref="ArgumentNullException"/> on a <see langword="null"/>
    /// <c>secretSource</c> rather than NRE-ing on the subsequent
    /// <c>secretSource.ByteRepresentation</c> dereference.
    /// </summary>
    [Fact]
    public void Constructor_CalculatorIsNull_ThrowsArgumentNullException()
    {
        // Arrange
        Calculator nullCalculator = null;

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => new Secret<BigInteger>(nullCalculator));
    }

    /// <summary>
    /// Regression guard for ultrareview Bug 5: the implicit
    /// <c>Calculator&lt;TNumber&gt; &#x2192; Secret&lt;TNumber&gt;</c> operator must surface
    /// <see cref="ArgumentNullException"/> on a <see langword="null"/> calculator rather
    /// than NRE-ing on the subsequent <c>ByteRepresentation</c> dereference.
    /// </summary>
    [Fact]
    public void ImplicitCast_FromNullCalculator_ThrowsArgumentNullException()
    {
        // Arrange
        Calculator<BigInteger> nullCalculator = null;

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => { Secret<BigInteger> _ = nullCalculator; });
    }

    /// <summary>
    /// Regression guard for ultrareview Bug 5: the implicit
    /// <c>byte[] &#x2192; Secret&lt;TNumber&gt;</c> operator must surface
    /// <see cref="ArgumentNullException"/> on a <see langword="null"/> array rather than
    /// NRE-ing on the subsequent <c>array.Length</c> read.
    /// </summary>
    [Fact]
    public void ImplicitCast_FromNullByteArray_ThrowsArgumentNullException()
    {
        // Arrange
        byte[] nullArray = null;

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => { Secret<BigInteger> _ = nullArray; });
    }

    /// <summary>
    /// Regression guard for ultrareview Bug 5: the implicit
    /// <c>PinnedPoolArray&lt;byte&gt; &#x2192; Secret&lt;TNumber&gt;</c> operator must surface
    /// <see cref="ArgumentNullException"/> on a <see langword="null"/> array rather than
    /// NRE-ing on the subsequent <c>array.PoolArray</c> dereference.
    /// </summary>
    [Fact]
    public void ImplicitCast_FromNullPinnedPoolArray_ThrowsArgumentNullException()
    {
        // Arrange
        PinnedPoolArray<byte> nullArray = null;

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => { Secret<BigInteger> _ = nullArray; });
    }

    /// <summary>
    /// Tests that a <see cref="string"/> password constructed via
    /// <see cref="Secret{TNumber}.FromText(PinnedPoolArray{char})"/> round-trips back to the original.
    /// </summary>
    /// <param name="password">A <see cref="string"/> source secret.</param>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Performance", "CA1822:MarkMembersAsStatic")]
    [Theory]
    [MemberData(nameof(TestData.StringSecrets), MemberType = typeof(TestData))]
    public void CastObjectToSecret_FromString_RestoresAfterTextRoundTrip(string password)
    {
        // Arrange & Act
        using var pinnedPassword = password.ToPinnedSecure();
        using var secret = Secret<BigInteger>.FromText(pinnedPassword);

        // Assert
        SecretAssertions.AssertSecretEqualsString(password, secret);
    }

    /// <summary>
    /// Tests that a <see cref="BigInteger"/> constructed via the implicit
    /// <see cref="Secret{TNumber}"/> cast round-trips back to the original value.
    /// </summary>
    /// <param name="bigNumber">A <see cref="BigInteger"/> source secret.</param>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Performance", "CA1822:MarkMembersAsStatic")]
    [Theory]
    [MemberData(nameof(TestData.BigIntegerSecrets), MemberType = typeof(TestData))]
    public void CastObjectToSecret_FromBigInteger_RestoresAfterCast(BigInteger bigNumber)
    {
        // Arrange & Act
        using Secret<BigInteger> secret = bigNumber;

        // Assert
        Assert.Equal(bigNumber, (BigInteger)secret);
    }

    /// <summary>
    /// Tests that an <see cref="int"/> constructed via the implicit
    /// <c>int → BigInteger → Secret&lt;BigInteger&gt;</c> chain round-trips back to the original value.
    /// </summary>
    /// <param name="number">An <see cref="int"/> source secret.</param>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Performance", "CA1822:MarkMembersAsStatic")]
    [Theory]
    [MemberData(nameof(TestData.IntSecrets), MemberType = typeof(TestData))]
    public void CastObjectToSecret_FromInt_RestoresAfterCast(int number)
    {
        // Arrange & Act
        using Secret<BigInteger> secret = (BigInteger)number;

        // Assert
        Assert.Equal(number, (BigInteger)secret);
    }

    /// <summary>
    /// Tests that a <see cref="byte"/> array constructed via
    /// <see cref="Secret{TNumber}(byte[], int)"/> round-trips back through
    /// <see cref="Secret{TNumber}.ToByteArray()"/>.
    /// </summary>
    /// <param name="byteArray">A <see cref="byte"/>[] source secret.</param>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Performance", "CA1822:MarkMembersAsStatic")]
    [Theory]
    [MemberData(nameof(TestData.ByteArraySecrets), MemberType = typeof(TestData))]
    public void CastObjectToSecret_FromByteArray_RestoresAfterReadBack(byte[] byteArray)
    {
        // Arrange & Act
        using var secret = new Secret<BigInteger>(byteArray, byteArray.Length);
        using var pinnedPoolArray = secret.ToByteArray();

        // Assert
        var countedEqualityComparer = new CountedEqualityComparer<byte>(count: byteArray.Length);
        Assert.True(pinnedPoolArray.Equals(byteArray, countedEqualityComparer));
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
        Assert.Equal(secretText, new string(roundTrip.PoolArray, 0, roundTrip.Length));
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
        Assert.Equal(secretText, new string(roundTrip.PoolArray, 0, roundTrip.Length));
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
        Assert.Equal(expected, rawBytes.PoolArray.Take(rawBytes.Length));
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
        Assert.Equal(secretText, new string(pinnedText.PoolArray, 0, pinnedText.Length));
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

    /// <summary>
    /// Tests that <see cref="Secret{TNumber}.FromBase64(PinnedPoolArray{char})"/> followed by
    /// <see cref="Secret{TNumber}.ToBase64CharArray()"/> reproduces the original Base64
    /// input verbatim across representative payloads.
    /// </summary>
    /// <param name="base64">A valid Base64 string.</param>
    [Theory]
    [InlineData(TestData.Base64GermanPangram)]
    [InlineData(TestData.Base64SimpleSentence)]
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
        Assert.Equal(base64, new string(roundTrip.PoolArray, 0, roundTrip.Length));
    }

    /// <summary>
    /// Tests that <see cref="Secret{TNumber}.FromBase64(PinnedPoolArray{char})"/> tolerates
    /// interior whitespace (LF, CR, SP, TAB, FF, VT, CRLF) inside the Base64 payload — the
    /// reconstructed secret matches the whitespace-free original.
    /// </summary>
    [Fact]
    public void FromBase64_PinnedPoolArrayChar_IgnoresInteriorWhitespace()
    {
        // Arrange — same payload as the bare-string Theory case, but split across "lines"
        // and with miscellaneous whitespace types (LF, CR, space, tab, FF, VT) injected.
        const string raw = TestData.Base64SimpleSentence;
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
        Assert.Equal(raw, new string(roundTrip.PoolArray, 0, roundTrip.Length));
    }

    /// <summary>
    /// Cross-checks <see cref="Secret{TNumber}.FromBase64(PinnedPoolArray{char})"/> against
    /// the BCL's <see cref="Convert.FromBase64String(string)"/>: decoded bytes must match
    /// exactly — independent oracle for the library's pinned Base64 decoder.
    /// </summary>
    [Fact]
    public void FromBase64_PinnedPoolArrayChar_EquivalentToConvertFromBase64String()
    {
        // Arrange
        // Independent oracle: bytes must match Convert.FromBase64String exactly.
        const string base64 = TestData.Base64GermanPangram;
        byte[] expected = Convert.FromBase64String(base64);

        // Act
        using var pinnedBase64 = base64.ToPinnedSecure();
        using var secret = Secret<BigInteger>.FromBase64(pinnedBase64);
        using var bytes = secret.ToByteArray();

        // Assert
        Assert.Equal(expected, bytes.PoolArray.Take(bytes.Length));
    }

    /// <summary>
    /// Tests that <see cref="Secret{TNumber}.FromBase64(PinnedPoolArray{char})"/> rejects a
    /// non-Base64 character with <see cref="FormatException"/>, and the exception message
    /// names both the offending character and its position.
    /// </summary>
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

    /// <summary>
    /// Tests that <see cref="Secret{TNumber}.FromBase64(PinnedPoolArray{char})"/> rejects a
    /// Base64 input whose non-whitespace length is not a multiple of four with
    /// <see cref="FormatException"/>.
    /// </summary>
    [Fact]
    public void FromBase64_PinnedPoolArrayChar_NotMultipleOfFour_ThrowsFormatException()
    {
        // Arrange
        using var pinnedBase64 = "ABC".ToPinnedSecure();

        // Act & Assert
        Assert.Throws<FormatException>(() => Secret<BigInteger>.FromBase64(pinnedBase64));
    }

    /// <summary>
    /// Tests that <see cref="Secret{TNumber}.FromBase64(PinnedPoolArray{char})"/> rejects
    /// Base64 input with more than two trailing <c>=</c> pad characters with
    /// <see cref="FormatException"/>.
    /// </summary>
    [Fact]
    public void FromBase64_PinnedPoolArrayChar_TooManyPads_ThrowsFormatException()
    {
        // Arrange
        using var pinnedBase64 = "A===".ToPinnedSecure();

        // Act & Assert
        Assert.Throws<FormatException>(() => Secret<BigInteger>.FromBase64(pinnedBase64));
    }

    /// <summary>
    /// Tests that <see cref="Secret{TNumber}.FromBase64(PinnedPoolArray{char})"/> rejects
    /// Base64 input where a non-<c>=</c> character follows an existing <c>=</c> pad with
    /// <see cref="FormatException"/>.
    /// </summary>
    [Fact]
    public void FromBase64_PinnedPoolArrayChar_NonPadAfterPad_ThrowsFormatException()
    {
        // Arrange
        // 'B' appears after a '=' in the same group.
        using var pinnedBase64 = "A=B=".ToPinnedSecure();

        // Act & Assert
        Assert.Throws<FormatException>(() => Secret<BigInteger>.FromBase64(pinnedBase64));
    }

    /// <summary>
    /// Tests that <see cref="Secret{TNumber}.FromBase64(PinnedPoolArray{char})"/> rejects a
    /// buffer that contains only whitespace with <see cref="ArgumentException"/> — the
    /// caller's <c>FromBase64</c> contract requires at least one Base64 character.
    /// </summary>
    [Fact]
    public void FromBase64_PinnedPoolArrayChar_OnlyWhitespace_ThrowsArgumentException()
    {
        // Arrange
        using var pinnedBase64 = "   \t\r\n\f\v   ".ToPinnedSecure();

        // Act & Assert
        Assert.Throws<ArgumentException>(() => Secret<BigInteger>.FromBase64(pinnedBase64));
    }

    /// <summary>
    /// Tests that <see cref="Secret{TNumber}.FromBase64(PinnedPoolArray{char})"/> rejects a
    /// zero-length pinned buffer with <see cref="ArgumentException"/>.
    /// </summary>
    [Fact]
    public void FromBase64_PinnedPoolArrayChar_EmptyBuffer_ThrowsArgumentException()
    {
        // Arrange
        using var pinnedBase64 = new PinnedPoolArray<char>(0);

        // Act & Assert
        Assert.Throws<ArgumentException>(() => Secret<BigInteger>.FromBase64(pinnedBase64));
    }

    /// <summary>
    /// Tests that <see cref="Secret{TNumber}.FromBase64(PinnedPoolArray{char})"/> rejects a
    /// <see langword="null"/> argument with <see cref="ArgumentNullException"/>.
    /// </summary>
    [Fact]
    public void FromBase64_PinnedPoolArrayChar_NullBuffer_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() => Secret<BigInteger>.FromBase64(null));
    }

    /// <summary>
    /// Tests that <see cref="Secret{TNumber}.FromBase64(PinnedPoolArray{char})"/> throws
    /// <see cref="ObjectDisposedException"/> when the input pinned buffer has already
    /// been disposed.
    /// </summary>
    [Fact]
    public void FromBase64_PinnedPoolArrayChar_DisposedBuffer_ThrowsObjectDisposedException()
    {
        // Arrange
        var pinnedBase64 = new PinnedPoolArray<char>(4);
        pinnedBase64.Dispose();

        // Act & Assert
        Assert.Throws<ObjectDisposedException>(() => Secret<BigInteger>.FromBase64(pinnedBase64));
    }

    /// <summary>
    /// Tests that <see cref="Secret{TNumber}.FromBase64(PinnedPoolArray{char})"/> does not
    /// consume or mutate the caller-owned input buffer — the pinned bytes remain intact
    /// after the call returns.
    /// </summary>
    [Fact]
    public void FromBase64_PinnedPoolArrayChar_DoesNotConsumeInput()
    {
        // Arrange
        const string base64 = TestData.Base64SimpleSentence;
        using var pinnedBase64 = base64.ToPinnedSecure();

        // Act
        using (Secret<BigInteger>.FromBase64(pinnedBase64))

        // Assert — input buffer must remain intact and usable.
        Assert.Equal(base64, new string(pinnedBase64.PoolArray, 0, pinnedBase64.Length));
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

    /// <summary>
    /// Mirror of <c>SecureBigInteger.SecretTest.CastToSecureBigInteger_FromSecret_ReturnsLiveCallerOwnedInstance</c>.
    /// For the value-type <see cref="BigInteger"/> backend the implicit op already returns a struct
    /// copy, so the SecureBigInteger-side "still live after the Calculator was disposed" hazard does
    /// not apply here — the mirror is kept anyway so a future src-side drift that breaks the
    /// extracted-value contract trips both backend hierarchies at once. The "independent instances"
    /// test from the SecureBigInteger side is intentionally not mirrored: <c>Assert.NotSame</c>
    /// against a struct is a category error.
    /// </summary>
    [Fact]
    public void CastToBigInteger_FromSecret_ReturnsExtractedValue()
    {
        // Arrange — byte-built Secret keeps the construction pattern in sync with the
        // SecureBigInteger mirror, which has to avoid the symmetric wrapping-direction
        // dispose bug. The expected value follows from LE two's-complement of {0x2A}.
        byte[] valueBytes = { 0x2A };
        using var secret = new Secret<BigInteger>(valueBytes, valueBytes.Length);

        // Act
        BigInteger extracted = secret;

        // Assert
        Assert.Equal(new BigInteger(42), extracted);
    }

    /// <summary>
    /// Tests that casting a <c>default(Secret&lt;BigInteger&gt;)</c> to
    /// <see cref="BigInteger"/> throws <see cref="InvalidOperationException"/>
    /// rather than silently returning <see cref="BigInteger.Zero"/>. Mirrors the
    /// SecureBigInteger-side test that checks the same throw on the class backend;
    /// the symmetric throw is what closes the prior null-vs-Zero backend asymmetry.
    /// </summary>
    [Fact]
    public void CastToBigInteger_FromDefaultSecret_ThrowsInvalidOperationException()
    {
        // Arrange
        Secret<BigInteger> uninitialized = default;

        // Act & Assert
        Assert.Throws<InvalidOperationException>(() => { BigInteger _ = uninitialized; });
    }

    /// <summary>
    /// Mirror of <c>SecureBigInteger.SecretTest.CastToSecret_FromSecureBigInteger_LeavesOriginalUsable</c>.
    /// For the value-type <see cref="BigInteger"/> backend the wrap operates on a struct copy, so the
    /// dispose-of-caller hazard is structurally absent. Mirror kept so a future change that broke the
    /// extracted-value contract would fail on both sides.
    /// </summary>
    [Fact]
    public void CastToSecret_FromBigInteger_LeavesOriginalUsable()
    {
        // Arrange
        BigInteger original = 42;

        // Act
        using var secret = (Secret<BigInteger>)original;

        // Assert
        Assert.Equal(new BigInteger(42), original);
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

    /// <summary>
    /// P2 regression (PR #296 Codex review): a private static readonly
    /// <see cref="Secret{TNumber}"/> singleton previously aliased a shared
    /// <c>PinnedPoolArray</c>, so the first caller's <c>using</c> disposal
    /// wiped the buffer and subsequent zero-draw returns from
    /// <c>Secret&lt;TNumber&gt;.CreateRandom</c> handed out an already-disposed
    /// instance. The fix removed the static field. This test fails if any static
    /// <see cref="Secret{TNumber}"/> field reappears at the class level.
    /// </summary>
    [Fact]
    public void Secret_HasNoStaticSingletonField_P2Regression()
    {
        // Arrange
        var staticSecretFields = typeof(Secret<BigInteger>)
            .GetFields(BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic)
            .Where(f => f.FieldType == typeof(Secret<BigInteger>))
            .ToArray();

        // Act & Assert
        Assert.Empty(staticSecretFields);
    }
}
