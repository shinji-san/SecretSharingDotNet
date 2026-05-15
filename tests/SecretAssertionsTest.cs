// ----------------------------------------------------------------------------
// <copyright file="SecretAssertionsTest.cs" company="Private">
// Copyright (c) 2026 All Rights Reserved
// </copyright>
// <author>Sebastian Walther</author>
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

namespace SecretSharingDotNetTest;

using System;
using System.Numerics;
using SecretSharingDotNet.Cryptography;
using SecretSharingDotNet.Cryptography.SecureInput;
using Xunit;
using Xunit.Sdk;

/// <summary>
/// Tests for the test-only <see cref="SecretAssertions"/> helper, which compares a
/// <see cref="Secret{TNumber}"/> against an expected <see cref="string"/> without
/// surfacing the secret bytes in the failure diagnostic.
/// </summary>
public class SecretAssertionsTest
{
    /// <summary>
    /// Tests that <see cref="SecretAssertions.AssertSecretEqualsString{TNumber}"/> succeeds
    /// silently when the secret's text content equals the expected string.
    /// </summary>
    [Fact]
    public void AssertSecretEqualsString_EqualValues_DoesNotThrow()
    {
        // Arrange
        const string text = "P&ssw0rd!";
        using var pinned = text.ToPinnedSecure();
        using var secret = Secret<BigInteger>.FromText(pinned);

        // Act & Assert
        SecretAssertions.AssertSecretEqualsString(text, secret);
    }

    /// <summary>
    /// Tests that <see cref="SecretAssertions.AssertSecretEqualsString{TNumber}"/> throws
    /// xUnit's <see cref="EqualException"/> when the secret's text content differs from the
    /// expected string — exposing the mismatch through the standard test-framework path.
    /// </summary>
    [Fact]
    public void AssertSecretEqualsString_DifferentValues_ThrowsEqualException()
    {
        // Arrange
        using var pinned = "actual".ToPinnedSecure();
        using var secret = Secret<BigInteger>.FromText(pinned);

        // Act & Assert
        Assert.Throws<EqualException>(
            () => SecretAssertions.AssertSecretEqualsString("expected", secret));
    }

    /// <summary>
    /// Tests that <see cref="SecretAssertions.AssertSecretEqualsString{TNumber}"/> rejects a
    /// <see langword="null"/> expected string with <see cref="ArgumentNullException"/>
    /// before attempting any comparison.
    /// </summary>
    [Fact]
    public void AssertSecretEqualsString_NullExpected_ThrowsArgumentNullException()
    {
        // Arrange
        using var pinned = "x".ToPinnedSecure();
        using var secret = Secret<BigInteger>.FromText(pinned);

        // Act & Assert
        Assert.Throws<ArgumentNullException>(
            () => SecretAssertions.AssertSecretEqualsString<BigInteger>(null, secret));
    }
}