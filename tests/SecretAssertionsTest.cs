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

public class SecretAssertionsTest
{
    [Fact]
    public void AssertSecretEqualsString_EqualValues_DoesNotThrow()
    {
        const string text = "P&ssw0rd!";
        using var pinned = text.ToPinnedSecure();
        using var secret = Secret<BigInteger>.FromText(pinned);

        SecretAssertions.AssertSecretEqualsString(text, secret);
    }

    [Fact]
    public void AssertSecretEqualsString_DifferentValues_ThrowsEqualException()
    {
        using var pinned = "actual".ToPinnedSecure();
        using var secret = Secret<BigInteger>.FromText(pinned);

        Assert.Throws<EqualException>(
            () => SecretAssertions.AssertSecretEqualsString("expected", secret));
    }

    [Fact]
    public void AssertSecretEqualsString_NullExpected_ThrowsArgumentNullException()
    {
        using var pinned = "x".ToPinnedSecure();
        using var secret = Secret<BigInteger>.FromText(pinned);

        Assert.Throws<ArgumentNullException>(
            () => SecretAssertions.AssertSecretEqualsString<BigInteger>(null, secret));
    }
}