// ----------------------------------------------------------------------------
// <copyright file="SecretAssertions.cs" company="Private">
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
using SecretSharingDotNet.Cryptography;
using SecretSharingDotNet.Cryptography.SecureInput;
using Xunit;

/// <summary>
/// xUnit-style assertion helpers for <see cref="Secret{TNumber}"/>.
/// </summary>
internal static class SecretAssertions
{
    /// <summary>
    /// Asserts that the UTF-8 encoding of <paramref name="expected"/> equals the byte
    /// payload of <paramref name="actual"/>.
    /// </summary>
    /// <typeparam name="TNumber">Numeric backing type of the <see cref="Secret{TNumber}"/>.</typeparam>
    /// <param name="expected">The expected secret content as a UTF-8 string.</param>
    /// <param name="actual">The <see cref="Secret{TNumber}"/> to compare against.</param>
    /// <remarks>
    /// Replaces the <c>Assert.Equal(string, Secret&lt;TNumber&gt;)</c> idiom that previously
    /// relied on the implicit <see cref="string"/>-to-<see cref="Secret{TNumber}"/> conversion.
    /// The expected string is copied into a pinned buffer and converted via
    /// <see cref="Secret{TNumber}.FromText(SecretSharingDotNet.Cryptography.SecureArray.PinnedPoolArray{char})"/>,
    /// preserving the historical UTF-8 default.
    /// </remarks>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="expected"/> is <see langword="null"/>.
    /// </exception>
    public static void AssertSecretEqualsString<TNumber>(string expected, Secret<TNumber> actual)
    {
        if (expected is null)
        {
            throw new ArgumentNullException(nameof(expected));
        }

        using var pinned = expected.ToPinnedSecure();
        using var expectedSecret = Secret<TNumber>.FromText(pinned);
        Assert.Equal(expectedSecret, actual);
    }
}