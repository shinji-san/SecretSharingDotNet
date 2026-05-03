// ----------------------------------------------------------------------------
// <copyright file="ExtendedGcdResultTest.cs" company="Private">
// Copyright (c) 2026 All Rights Reserved
// </copyright>
// <author>Sebastian Walther</author>
// <date>05/03/2026 00:00:00 AM</date>
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


namespace SecretSharingDotNetTest.Math.SecureBigInteger;

using SecretSharingDotNet.Math;
using SecretSharingDotNet.Math.Numerics;
using System;
using System.Collections.Generic;
using Xunit;

public class ExtendedGcdResultTest
{
    [Fact]
    public void Constructor_NullGcd_ThrowsArgumentNullException()
    {
        // Arrange
        var coefficients = new List<Calculator<SecureBigInteger>>();
        var quotients = new List<Calculator<SecureBigInteger>>();

        // Act & Assert
        var ex = Assert.Throws<ArgumentNullException>(() =>
            new ExtendedGcdResult<SecureBigInteger>(null!, coefficients, quotients));
        Assert.Equal("gcd", ex.ParamName);
    }

    [Fact]
    public void Constructor_NullCoefficients_ThrowsArgumentNullException()
    {
        // Arrange
        using Calculator<SecureBigInteger> gcd = (SecureBigInteger)1;
        var quotients = new List<Calculator<SecureBigInteger>>();

        // Act & Assert
        var ex = Assert.Throws<ArgumentNullException>(() =>
            new ExtendedGcdResult<SecureBigInteger>(gcd, null!, quotients));
        Assert.Equal("coefficients", ex.ParamName);
    }

    [Fact]
    public void Constructor_NullQuotients_ThrowsArgumentNullException()
    {
        // Arrange
        using Calculator<SecureBigInteger> gcd = (SecureBigInteger)1;
        var coefficients = new List<Calculator<SecureBigInteger>>();

        // Act & Assert
        var ex = Assert.Throws<ArgumentNullException>(() =>
            new ExtendedGcdResult<SecureBigInteger>(gcd, coefficients, null!));
        Assert.Equal("quotients", ex.ParamName);
    }

    [Fact]
    public void Dispose_OnDefaultStruct_DoesNotThrow()
    {
        // Arrange — every component (gcd, coefficients, quotients) is null on a default struct.
        var result = default(ExtendedGcdResult<SecureBigInteger>);

        // Act & Assert — must not NRE on null collections.
        result.Dispose();
    }

    [Fact]
    public void Dispose_OnPopulatedResult_DisposesAllCalculators()
    {
        // Arrange — wire fresh calculators into the result; they must all end up disposed.
        Calculator<SecureBigInteger> gcd = (SecureBigInteger)1;
        Calculator<SecureBigInteger> coefficient = (SecureBigInteger)2;
        Calculator<SecureBigInteger> quotient = (SecureBigInteger)3;
        var result = new ExtendedGcdResult<SecureBigInteger>(
            gcd,
            new[] { coefficient },
            new[] { quotient });

        // Act
        result.Dispose();

        // Assert — every contained calculator's underlying SecureBigInteger is now disposed.
        Assert.Throws<ObjectDisposedException>(() => _ = gcd.Value.IsZero);
        Assert.Throws<ObjectDisposedException>(() => _ = coefficient.Value.IsZero);
        Assert.Throws<ObjectDisposedException>(() => _ = quotient.Value.IsZero);
    }
}