// ----------------------------------------------------------------------------
// <copyright file="ExtendedGcdResultTest.cs" company="Private">
// Copyright (c) 2026 All Rights Reserved
// </copyright>
// <author>Sebastian Walther</author>
// <date>05/08/2026 00:00:00 AM</date>
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


namespace SecretSharingDotNetTest.Math.BigInteger;

using SecretSharingDotNet.Math;
using SecretSharingDotNet.Math.Numerics;
using System;
using System.Collections.Generic;
using System.Numerics;
using Xunit;

public class ExtendedGcdResultTest
{
    [Fact]
    public void Constructor_NullGcd_ThrowsArgumentNullException()
    {
        // Arrange
        var coefficients = new List<Calculator<BigInteger>>();
        var quotients = new List<Calculator<BigInteger>>();

        // Act & Assert
        var ex = Assert.Throws<ArgumentNullException>(() =>
            new ExtendedGcdResult<BigInteger>(null!, coefficients, quotients));
        Assert.Equal("gcd", ex.ParamName);
    }

    [Fact]
    public void Constructor_NullCoefficients_ThrowsArgumentNullException()
    {
        // Arrange
        using Calculator<BigInteger> gcd = (BigInteger)1;
        var quotients = new List<Calculator<BigInteger>>();

        // Act & Assert
        var ex = Assert.Throws<ArgumentNullException>(() =>
            new ExtendedGcdResult<BigInteger>(gcd, null!, quotients));
        Assert.Equal("coefficients", ex.ParamName);
    }

    [Fact]
    public void Constructor_NullQuotients_ThrowsArgumentNullException()
    {
        // Arrange
        using Calculator<BigInteger> gcd = (BigInteger)1;
        var coefficients = new List<Calculator<BigInteger>>();

        // Act & Assert
        var ex = Assert.Throws<ArgumentNullException>(() =>
            new ExtendedGcdResult<BigInteger>(gcd, coefficients, null!));
        Assert.Equal("quotients", ex.ParamName);
    }

    [Fact]
    public void Dispose_OnDefaultStruct_DoesNotThrow()
    {
        // Arrange — every component (gcd, coefficients, quotients) is null on a default struct.
        var result = default(ExtendedGcdResult<BigInteger>);

        // Act & Assert — must not NRE on null collections.
        result.Dispose();
    }

    [Fact]
    public void Dispose_OnPopulatedResult_IsIdempotent()
    {
        // Arrange — wire fresh calculators into the result. Unlike SecureBigInteger,
        // BigInteger / BigIntCalculator have no observable post-dispose state
        // (BigInteger is a BCL struct; BigIntCalculator's `Value` getter does not
        // throw after Dispose). The BigInteger backend therefore can only assert
        // the cascade-dispose contract indirectly: triple-dispose must not throw
        // and must be idempotent.
        Calculator<BigInteger> gcd = (BigInteger)1;
        Calculator<BigInteger> coefficient = (BigInteger)2;
        Calculator<BigInteger> quotient = (BigInteger)3;
        var result = new ExtendedGcdResult<BigInteger>(
            gcd,
            new[] { coefficient },
            new[] { quotient });

        // Act
        var ex = Record.Exception(() =>
        {
            result.Dispose();
            result.Dispose();
            result.Dispose();
        });

        // Assert
        Assert.Null(ex);
    }
}