// ----------------------------------------------------------------------------
// <copyright file="ExtendedEuclideanAlgorithmTest.cs" company="Private">
// Copyright (c) 2019 All Rights Reserved
// </copyright>
// <author>Sebastian Walther</author>
// <date>04/20/2019 10:52:28 PM</date>
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

namespace SecretSharingDotNetTest.Math;

using SecretSharingDotNet.Helper;
using SecretSharingDotNet.Math;
using System;
using System.Globalization;
using System.Numerics;
using Xunit;

#if NET6_0_OR_GREATER
public sealed class ExtendedEuclideanAlgorithmTest : IDisposable
#else
public sealed class ExtendedEuclideanAlgorithmTest
#endif
{
#if NET6_0_OR_GREATER
    private readonly Scope scope;
    private bool disposed;

    public ExtendedEuclideanAlgorithmTest()
    {
        this.scope = new Scope();
        var compositeDisposable = this.scope.GetScopedSingleton<CompositeDisposable>();
        CompositeDisposableContext.SetCurrent(compositeDisposable);
    }
    
    ~ExtendedEuclideanAlgorithmTest()
    {
        this.Dispose(false);
    }
    
    public void Dispose()
    {
        this.Dispose(true);
        GC.SuppressFinalize(this);
    }
    
    private void Dispose(bool disposing)
    {
        if (this.disposed)
        {
            return;
        }
        
        if (disposing)
        {
            this.scope?.Dispose();
        }
        
        this.disposed = true;
    }

    [Fact]
    public void TestSimpleGcd_WithSecureBigInteger()
    {
        // Arrange
        var gcd = new ExtendedEuclideanAlgorithm<SecureBigInteger>();
        Calculator<SecureBigInteger> expected = new SecureBigInteger(3);

        // Act
        var gcdResult = gcd.Compute(new SecureBigInteger(6), new SecureBigInteger(9));

        // Assert
        Assert.Equal(expected, gcdResult.GreatestCommonDivisor);
    }

    [Fact]
    public void TestPositiveBoth_WithSecureBigInteger()
    {
        // Arrange
        var gcd = new ExtendedEuclideanAlgorithm<SecureBigInteger>();

        // Act
        var result = gcd.Compute(
            SecureBigInteger.Parse("2", CultureInfo.InvariantCulture),
            SecureBigInteger.Parse("170141183460469231731687303715884105727", CultureInfo.InvariantCulture));

        // Assert
        Assert.Equal(
            SecureBigInteger.Parse("-85070591730234615865843651857942052863", CultureInfo.InvariantCulture),
            result.BezoutCoefficients[0].Value);
        Assert.Equal(SecureBigInteger.One, result.BezoutCoefficients[1].Value);
    }

    [Fact]
    public void Test1NegativeParameterA_WithSecureBigInteger()
    {
        // Arrange
        var gcd = new ExtendedEuclideanAlgorithm<SecureBigInteger>();

        // Act
        var result = gcd.Compute(
            SecureBigInteger.Parse("-1", CultureInfo.InvariantCulture),
            SecureBigInteger.Parse("170141183460469231731687303715884105727", CultureInfo.InvariantCulture));

        // Assert
        Assert.Equal(SecureBigInteger.One, result.BezoutCoefficients[0].Value);
        Assert.Equal(SecureBigInteger.Zero, result.BezoutCoefficients[1].Value);
    }

    [Fact]
    public void Test2NegativeParameterA_WithSecureBigInteger()
    {
        // Arrange
        var gcd = new ExtendedEuclideanAlgorithm<SecureBigInteger>();

        // Act
        var result = gcd.Compute(
            SecureBigInteger.Parse("-4", CultureInfo.InvariantCulture),
            SecureBigInteger.Parse("170141183460469231731687303715884105727", CultureInfo.InvariantCulture));

        // Assert
        Assert.Equal(
            SecureBigInteger.Parse("42535295865117307932921825928971026432", CultureInfo.InvariantCulture),
            result.BezoutCoefficients[0].Value);
        Assert.Equal(SecureBigInteger.One, result.BezoutCoefficients[1].Value);
    }

    [Fact]
    public void Test1NegativeParameterB_WithSecureBigInteger()
    {
        // Arrange
        var gcd = new ExtendedEuclideanAlgorithm<SecureBigInteger>();

        // Act
        var result = gcd.Compute(
            SecureBigInteger.Parse("170141183460469231731687303715884105727", CultureInfo.InvariantCulture),
            SecureBigInteger.Parse("-1", CultureInfo.InvariantCulture));

        // Assert
        Assert.Equal(SecureBigInteger.Zero, result.BezoutCoefficients[0].Value);
        Assert.Equal(SecureBigInteger.One, result.BezoutCoefficients[1].Value);
    }

    [Fact]
    public void Test2NegativeParameterB_WithSecureBigInteger()
    {
        // Arrange
        var gcd = new ExtendedEuclideanAlgorithm<SecureBigInteger>();

        // Act
        var result = gcd.Compute(
                SecureBigInteger.Parse("170141183460469231731687303715884105727", CultureInfo.InvariantCulture),
                SecureBigInteger.Parse("-4", CultureInfo.InvariantCulture));

        // Assert
        Assert.Equal(SecureBigInteger.One, result.BezoutCoefficients[0].Value);
        Assert.Equal(
            SecureBigInteger.Parse("42535295865117307932921825928971026432", CultureInfo.InvariantCulture),
            result.BezoutCoefficients[1].Value);
    }

    [Fact]
    public void TestBezoutCoefficients_WithSecureBigInteger()
    {
        // Arrange
        var gcd = new ExtendedEuclideanAlgorithm<SecureBigInteger>();

        // Act
        var result = gcd.Compute(
            SecureBigInteger.Parse("-6", CultureInfo.InvariantCulture),
            SecureBigInteger.Parse("170141183460469231731687303715884105727", CultureInfo.InvariantCulture));

        // Assert
        Assert.Equal(
            SecureBigInteger.Parse("28356863910078205288614550619314017621", CultureInfo.InvariantCulture),
            result.BezoutCoefficients[0].Value);
        Assert.Equal(SecureBigInteger.Parse("1", CultureInfo.InvariantCulture), result.BezoutCoefficients[1].Value);
    }
#endif

    [Fact]
    public void TestSimpleGcd_WithBigInteger()
    {
        // Arrange
        var gcd = new ExtendedEuclideanAlgorithm<BigInteger>();
        Calculator<BigInteger> expected = (BigInteger)3;

        // Act
        var gcdResult = gcd.Compute(BigInteger.Parse("6", CultureInfo.InvariantCulture), BigInteger.Parse("9", CultureInfo.InvariantCulture));

        // Assert
        Assert.Equal(expected, gcdResult.GreatestCommonDivisor);
    }

    [Fact]
    public void TestPositiveBoth_WithBigInteger()
    {
        // Arrange
        var gcd = new ExtendedEuclideanAlgorithm<BigInteger>();
        
        // Act
        var result = gcd.Compute(BigInteger.Parse("2", CultureInfo.InvariantCulture), BigInteger.Parse("170141183460469231731687303715884105727", CultureInfo.InvariantCulture));
        
        // Assert
        Assert.Equal(BigInteger.Parse("-85070591730234615865843651857942052863", CultureInfo.InvariantCulture), result.BezoutCoefficients[0].Value);
        Assert.Equal(BigInteger.One, result.BezoutCoefficients[1].Value);
    }

    [Fact]
    public void Test1NegativeParameterA_WithBigInteger()
    {
        // Arrange
        var gcd = new ExtendedEuclideanAlgorithm<BigInteger>();
        
        // Act
        var result = gcd.Compute(BigInteger.Parse("-1", CultureInfo.InvariantCulture), BigInteger.Parse("170141183460469231731687303715884105727", CultureInfo.InvariantCulture));
        
        // Assert
        Assert.Equal(BigInteger.One, result.BezoutCoefficients[0].Value);
        Assert.Equal(BigInteger.Zero, result.BezoutCoefficients[1].Value);
    }

    [Fact]
    public void Test2NegativeParameterA_WithBigInteger()
    {
        ExtendedEuclideanAlgorithm<BigInteger> gcd = new ExtendedEuclideanAlgorithm<BigInteger>();
        var result = gcd.Compute(BigInteger.Parse("-4", CultureInfo.InvariantCulture), BigInteger.Parse("170141183460469231731687303715884105727", CultureInfo.InvariantCulture));
        Assert.Equal(BigInteger.Parse("42535295865117307932921825928971026432", CultureInfo.InvariantCulture), result.BezoutCoefficients[0].Value);
        Assert.Equal(BigInteger.One, result.BezoutCoefficients[1].Value);
    }

    [Fact]
    public void Test1NegativeParameterB_WithBigInteger()
    {
        // Arrange
        var gcd = new ExtendedEuclideanAlgorithm<BigInteger>();
        
        // Act
        var result = gcd.Compute(BigInteger.Parse("170141183460469231731687303715884105727", CultureInfo.InvariantCulture), BigInteger.Parse("-1", CultureInfo.InvariantCulture));
        
        // Assert
        Assert.Equal(BigInteger.Zero, result.BezoutCoefficients[0].Value);
        Assert.Equal(BigInteger.One, result.BezoutCoefficients[1].Value);
    }

    [Fact]
    public void Test2NegativeParameterB_WithBigInteger()
    {
        // Arrange
        var gcd = new ExtendedEuclideanAlgorithm<BigInteger>();
        
        // Act
        var result = gcd.Compute(BigInteger.Parse("170141183460469231731687303715884105727", CultureInfo.InvariantCulture), BigInteger.Parse("-4", CultureInfo.InvariantCulture));
        
        // Assert
        Assert.Equal(BigInteger.One, result.BezoutCoefficients[0].Value);
        Assert.Equal(BigInteger.Parse("42535295865117307932921825928971026432", CultureInfo.InvariantCulture), result.BezoutCoefficients[1].Value);
    }
}