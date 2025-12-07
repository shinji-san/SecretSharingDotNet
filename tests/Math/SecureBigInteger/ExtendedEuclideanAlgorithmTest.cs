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

namespace SecretSharingDotNetTest.Math.SecureBigInteger;

using SecretSharingDotNet.Math;
using SecretSharingDotNet.Math.SecureBigInteger;
using Xunit;

public class ExtendedEuclideanAlgorithmTest
{
    private readonly ExtendedEuclideanAlgorithm<SecureBigInteger> gcd = new ExtendedEuclideanAlgorithm<SecureBigInteger>();

    [Fact]
    public void TestSimpleGcd()
    {
        // Arrange
        using Calculator<SecureBigInteger> expected = (SecureBigInteger)3;
        using Calculator<SecureBigInteger> a = (SecureBigInteger)6; 
        using Calculator<SecureBigInteger> b = (SecureBigInteger)9;

        // Act
        using var gcdResult = this.gcd.Compute(a, b);

        // Assert
        Assert.Equal(expected, gcdResult.GreatestCommonDivisor);
    }

    [Fact]
    public void TestPositiveBoth()
    {
        // Arrange
        using Calculator<SecureBigInteger> a = (SecureBigInteger)2; 
        using Calculator<SecureBigInteger> b = new SecureBigInteger("170141183460469231731687303715884105727");

        // Act
        using var result = this.gcd.Compute(a, b);
        
        // Assert
        using Calculator<SecureBigInteger> expected1 = new SecureBigInteger("-85070591730234615865843651857942052863");
        using Calculator<SecureBigInteger> expected2 = new SecureBigInteger("1");
        Assert.Equal(expected1, result.BezoutCoefficients[0]);
        Assert.Equal(expected2, result.BezoutCoefficients[1]);
    }

    [Fact]
    public void Test1NegativeParameterA()
    {
        // Arrange
        using Calculator<SecureBigInteger> a = (SecureBigInteger)(-1); 
        using Calculator<SecureBigInteger> b = new SecureBigInteger("170141183460469231731687303715884105727");

        // Act
        using var result = this.gcd.Compute(a, b);

        // Assert
        using Calculator<SecureBigInteger> expected1 = (SecureBigInteger)1;
        using Calculator<SecureBigInteger> expected2 =  (SecureBigInteger)0;
        Assert.Equal(expected1, result.BezoutCoefficients[0]);
        Assert.Equal(expected2, result.BezoutCoefficients[1]);
    }

    [Fact]
    public void Test2NegativeParameterA()
    {
        // Arrange
        using Calculator<SecureBigInteger> a = (SecureBigInteger)(-4); 
        using Calculator<SecureBigInteger> b = new SecureBigInteger("170141183460469231731687303715884105727");

        // Act
        using var result = this.gcd.Compute(a, b);

        // Assert
        using Calculator<SecureBigInteger> expected1 = new SecureBigInteger("42535295865117307932921825928971026432");
        using Calculator<SecureBigInteger> expected2 =  (SecureBigInteger)1;
        Assert.Equal(expected1, result.BezoutCoefficients[0]);
        Assert.Equal(expected2, result.BezoutCoefficients[1]);
    }

    [Fact]
    public void Test1NegativeParameterB()
    {
        // Arrange
        using Calculator<SecureBigInteger> a = new SecureBigInteger("170141183460469231731687303715884105727"); 
        using Calculator<SecureBigInteger> b = (SecureBigInteger)(-1);

        // Act
        using var result = this.gcd.Compute(a, b);

        // Assert
        using Calculator<SecureBigInteger> expected1 = (SecureBigInteger)0;
        using Calculator<SecureBigInteger> expected2 =  (SecureBigInteger)1;
        Assert.Equal(expected1, result.BezoutCoefficients[0]);
        Assert.Equal(expected2, result.BezoutCoefficients[1]);
    }

    [Fact]
    public void Test2NegativeParameterB()
    {
        // Arrange
        using Calculator<SecureBigInteger> a = new SecureBigInteger("170141183460469231731687303715884105727"); 
        using Calculator<SecureBigInteger> b = (SecureBigInteger)(-4);

        // Act
        using var result = this.gcd.Compute(a, b);

        // Assert
        using Calculator<SecureBigInteger> expected1 = (SecureBigInteger)1;
        using Calculator<SecureBigInteger> expected2 =  new SecureBigInteger("42535295865117307932921825928971026432");
        Assert.Equal(expected1, result.BezoutCoefficients[0]);
        Assert.Equal(expected2, result.BezoutCoefficients[1]);
    }
}