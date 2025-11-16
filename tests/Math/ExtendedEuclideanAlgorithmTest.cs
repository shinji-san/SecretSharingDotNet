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

using SecretSharingDotNet.Math;
using System.Globalization;
using System.Numerics;
using Xunit;

public class ExtendedEuclideanAlgorithmTest
{
    private readonly ExtendedEuclideanAlgorithm<BigInteger> gcd = new ExtendedEuclideanAlgorithm<BigInteger>();

    [Fact]
    public void TestSimpleGcd()
    {
        Calculator<BigInteger> expected = (BigInteger)3;
        var gcdResult = this.gcd.Compute(BigInteger.Parse("6", CultureInfo.InvariantCulture), BigInteger.Parse("9", CultureInfo.InvariantCulture));
        Assert.Equal(expected, gcdResult.GreatestCommonDivisor);
    }

    [Fact]
    public void TestPositiveBoth()
    {
        var result = this.gcd.Compute(BigInteger.Parse("2", CultureInfo.InvariantCulture), BigInteger.Parse("170141183460469231731687303715884105727", CultureInfo.InvariantCulture));
        Assert.Equal(BigInteger.Parse("-85070591730234615865843651857942052863", CultureInfo.InvariantCulture), result.BezoutCoefficients[0].Value);
        Assert.Equal(BigInteger.One, result.BezoutCoefficients[1].Value);
    }

    [Fact]
    public void Test1NegativeParameterA()
    {
        var result = this.gcd.Compute(BigInteger.Parse("-1", CultureInfo.InvariantCulture), BigInteger.Parse("170141183460469231731687303715884105727", CultureInfo.InvariantCulture));
        Assert.Equal(BigInteger.One, result.BezoutCoefficients[0].Value);
        Assert.Equal(BigInteger.Zero, result.BezoutCoefficients[1].Value);
    }

    [Fact]
    public void Test2NegativeParameterA()
    {
        var result = this.gcd.Compute(BigInteger.Parse("-4", CultureInfo.InvariantCulture), BigInteger.Parse("170141183460469231731687303715884105727", CultureInfo.InvariantCulture));
        Assert.Equal(BigInteger.Parse("42535295865117307932921825928971026432", CultureInfo.InvariantCulture), result.BezoutCoefficients[0].Value);
        Assert.Equal(BigInteger.One, result.BezoutCoefficients[1].Value);
    }

    [Fact]
    public void Test1NegativeParameterB()
    {
        var result = this.gcd.Compute(BigInteger.Parse("170141183460469231731687303715884105727", CultureInfo.InvariantCulture), BigInteger.Parse("-1", CultureInfo.InvariantCulture));
        Assert.Equal(BigInteger.Zero, result.BezoutCoefficients[0].Value);
        Assert.Equal(BigInteger.One, result.BezoutCoefficients[1].Value);
    }

    [Fact]
    public void Test2NegativeParameterB()
    {
        var result = this.gcd.Compute(BigInteger.Parse("170141183460469231731687303715884105727", CultureInfo.InvariantCulture), BigInteger.Parse("-4", CultureInfo.InvariantCulture));
        Assert.Equal(BigInteger.One, result.BezoutCoefficients[0].Value);
        Assert.Equal(BigInteger.Parse("42535295865117307932921825928971026432", CultureInfo.InvariantCulture), result.BezoutCoefficients[1].Value);
    }
}