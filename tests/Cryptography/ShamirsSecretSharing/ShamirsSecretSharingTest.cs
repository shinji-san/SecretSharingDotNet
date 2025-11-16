// ----------------------------------------------------------------------------
// <copyright file="ShamirsSecretSharingTest.cs" company="Private">
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

namespace SecretSharingDotNetTest.Cryptography.ShamirsSecretSharing;

using SecretSharingDotNet.Cryptography;
using SecretSharingDotNet.Cryptography.ShamirsSecretSharing;
using SecretSharingDotNet.Math;
using System;
using System.Linq;
using System.Numerics;
using System.Text;
using Xunit;

/// <summary>
/// Unit test of the <see cref="SecretSplitter{TNumber}"/> class.
/// </summary>
public class SecretSplitterTest
{
    /// <summary>
    /// Checks the following condition: denominator * DivMod(numerator, denominator, prime) % prime == numerator
    /// ToDo: Find another technical solution for this test. Code redundancy.
    /// </summary>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Performance", "CA1822:MarkMembersAsStatic")]
    [Fact]
    public void TestDivMod()
    {
        Calculator<BigInteger> DivMod(Calculator<BigInteger> denominator, Calculator<BigInteger> numerator,
            Calculator<BigInteger> prime)
        {
            var gcd = new ExtendedEuclideanAlgorithm<BigInteger>();
            var result = gcd.Compute(denominator, prime);
            return numerator * result.BezoutCoefficients[0] * result.GreatestCommonDivisor;
        }

        Calculator<BigInteger> d = (BigInteger)3000;
        Calculator<BigInteger> n = (BigInteger)3000;
        Calculator<BigInteger> p = Calculator<BigInteger>.Two.Pow(127) - Calculator<BigInteger>.One;
        Assert.Equal(n, d * DivMod(d, n, p) % p);
    }

    /// <summary>
    /// Tests the security level auto-detection of <see cref="SecretSplitter{TNumber}"/>.
    /// </summary>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Performance", "CA1822:MarkMembersAsStatic")]
    [Theory]
    [MemberData(nameof(TestData.SecurityLevelAutoDetectionData), MemberType = typeof(TestData))]
    public void TestSecurityLevelAutoDetection(object secret, int expectedSecurityLevel)
    {
        // Arrange
        var secretSplitter = new SecretSplitter<BigInteger>();
        var secretReconstructor = new SecretReconstructor<BigInteger>(new ExtendedEuclideanAlgorithm<BigInteger>());

        // Act & Assert
        Shares<BigInteger> shares = null;
        switch (secret)
        {
            case string password:
                shares = secretSplitter.MakeShares(3, 7, password);
                break;
            case BigInteger number:
                shares = secretSplitter.MakeShares(3, 7, number);
                break;
            case null:
                return;
        }

        Assert.NotNull(shares);
        Assert.True(shares.OriginalSecretExists);
        Assert.NotNull(shares.OriginalSecret);
        var subSet1 = shares.Where(p => p.X.IsEven).ToList();
        var recoveredSecret1 = secretReconstructor.Reconstruction(subSet1.ToArray());
        var subSet2 = shares.Where(p => !p.X.IsEven).ToList();
        var recoveredSecret2 = secretReconstructor.Reconstruction(subSet2.ToArray());

        switch (secret)
        {
            case string password:
                Assert.Equal(password, recoveredSecret1);
                break;
            case BigInteger number:
                Assert.Equal(number, (BigInteger)recoveredSecret1);
                break;
        }

        Assert.Equal(shares.OriginalSecret, recoveredSecret1);
        Assert.Equal(shares.OriginalSecret, recoveredSecret2);
        Assert.Equal(expectedSecurityLevel, secretSplitter.SecurityLevel);
    }

    /// <summary>
    /// Tests <see cref="SecretSplitter{TNumber}"/> with <see cref="string"/> as secret.
    /// </summary>
    /// <param name="splitSecurityLevel">Initial security level for secret split phase</param>
    /// <param name="expectedSecurityLevel">Expected security level after secret reconstruction</param>
    /// <param name="password">A <see cref="string"/> as secret to test with</param>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Performance", "CA1822:MarkMembersAsStatic")]
    [Theory]
    [MemberData(nameof(TestData.TestPasswordData), MemberType = typeof(TestData))]
    public void TestWithPassword(int splitSecurityLevel, int expectedSecurityLevel, string password)
    {
        // Arrange
        var secretSplitter = new SecretSplitter<BigInteger>();
        var secretReconstructor = new SecretReconstructor<BigInteger>(new ExtendedEuclideanAlgorithm<BigInteger>());

        // Act
        var shares = secretSplitter.MakeShares(3, 7, password, splitSecurityLevel);
        var secret = shares.OriginalSecret;
        var subSet1 = shares.Where(p => p.X.IsEven).ToList();
        var recoveredSecret1 = secretReconstructor.Reconstruction(subSet1.ToArray());
        var subSet2 = shares.Where(p => !p.X.IsEven).ToList();
        var recoveredSecret2 = secretReconstructor.Reconstruction(subSet2.ToArray());

        // Assert
        Assert.True(shares.OriginalSecretExists);
        Assert.NotNull(shares.OriginalSecret);
        Assert.Equal(password, recoveredSecret1);
        Assert.Equal(secret, recoveredSecret1);
        Assert.Equal(secret, recoveredSecret2);
        Assert.Equal(expectedSecurityLevel, secretSplitter.SecurityLevel);
    }

    /// <summary>
    /// Tests <see cref="SecretSplitter{TNumber}"/> with <see cref="BigInteger"/> as secret.
    /// </summary>
    /// <param name="splitSecurityLevel">Initial security level for secret split phase</param>
    /// <param name="expectedSecurityLevel">Expected security level after secret reconstruction</param>
    /// <param name="number">An integer number as secret to test with</param>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Performance", "CA1822:MarkMembersAsStatic")]
    [Theory]
    [MemberData(nameof(TestData.TestNumberData), MemberType = typeof(TestData))]
    public void TestWithNumber(int splitSecurityLevel, int expectedSecurityLevel, BigInteger number)
    {
        // Arrange
        var secretSplitter = new SecretSplitter<BigInteger>();
        var secretReconstructor = new SecretReconstructor<BigInteger>(new ExtendedEuclideanAlgorithm<BigInteger>());

        // Act
        var shares = secretSplitter.MakeShares(3, 7, number, splitSecurityLevel);
        var secret = shares.OriginalSecret;
        var subSet1 = shares.Where(p => p.X.IsEven).ToList();
        var recoveredSecret1 = secretReconstructor.Reconstruction(subSet1.ToArray());
        var subSet2 = shares.Where(p => !p.X.IsEven).ToList();
        var recoveredSecret2 = secretReconstructor.Reconstruction(subSet2.ToArray());

        // Assert
        Assert.True(shares.OriginalSecretExists);
        Assert.NotNull(shares.OriginalSecret);
        Assert.Equal(number, (BigInteger)recoveredSecret1);
        Assert.Equal(secret, recoveredSecret1);
        Assert.Equal(secret, recoveredSecret2);
        Assert.Equal(expectedSecurityLevel, secretSplitter.SecurityLevel);
    }

    /// <summary>
    /// Tests <see cref="SecretSplitter{TNumber}"/> with random <see cref="BigInteger"/> value as secret.
    /// </summary>
    /// <param name="splitSecurityLevel">Initial security level for secret split phase</param>
    /// <param name="expectedSecurityLevel">Expected security level after secret reconstruction</param>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Performance", "CA1822:MarkMembersAsStatic")]
    [Theory]
    [MemberData(nameof(TestData.TestRandomSecretData), MemberType = typeof(TestData))]
    public void TestWithRandomSecret(int splitSecurityLevel, int expectedSecurityLevel)
    {
        // Arrange
        var secretSplitter = new SecretSplitter<BigInteger>();
        var secretReconstructor = new SecretReconstructor<BigInteger>(new ExtendedEuclideanAlgorithm<BigInteger>());

        // Act
        var shares = secretSplitter.MakeShares(3, 7, splitSecurityLevel);
        var secret = shares.OriginalSecret;
        var subSet1 = shares.Where(p => p.X.IsEven).ToList();
        var recoveredSecret1 = secretReconstructor.Reconstruction(subSet1.ToArray());
        var subSet2 = shares.Where(p => !p.X.IsEven).ToList();
        var recoveredSecret2 = secretReconstructor.Reconstruction(subSet2.ToArray());

        // Assert
        Assert.True(shares.OriginalSecretExists);
        Assert.NotNull(shares.OriginalSecret);
        Assert.Equal(secret, recoveredSecret1);
        Assert.Equal(secret, recoveredSecret2);
        Assert.Equal(expectedSecurityLevel, secretSplitter.SecurityLevel);
    }

    /// <summary>
    /// Tests the MakeShares method with a minimum shares number of 1 to be sure that a error occurs.
    /// Only a minimum shares number of greater or equal to 2 is valid.
    /// </summary>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Performance", "CA1822:MarkMembersAsStatic")]
    [Fact]
    public void TestMinimumSharedSecretsMake()
    {
        // Arrange
        var secretSplitter = new SecretSplitter<BigInteger>();

        // Act & Assert
        Assert.Throws<ArgumentOutOfRangeException>(() => secretSplitter.MakeShares(1, 7, 5));
    }

    /// <summary>
    /// Tests
    /// </summary>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Performance", "CA1822:MarkMembersAsStatic")]
    [Fact]
    public void TestMinimumSharedSecretsReconstruction()
    {
        // Arrange
        var secretSplitter = new SecretSplitter<BigInteger>();
        var secretReconstructor = new SecretReconstructor<BigInteger>(new ExtendedEuclideanAlgorithm<BigInteger>());

        // Act & Assert
        var shares = secretSplitter.MakeShares(2, 7, 13);
        var subSet = shares.Where(p => p.X == Calculator<BigInteger>.One).ToList();
        Assert.Throws<ArgumentOutOfRangeException>(() => secretReconstructor.Reconstruction(subSet.ToArray()));
    }

    /// <summary>
    /// Tests
    /// </summary>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Performance", "CA1822:MarkMembersAsStatic")]
    [Fact]
    public void TestShareThreshold()
    {
        // Arrange
        var secretSplitter = new SecretSplitter<BigInteger>();
        var secretReconstructor = new SecretReconstructor<BigInteger>(new ExtendedEuclideanAlgorithm<BigInteger>());

        // Act
        var shares = secretSplitter.MakeShares(3, 7, 51);
        var subSet = shares.Take(2).ToList();
        var secret = secretReconstructor.Reconstruction(subSet.ToArray());

        // Assert
        Assert.NotEqual(shares.OriginalSecret, secret);
    }

    /// <summary>
    /// Tests whether or not bug #40 occurs [Maximum exceeded! (Parameter 'value') Actual value was 10912." #40].
    /// </summary>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Performance", "CA1822:MarkMembersAsStatic")]
    [Fact]
    public void MaximumExceeded()
    {
        // Arrange
        const string longSecret =
            "-----BEGIN EC PRIVATE KEY-----MIIBUQIBAQQgxq7AWG9L6uleuTB9q5FGqnHjXF+kD4y9154SLYYKMDqggeMwgeACAQEwLAYHKoZIzj0BAQIhAP////////////////////////////////////7///wvMEQEIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABwRBBHm+Zn753LusVaBilc6HCwcCm/zbLc4o2VnygVsW+BeYSDradyajxGVdpPv8DhEIqP0XtEimhVQZnEfQj/sQ1LgCIQD////////////////////+uq7c5q9IoDu/0l6M0DZBQQIBAaFEA0IABE0XO6I8lZYzXqRQnHP/knSwLex7q77g4J2AN0cVyrADicGlUr6QjVIlIu9NXCHxD2i++ToWjO1zLVdxgNJbUUc=-----END EC PRIVATE KEY-----";
        var secretSplitter = new SecretSplitter<BigInteger>();
        var secretReconstructor = new SecretReconstructor<BigInteger>(new ExtendedEuclideanAlgorithm<BigInteger>());

        // Act
        var shares = secretSplitter.MakeShares(3, 7, longSecret, 1024);
        var subSet1 = shares.Where(p => p.X.IsEven).ToList();
        var recoveredSecret1 = secretReconstructor.Reconstruction(subSet1.ToArray());
        var subSet2 = shares.Where(p => !p.X.IsEven).ToList();
        var recoveredSecret2 = secretReconstructor.Reconstruction(subSet2.ToArray());

        // Assert
        Assert.Equal(longSecret, recoveredSecret1);
        Assert.Equal(longSecret, recoveredSecret2);
    }

    /// <summary>
    /// Tests the secret reconstruction from an array of shares represented by strings
    /// </summary>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Performance", "CA1822:MarkMembersAsStatic")]
    [Fact]
    public void TestReconstructFromStringArray()
    {
        // Arrange
        var secretReconstructor = new SecretReconstructor<BigInteger>(new ExtendedEuclideanAlgorithm<BigInteger>());

        // Act
        var secret = secretReconstructor.Reconstruction(TestData.GetPredefinedShares());

        // Assert
        Assert.Equal(TestData.DefaultTestPassword, secret);
    }

    /// <summary>
    /// Tests the secret reconstruction from shares represented by a single string (separated by newline)
    /// </summary>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Performance", "CA1822:MarkMembersAsStatic")]
    [Fact]
    public void TestReconstructFromString()
    {
        // Arrange
        var sharesChunk = new StringBuilder();
        foreach (var share in TestData.GetPredefinedShares())
        {
            sharesChunk.AppendLine(share);
        }

        var secretReconstructor = new SecretReconstructor<BigInteger>(new ExtendedEuclideanAlgorithm<BigInteger>());

        // Act
        var secret = secretReconstructor.Reconstruction(sharesChunk.ToString());

        // Assert
        Assert.Equal(TestData.DefaultTestPassword, secret);
    }

    /// <summary>
    /// Tests whether or not bug #60 occurs [Reconstruction fails at random].
    /// </summary>
    [Theory]
    [MemberData(nameof(TestData.ByteArraySize), MemberType = typeof(TestData))]
    public void ReconstructionFailsAtRnd(int byteArraySize)
    {
        // Arrange
        int ok = 0;
        const int total = 1000;
        var secretSplitter = new SecretSplitter<BigInteger>();
        var secretReconstructor = new SecretReconstructor<BigInteger>(new ExtendedEuclideanAlgorithm<BigInteger>());
        var rng = new Random();

        // Act
        for (int i = 0; i < total; i++)
        {
            var message = new byte[byteArraySize];
            rng.NextBytes(message);
            const int n = 5;
            var s = Convert.ToBase64String(message);
            var secret = new Secret<BigInteger>(s);
            var shares = secretSplitter.MakeShares((n + 1) / 2, n, secret);
            var reconstructed =
                Convert.FromBase64String(secretReconstructor.Reconstruction(shares.Take((n + 1) / 2).ToArray())
                    .ToBase64());
            if (message.SequenceEqual(reconstructed))
                ok++;
        }

        // Assert
        Assert.Equal(1.0, (double)ok / total);
    }
}