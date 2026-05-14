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

namespace SecretSharingDotNetTest.Cryptography.ShamirsSecretSharing.SecureBigInteger;

using SecretSharingDotNet.Cryptography;
using SecretSharingDotNet.Cryptography.SecureInput;
using SecretSharingDotNet.Cryptography.ShamirsSecretSharing;
using SecretSharingDotNet.Math;
using SecretSharingDotNet.Math.Numerics;
using System;
using System.Linq;
using System.Numerics;
using System.Text;
using Xunit;

/// <summary>
/// Roundtrip integration tests covering <see cref="SecretSplitter{TNumber}"/> together with
/// <see cref="SecretReconstructor{TNumber}"/>.
/// </summary>
public class ShamirsSecretSharingTest
{
    /// <summary>
    /// Tests the security level auto-detection of <see cref="SecretSplitter{TNumber}"/>.
    /// </summary>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Performance", "CA1822:MarkMembersAsStatic")]
    [Theory]
    [MemberData(nameof(TestData.SecurityLevelAutoDetectionData), MemberType = typeof(TestData))]
    public void TestSecurityLevelAutoDetection(object secret, int expectedSecurityLevel)
    {
        // Arrange
        using var secretSplitter = new SecretSplitter<SecureBigInteger>();
        using var secretReconstructor = new SecretReconstructor<SecureBigInteger>(new MersenneSafeGcdAlgorithm());

        // Act & Assert
        switch (secret)
        {
            case string password:
                using (var pinnedText = password.ToPinnedSecure())
                using (var s = Secret<SecureBigInteger>.FromText(pinnedText))
                {
                    RunAutoDetectionRoundTrip(secretSplitter, secretReconstructor, s, expectedSecurityLevel,
                        recovered => SecretAssertions.AssertSecretEqualsString(password, recovered));
                }
                break;
            case BigInteger number:
                using (var secretNumber = number.ToSecureBigInteger())
                using (var s = (Secret<SecureBigInteger>)secretNumber)
                {
                    RunAutoDetectionRoundTrip(secretSplitter, secretReconstructor, s, expectedSecurityLevel,
                        recovered =>
                        {
                            using var secureBigInteger = (SecureBigInteger)recovered;
                            var bigInteger = secureBigInteger.ToBigInteger();
                            Assert.Equal(number, bigInteger);
                        });
                }
                break;
            case null:
                return;
        }
    }

    private static void RunAutoDetectionRoundTrip(
        SecretSplitter<SecureBigInteger> secretSplitter,
        SecretReconstructor<SecureBigInteger> secretReconstructor,
        Secret<SecureBigInteger> s,
        int expectedSecurityLevel,
        Action<Secret<SecureBigInteger>> typeAssert)
    {
        using var shares = secretSplitter.MakeShares(3, 7, s);
        Assert.NotNull(shares);
        var subSet1 = shares.Where(p => p.IsIndexOdd).ToArray();
        using var recoveredSecret1 = secretReconstructor.Reconstruction(subSet1);
        var subSet2 = shares.Where(p => p.IsIndexEven).ToArray();
        using var recoveredSecret2 = secretReconstructor.Reconstruction(subSet2);

        typeAssert(recoveredSecret1);
        Assert.Equal(s, recoveredSecret1);
        Assert.Equal(s, recoveredSecret2);
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
        using var secretSplitter = new SecretSplitter<SecureBigInteger>();
        using var secretReconstructor = new SecretReconstructor<SecureBigInteger>(new MersenneSafeGcdAlgorithm());
        using var pinnedPassword = password.ToPinnedSecure();
        using var passwordSecret = Secret<SecureBigInteger>.FromText(pinnedPassword);

        // Act
        using var shares = secretSplitter.MakeShares(3, 7, passwordSecret, splitSecurityLevel);
        var subSet1 = shares.Where(p => p.IsIndexOdd).ToArray();
        using var recoveredSecret1 = secretReconstructor.Reconstruction(subSet1);
        var subSet2 = shares.Where(p => p.IsIndexEven).ToArray();
        using var recoveredSecret2 = secretReconstructor.Reconstruction(subSet2);

        // Assert
        SecretAssertions.AssertSecretEqualsString(password, recoveredSecret1);
        SecretAssertions.AssertSecretEqualsString(password, recoveredSecret2);
        Assert.Equal(expectedSecurityLevel, secretSplitter.SecurityLevel);
    }

    /// <summary>
    /// Tests <see cref="SecretSplitter{TNumber}"/> with <see cref="SecureBigInteger"/> as secret.
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
        using var secretSplitter = new SecretSplitter<SecureBigInteger>();
        using var secretReconstructor = new SecretReconstructor<SecureBigInteger>(new MersenneSafeGcdAlgorithm());
        using var secretNumber = number.ToSecureBigInteger();

        // Act
        using var shares = secretSplitter.MakeShares(3, 7, secretNumber, splitSecurityLevel);
        var subSet1 = shares.Where(p => p.IsIndexOdd).ToArray();
        using var recoveredSecret1 = secretReconstructor.Reconstruction(subSet1);
        var subSet2 = shares.Where(p => p.IsIndexEven).ToArray();
        using var recoveredSecret2 = secretReconstructor.Reconstruction(subSet2);

        // Assert
        Assert.Equal(expectedSecurityLevel, secretSplitter.SecurityLevel);
    }

    /// <summary>
    /// Tests <see cref="SecretSplitter{TNumber}"/> with random <see cref="SecureBigInteger"/> value as secret.
    /// </summary>
    /// <param name="splitSecurityLevel">Initial security level for secret split phase</param>
    /// <param name="expectedSecurityLevel">Expected security level after secret reconstruction</param>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Performance", "CA1822:MarkMembersAsStatic")]
    [Theory]
    [MemberData(nameof(TestData.TestRandomSecretData), MemberType = typeof(TestData))]
    public void TestWithRandomSecret(int splitSecurityLevel, int expectedSecurityLevel)
    {
        // Arrange
        using var secretSplitter = new SecretSplitter<SecureBigInteger>();
        using var secretReconstructor = new SecretReconstructor<SecureBigInteger>(new MersenneSafeGcdAlgorithm());

        // Act
        using var shares = secretSplitter.MakeShares(3, 7, splitSecurityLevel, out var originalSecret);
        using (originalSecret)
        {
            var subSet1 = shares.Where(p => p.IsIndexOdd).ToArray();
            using var recoveredSecret1 = secretReconstructor.Reconstruction(subSet1);
            var subSet2 = shares.Where(p => p.IsIndexEven).ToArray();
            using var recoveredSecret2 = secretReconstructor.Reconstruction(subSet2);

            // Assert
            Assert.Equal(originalSecret, recoveredSecret1);
            Assert.Equal(originalSecret, recoveredSecret2);
            Assert.Equal(expectedSecurityLevel, secretSplitter.SecurityLevel);
        }
    }
    
    /// <summary>
    /// Tests the MakeShares method with a minimum shares number of 1 to be sure that an error occurs.
    /// Only a minimum shares number of greater or equal to 2 is valid.
    /// </summary>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Performance", "CA1822:MarkMembersAsStatic")]
    [Fact]
    public void TestMinimumSharedSecretsMake()
    {
        // Arrange
        using var secretSplitter = new SecretSplitter<SecureBigInteger>();
    
        // Act & Assert
        Assert.Throws<ArgumentOutOfRangeException>(() => secretSplitter.MakeShares(1, 7, 5, out _));
    }
    
    /// <summary>
    /// Tests
    /// </summary>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Performance", "CA1822:MarkMembersAsStatic")]
    [Fact]
    public void TestMinimumSharedSecretsReconstruction()
    {
        // Arrange
        using var secretSplitter = new SecretSplitter<SecureBigInteger>();
        using var secretReconstructor = new SecretReconstructor<SecureBigInteger>(new MersenneSafeGcdAlgorithm());

        // Act & Assert
        using var shares = secretSplitter.MakeShares(2, 7, 13, out var discardedSecret);
        using (discardedSecret)
        {
            using var oneCalc = Calculator<SecureBigInteger>.One;
            var subSet = shares.Where(p => p.Index == oneCalc).ToArray();
            Assert.Throws<ArgumentOutOfRangeException>(() => secretReconstructor.Reconstruction(subSet));
        }
    }

    /// <summary>
    /// Tests
    /// </summary>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Performance", "CA1822:MarkMembersAsStatic")]
    [Fact]
    public void TestShareThreshold()
    {
        // Arrange
        using var secretSplitter = new SecretSplitter<SecureBigInteger>();
        using var secretReconstructor = new SecretReconstructor<SecureBigInteger>(new MersenneSafeGcdAlgorithm());

        // Act
        using var shares = secretSplitter.MakeShares(3, 7, 51, out var originalSecret);
        using (originalSecret)
        {
            var subSet = shares.Take(2).ToArray();
            using var secret = secretReconstructor.Reconstruction(subSet);

            // Assert
            Assert.NotEqual(originalSecret, secret);
        }
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
        using var secretSplitter = new SecretSplitter<SecureBigInteger>();
        using var secretReconstructor = new SecretReconstructor<SecureBigInteger>(new MersenneSafeGcdAlgorithm());
        using var pinnedLong = longSecret.ToPinnedSecure();
        using var longSecretValue = Secret<SecureBigInteger>.FromText(pinnedLong);

        // Act
        using var shares = secretSplitter.MakeShares(3, 7, longSecretValue, 1024);
        var subSet1 = shares.Where(p => p.IsIndexOdd).ToArray();
        using var recoveredSecret1 = secretReconstructor.Reconstruction(subSet1);
        var subSet2 = shares.Where(p => p.IsIndexEven).ToArray();
        using var recoveredSecret2 = secretReconstructor.Reconstruction(subSet2);

        // Assert
        SecretAssertions.AssertSecretEqualsString(longSecret, recoveredSecret1);
        SecretAssertions.AssertSecretEqualsString(longSecret, recoveredSecret2);
    }
    
    /// <summary>
    /// Tests the secret reconstruction from an array of shares represented by strings
    /// </summary>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Performance", "CA1822:MarkMembersAsStatic")]
    [Fact]
    public void TestReconstructFromStringArray()
    {
        // Arrange
        using var secretReconstructor = new SecretReconstructor<SecureBigInteger>(new MersenneSafeGcdAlgorithm());
        using var lines = TestData.GetPredefinedShares().ToPinnedSecureShareLines();

        // Act
        using Shares<SecureBigInteger> shares = Shares<SecureBigInteger>.FromTextLines(lines);
        using var secret = secretReconstructor.Reconstruction(shares);

        // Assert
        SecretAssertions.AssertSecretEqualsString(TestData.DefaultTestPassword, secret);
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

        using var secretReconstructor = new SecretReconstructor<SecureBigInteger>(new MersenneSafeGcdAlgorithm());
        using var blob = sharesChunk.ToString().ToPinnedSecure();

        // Act
        using Shares<SecureBigInteger> shares = Shares<SecureBigInteger>.FromText(blob);
        using var secret = secretReconstructor.Reconstruction(shares);

        // Assert
        SecretAssertions.AssertSecretEqualsString(TestData.DefaultTestPassword, secret);
    }

    /// <summary>
    /// Tests whether or not bug #60 occurs [Reconstruction fails at random].
    /// </summary>
    [Theory(Skip = "Takes to long to run. SecureBigInteger is not performant enough.")]
    [MemberData(nameof(TestData.ByteArraySize), MemberType = typeof(TestData))]
    public void ReconstructionFailsAtRnd(int byteArraySize)
    {
        // Arrange
        int ok = 0;
        const int total = 1000;
        using var secretSplitter = new SecretSplitter<SecureBigInteger>();
        using var secretReconstructor = new SecretReconstructor<SecureBigInteger>(new MersenneSafeGcdAlgorithm());
        var rng = new Random();

        // Act
        for (int i = 0; i < total; i++)
        {
            var message = new byte[byteArraySize];
            rng.NextBytes(message);
            const int n = 5;
            var s = Convert.ToBase64String(message);
            using var pinnedBase64 = s.ToPinnedSecure();
            using var secret = Secret<SecureBigInteger>.FromBase64(pinnedBase64);
            using var shares = secretSplitter.MakeShares((n + 1) / 2, n, secret);
            using var reconstructedSecret = secretReconstructor.Reconstruction(shares.Take((n + 1) / 2).ToArray());
            using var reconstructedBase64 = reconstructedSecret.ToBase64CharArray();
            var reconstructed =
                Convert.FromBase64String(new string(reconstructedBase64.PoolArray, 0, reconstructedBase64.Length));
            if (message.SequenceEqual(reconstructed))
                ok++;
        }

        // Assert
        Assert.Equal(1.0, (double)ok / total);
    }
}