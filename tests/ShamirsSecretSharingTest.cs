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

namespace SecretSharingDotNetTest
{
    using SecretSharingDotNet.Cryptography;
    using SecretSharingDotNet.Math;
    using System;
    using System.Linq;
    using System.Numerics;
    using System.Text;
    using Xunit;

    /// <summary>
    /// Unit test of the <see cref="ShamirsSecretSharing{TNumber}"/> class.
    /// </summary>
    public class ShamirsSecretSharingTest
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
        /// Tests the security level auto-detection of <see cref="ShamirsSecretSharing{TNumber}"/>.
        /// </summary>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Performance", "CA1822:MarkMembersAsStatic")]
        [Theory]
        [MemberData(nameof(TestData.SecurityLevelAutoDetectionData), MemberType = typeof(TestData))]
        public void TestSecurityLevelAutoDetection(object secret, int expectedSecurityLevel)
        {
            var split = new ShamirsSecretSharing<BigInteger>(new ExtendedEuclideanAlgorithm<BigInteger>());
            var combine = new ShamirsSecretSharing<BigInteger>(new ExtendedEuclideanAlgorithm<BigInteger>());

            Shares<BigInteger> shares = null;
            switch (secret)
            {
                case string password:
                    shares = split.MakeShares(3, 7, password);
                    break;
                case BigInteger number:
                    shares = split.MakeShares(3, 7, number);
                    break;
                case null:
                    return;
            }

            Assert.NotNull(shares);
            Assert.True(shares.OriginalSecretExists);
            Assert.NotNull(shares.OriginalSecret);
            var subSet1 = shares.Where(p => p.X.IsEven).ToList();
            var recoveredSecret1 = combine.Reconstruction(subSet1.ToArray());
            var subSet2 = shares.Where(p => !p.X.IsEven).ToList();
            var recoveredSecret2 = combine.Reconstruction(subSet2.ToArray());

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
            Assert.Equal(expectedSecurityLevel, split.SecurityLevel);
        }

        /// <summary>
        /// Tests <see cref="ShamirsSecretSharing{TNumber}"/> with <see cref="string"/> as secret.
        /// </summary>
        /// <param name="splitSecurityLevel">Initial security level for secret split phase</param>
        /// <param name="expectedSecurityLevel">Expected security level after secret reconstruction</param>
        /// <param name="password">A <see cref="string"/> as secret to test with</param>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Performance", "CA1822:MarkMembersAsStatic")]
        [Theory]
        [MemberData(nameof(TestData.TestPasswordData), MemberType = typeof(TestData))]
        public void TestWithPassword(int splitSecurityLevel, int expectedSecurityLevel, string password)
        {
            var split = new ShamirsSecretSharing<BigInteger>(new ExtendedEuclideanAlgorithm<BigInteger>());
            var combine = new ShamirsSecretSharing<BigInteger>(new ExtendedEuclideanAlgorithm<BigInteger>());
            var shares = split.MakeShares(3, 7, password, splitSecurityLevel);
            Assert.True(shares.OriginalSecretExists);
            Assert.NotNull(shares.OriginalSecret);
            var secret = shares.OriginalSecret;
            var subSet1 = shares.Where(p => p.X.IsEven).ToList();
            var recoveredSecret1 = combine.Reconstruction(subSet1.ToArray());
            var subSet2 = shares.Where(p => !p.X.IsEven).ToList();
            var recoveredSecret2 = combine.Reconstruction(subSet2.ToArray());
            Assert.Equal(password, recoveredSecret1);
            Assert.Equal(secret, recoveredSecret1);
            Assert.Equal(secret, recoveredSecret2);
            Assert.Equal(expectedSecurityLevel, split.SecurityLevel);
        }

        /// <summary>
        /// Tests <see cref="ShamirsSecretSharing{TNumber}"/> with <see cref="BigInteger"/> as secret.
        /// </summary>
        /// <param name="splitSecurityLevel">Initial security level for secret split phase</param>
        /// <param name="expectedSecurityLevel">Expected security level after secret reconstruction</param>
        /// <param name="number">An integer number as secret to test with</param>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Performance", "CA1822:MarkMembersAsStatic")]
        [Theory]
        [MemberData(nameof(TestData.TestNumberData), MemberType = typeof(TestData))]
        public void TestWithNumber(int splitSecurityLevel, int expectedSecurityLevel, BigInteger number)
        {
            var split = new ShamirsSecretSharing<BigInteger>(new ExtendedEuclideanAlgorithm<BigInteger>());
            var combine = new ShamirsSecretSharing<BigInteger>(new ExtendedEuclideanAlgorithm<BigInteger>());
            var shares = split.MakeShares(3, 7, number, splitSecurityLevel);
            Assert.True(shares.OriginalSecretExists);
            Assert.NotNull(shares.OriginalSecret);
            var secret = shares.OriginalSecret;
            var subSet1 = shares.Where(p => p.X.IsEven).ToList();
            var recoveredSecret1 = combine.Reconstruction(subSet1.ToArray());
            var subSet2 = shares.Where(p => !p.X.IsEven).ToList();
            var recoveredSecret2 = combine.Reconstruction(subSet2.ToArray());
            Assert.Equal(number, (BigInteger)recoveredSecret1);
            Assert.Equal(secret, recoveredSecret1);
            Assert.Equal(secret, recoveredSecret2);
            Assert.Equal(expectedSecurityLevel, split.SecurityLevel);
        }

        /// <summary>
        /// Tests <see cref="ShamirsSecretSharing{TNumber}"/> with random <see cref="BigInteger"/> value as secret.
        /// </summary>
        /// <param name="splitSecurityLevel">Initial security level for secret split phase</param>
        /// <param name="expectedSecurityLevel">Expected security level after secret reconstruction</param>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Performance", "CA1822:MarkMembersAsStatic")]
        [Theory]
        [MemberData(nameof(TestData.TestRandomSecretData), MemberType = typeof(TestData))]
        public void TestWithRandomSecret(int splitSecurityLevel, int expectedSecurityLevel)
        {
            var split = new ShamirsSecretSharing<BigInteger>(new ExtendedEuclideanAlgorithm<BigInteger>());
            var combine = new ShamirsSecretSharing<BigInteger>(new ExtendedEuclideanAlgorithm<BigInteger>());
            var shares = split.MakeShares(3, 7, splitSecurityLevel);
            Assert.True(shares.OriginalSecretExists);
            Assert.NotNull(shares.OriginalSecret);
            var secret = shares.OriginalSecret;
            var subSet1 = shares.Where(p => p.X.IsEven).ToList();
            var recoveredSecret1 = combine.Reconstruction(subSet1.ToArray());
            var subSet2 = shares.Where(p => !p.X.IsEven).ToList();
            var recoveredSecret2 = combine.Reconstruction(subSet2.ToArray());
            Assert.Equal(secret, recoveredSecret1);
            Assert.Equal(secret, recoveredSecret2);
            Assert.Equal(expectedSecurityLevel, split.SecurityLevel);
        }

        /// <summary>
        /// Tests the MakeShares method with a minimum shares number of 1 to be sure that a error occurs.
        /// Only a minimum shares number of greater or equal to 2 is valid.
        /// </summary>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Performance", "CA1822:MarkMembersAsStatic")]
        [Fact]
        public void TestMinimumSharedSecretsMake()
        {
            var sss = new ShamirsSecretSharing<BigInteger>(new ExtendedEuclideanAlgorithm<BigInteger>());
            Assert.Throws<ArgumentOutOfRangeException>(() => sss.MakeShares(1, 7, 5));
        }

        /// <summary>
        /// Tests
        /// </summary>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Performance", "CA1822:MarkMembersAsStatic")]
        [Fact]
        public void TestMinimumSharedSecretsReconstruction()
        {
            var sss = new ShamirsSecretSharing<BigInteger>(new ExtendedEuclideanAlgorithm<BigInteger>());
            var shares = sss.MakeShares(2, 7, 13);
            var subSet = shares.Where(p => p.X == Calculator<BigInteger>.One).ToList();
            Assert.Throws<ArgumentOutOfRangeException>(() => sss.Reconstruction(subSet.ToArray()));
        }

        /// <summary>
        /// Tests
        /// </summary>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Performance", "CA1822:MarkMembersAsStatic")]
        [Fact]
        public void TestShareThreshold()
        {
            var sss = new ShamirsSecretSharing<BigInteger>(new ExtendedEuclideanAlgorithm<BigInteger>());
            var shares = sss.MakeShares(3, 7, 51);
            var subSet = shares.Take(2).ToList();
            var secret = sss.Reconstruction(subSet.ToArray());
            Assert.NotEqual(shares.OriginalSecret, secret);
        }

        /// <summary>
        /// Tests whether or not bug #40 occurs [Maximum exceeded! (Parameter 'value') Actual value was 10912." #40].
        /// </summary>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Performance", "CA1822:MarkMembersAsStatic")]
        [Fact]
        public void MaximumExceeded()
        {
            const string longSecret =
                "-----BEGIN EC PRIVATE KEY-----MIIBUQIBAQQgxq7AWG9L6uleuTB9q5FGqnHjXF+kD4y9154SLYYKMDqggeMwgeACAQEwLAYHKoZIzj0BAQIhAP////////////////////////////////////7///wvMEQEIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABwRBBHm+Zn753LusVaBilc6HCwcCm/zbLc4o2VnygVsW+BeYSDradyajxGVdpPv8DhEIqP0XtEimhVQZnEfQj/sQ1LgCIQD////////////////////+uq7c5q9IoDu/0l6M0DZBQQIBAaFEA0IABE0XO6I8lZYzXqRQnHP/knSwLex7q77g4J2AN0cVyrADicGlUr6QjVIlIu9NXCHxD2i++ToWjO1zLVdxgNJbUUc=-----END EC PRIVATE KEY-----";
            var split = new ShamirsSecretSharing<BigInteger>(new ExtendedEuclideanAlgorithm<BigInteger>());
            var combine = new ShamirsSecretSharing<BigInteger>(new ExtendedEuclideanAlgorithm<BigInteger>());
            var shares = split.MakeShares(3, 7, longSecret, 1024);
            var subSet1 = shares.Where(p => p.X.IsEven).ToList();
            var recoveredSecret1 = combine.Reconstruction(subSet1.ToArray());
            var subSet2 = shares.Where(p => !p.X.IsEven).ToList();
            var recoveredSecret2 = combine.Reconstruction(subSet2.ToArray());
            Assert.Equal(longSecret, recoveredSecret1);
            Assert.Equal(longSecret, recoveredSecret2);
        }

        /// <summary>
        /// Tests the secret reconstruction from array of shares represented by strings
        /// </summary>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Performance", "CA1822:MarkMembersAsStatic")]
        [Fact]
        public void TestReconstructFromStringArray()
        {
            var combine = new ShamirsSecretSharing<BigInteger>(new ExtendedEuclideanAlgorithm<BigInteger>());
            var secret = combine.Reconstruction(TestData.GetPredefinedShares());
            Assert.Equal(TestData.DefaultTestPassword, secret);
        }

        /// <summary>
        /// Tests the secret reconstruction from shares represented by a single string (separated by newline)
        /// </summary>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Performance", "CA1822:MarkMembersAsStatic")]
        [Fact]
        public void TestReconstructFromString()
        {
            StringBuilder sharesChunk = new StringBuilder();
            foreach (var share in TestData.GetPredefinedShares())
            {
                sharesChunk.AppendLine(share);
            }

            var combine = new ShamirsSecretSharing<BigInteger>(new ExtendedEuclideanAlgorithm<BigInteger>());
            var secret = combine.Reconstruction(sharesChunk.ToString());
            Assert.Equal(TestData.DefaultTestPassword, secret);
        }

        /// <summary>
        /// Tests whether or not bug #60 occurs [Reconstruction fails at random].
        /// </summary>
        [Theory]
        [MemberData(nameof(TestData.ByteArraySize), MemberType = typeof(TestData))]
        public void ReconstructionFailsAtRnd(int byteArraySize)
        {
            int ok = 0;
            const int total = 1000;
            var sss = new ShamirsSecretSharing<BigInteger>(new ExtendedEuclideanAlgorithm<BigInteger>());
            var rng = new Random();
            for (int i = 0; i < total; i++)
            {
                var message = new byte[byteArraySize];
                rng.NextBytes(message);
                const int n = 5;
                var s = Convert.ToBase64String(message);
                var secret = new Secret<BigInteger>(s);
                var shares = sss.MakeShares((n + 1) / 2, n, secret);
                var reconstructed =
                    Convert.FromBase64String(sss.Reconstruction(shares.Take((n + 1) / 2).ToArray())
                        .ToBase64());
                if (message.SequenceEqual(reconstructed))
                    ok++;
            }

            Assert.Equal(1.0, (double)ok / total);
        }
    }
}
