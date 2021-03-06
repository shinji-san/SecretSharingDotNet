// ----------------------------------------------------------------------------
// <copyright file="ShamirsSecretSharingTest.cs" company="Private">
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

namespace SecretSharingDotNet.Test
{
    using Cryptography;
    using Math;
    using System;
    using System.Linq;
    using System.Numerics;
    using Xunit;

    public class ShamirsSecretSharingTest
    {
        /// <summary>
        /// A test password as secret.
        /// </summary>
        public const string TestPassword = "Hello World!!";

        /// <summary>
        /// A test number as secret.
        /// </summary>
        private readonly BigInteger testNumber = 20000;

        /// <summary>
        /// Checks the following condition: denominator * DivMod(numerator, denominator, prime) % prime == numerator
        /// ToDo: Find another technical solution for this test. Code redundancy.
        /// </summary>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Performance", "CA1822:MarkMembersAsStatic")]
        [Fact]
        public void TestDivMod()
        {
            Calculator<BigInteger> DivMod(Calculator<BigInteger> denominator, Calculator<BigInteger> numerator, Calculator<BigInteger> prime)
            {
                var gcd = new ExtendedEuclideanAlgorithm<BigInteger>();
                var result = gcd.Compute(denominator, prime);
                return numerator * result.BezoutCoefficients[0] * result.GreatestCommonDivisor;
            }

            Calculator<BigInteger> d = (BigInteger)3000;
            Calculator<BigInteger> n = (BigInteger)3000;
            Calculator<BigInteger> p = Calculator<BigInteger>.Two.Pow (127) - Calculator<BigInteger>.One;
            Assert.Equal(n, d * DivMod(d, n, p) % p);
        }

        /// <summary>
        /// Tests <see cref="ShamirsSecretSharing{TNumber}"/> with <see cref="string"/> as secret.
        /// (Minimum security level is auto detected)
        /// </summary>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Performance", "CA1822:MarkMembersAsStatic")]
        [Fact]
        public void TestPasswordWithSecurityLevelAutoDetected()
        {
            var split = new ShamirsSecretSharing<BigInteger>(new ExtendedEuclideanAlgorithm<BigInteger>());
            var combine = new ShamirsSecretSharing<BigInteger>(new ExtendedEuclideanAlgorithm<BigInteger>());
            var x = split.MakeShares(3, 7, TestPassword);
            var secret = x.Item1;
            var subSet1 = x.Item2.Where(p => p.X.IsEven).ToList();
            var recoveredSecret1 = combine.Reconstruction(subSet1.ToArray());
            var subSet2 = x.Item2.Where(p => !p.X.IsEven).ToList();
            var recoveredSecret2 = combine.Reconstruction(subSet2.ToArray());
            Assert.Equal(TestPassword, recoveredSecret1);
            Assert.Equal(secret, recoveredSecret1);
            Assert.Equal(secret, recoveredSecret2);
            Assert.Equal(521, split.SecurityLevel);
        }

        /// <summary>
        /// Tests <see cref="ShamirsSecretSharing{TNumber}"/> with <see cref="string"/> as secret.
        /// (Security level is pre-defined)
        /// </summary>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Performance", "CA1822:MarkMembersAsStatic")]
        [Fact]
        public void TestPasswordWithSecurityLevel1279()
        {
            var split = new ShamirsSecretSharing<BigInteger>(new ExtendedEuclideanAlgorithm<BigInteger>(), 1279);
            var combine = new ShamirsSecretSharing<BigInteger>(new ExtendedEuclideanAlgorithm<BigInteger>());
            var x = split.MakeShares(3, 7, TestPassword);
            var secret = x.Item1;
            var subSet1 = x.Item2.Where(p => p.X.IsEven).ToList();
            var recoveredSecret1 = combine.Reconstruction(subSet1.ToArray());
            var subSet2 = x.Item2.Where(p => !p.X.IsEven).ToList();
            var recoveredSecret2 = combine.Reconstruction(subSet2.ToArray());
            Assert.Equal(TestPassword, recoveredSecret1);
            Assert.Equal(secret, recoveredSecret1);
            Assert.Equal(secret, recoveredSecret2);
            Assert.Equal(1279, split.SecurityLevel);
        }

        /// <summary>
        /// Tests <see cref="ShamirsSecretSharing{TNumber}"/> with <see cref="BigInteger"/> as secret.
        /// (Minimum security level is auto detected)
        /// </summary>
        [Fact]
        public void TestNumberWithSecurityLevelAutoDetected()
        {
            var split = new ShamirsSecretSharing<BigInteger>(new ExtendedEuclideanAlgorithm<BigInteger>());
            var combine = new ShamirsSecretSharing<BigInteger>(new ExtendedEuclideanAlgorithm<BigInteger>());
            var x = split.MakeShares(3, 7, testNumber);
            var secret = x.Item1;
            var subSet1 = x.Item2.Where(p => p.X.IsEven).ToList();
            var recoveredSecret1 = combine.Reconstruction(subSet1.ToArray());
            var subSet2 = x.Item2.Where(p => !p.X.IsEven).ToList();
            var recoveredSecret2 = combine.Reconstruction(subSet2.ToArray());
            Assert.Equal(testNumber, (BigInteger)recoveredSecret1);
            Assert.Equal(secret, recoveredSecret1);
            Assert.Equal(secret, recoveredSecret2);
            Assert.Equal(17, split.SecurityLevel);
        }

        /// <summary>
        /// Tests <see cref="ShamirsSecretSharing{TNumber}"/> with <see cref="BigInteger"/> as secret.
        /// (Security level is pre-defined)
        /// </summary>
        [Fact]
        public void TestNumberWithSecurityLevel17()
        {
            var split = new ShamirsSecretSharing<BigInteger>(new ExtendedEuclideanAlgorithm<BigInteger>());
            var combine = new ShamirsSecretSharing<BigInteger>(new ExtendedEuclideanAlgorithm<BigInteger>());
            var x = split.MakeShares(3, 7, testNumber);
            var secret = x.Item1;
            var subSet1 = x.Item2.Where(p => p.X.IsEven).ToList();
            var recoveredSecret1 = combine.Reconstruction(subSet1.ToArray());
            var subSet2 = x.Item2.Where(p => !p.X.IsEven).ToList();
            var recoveredSecret2 = combine.Reconstruction(subSet2.ToArray());
            Assert.Equal(testNumber, (BigInteger)recoveredSecret1);
            Assert.Equal(secret, recoveredSecret1);
            Assert.Equal(secret, recoveredSecret2);
            Assert.Equal(17, split.SecurityLevel);
        }

        /// <summary>
        /// Tests <see cref="ShamirsSecretSharing{TNumber}"/> with random <see cref="BigInteger"/> value as secret and security level 127
        /// </summary>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Performance", "CA1822:MarkMembersAsStatic")]
        [Fact]
        public void TestRandomSecretWithSecurityLevel127()
        {
            var split = new ShamirsSecretSharing<BigInteger> (new ExtendedEuclideanAlgorithm<BigInteger> (), 127);
            var combine = new ShamirsSecretSharing<BigInteger>(new ExtendedEuclideanAlgorithm<BigInteger> (), 32);
            var x = split.MakeShares (3, 7);
            var secret = x.Item1;
            var subSet1 = x.Item2.Where (p => p.X.IsEven).ToList ();
            var recoveredSecret1 = combine.Reconstruction(subSet1.ToArray());
            var subSet2 = x.Item2.Where (p => !p.X.IsEven).ToList ();
            var recoveredSecret2 = combine.Reconstruction(subSet2.ToArray());
            Assert.Equal(secret, recoveredSecret1);
            Assert.Equal(secret, recoveredSecret2);
            Assert.Equal(127, split.SecurityLevel);
        }

        /// <summary>
        /// Tests <see cref="ShamirsSecretSharing{TNumber}"/> with random <see cref="BigInteger"/> value as secret and security level 5
        /// </summary>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Performance", "CA1822:MarkMembersAsStatic")]
        [Fact]
        public void TestRandomSecretWithSecurityLevel5 ()
        {
            var split = new ShamirsSecretSharing<BigInteger> (new ExtendedEuclideanAlgorithm<BigInteger> (), 5);
            var combine = new ShamirsSecretSharing<BigInteger>(new ExtendedEuclideanAlgorithm<BigInteger> (), 32);
            var x = split.MakeShares (2, 7);
            var secret = x.Item1;
            var subSet1 = x.Item2.Where (p => p.X.IsEven).ToList ();
            var recoveredSecret1 = combine.Reconstruction(subSet1.ToArray());
            var subSet2 = x.Item2.Where (p => !p.X.IsEven).ToList ();
            var recoveredSecret2 = combine.Reconstruction(subSet2.ToArray());
            Assert.Equal(secret, recoveredSecret1);
            Assert.Equal(secret, recoveredSecret2);
            Assert.Equal(5, split.SecurityLevel);
        }

        /// <summary>
        /// Tests <see cref="ShamirsSecretSharing{TNumber}"/> with random <see cref="BigInteger"/> value as secret and security level 130
        /// which is not a Mersenne prime exponent. Next Mersenne prime exponent is 521. The ctor of <see cref="ShamirsSecretSharing{TNumber}"/>
        /// must find 521 as the next Mersenne prime exponent of 130
        /// </summary>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Performance", "CA1822:MarkMembersAsStatic")]
        [Fact]
        public void TestRandomSecretWithSecurityLevel130 ()
        {
            var split = new ShamirsSecretSharing<BigInteger> (new ExtendedEuclideanAlgorithm<BigInteger> (), 130);
            var combine = new ShamirsSecretSharing<BigInteger> (new ExtendedEuclideanAlgorithm<BigInteger> (), 5);
            var x = split.MakeShares (3, 7);
            var secret = x.Item1;
            var subSet1 = x.Item2.Where (p => p.X.IsEven).ToList ();
            var recoveredSecret1 = combine.Reconstruction(subSet1.ToArray());
            var subSet2 = x.Item2.Where (p => !p.X.IsEven).ToList ();
            var recoveredSecret2 = combine.Reconstruction(subSet2.ToArray());
            Assert.Equal(secret, recoveredSecret1);
            Assert.Equal(secret, recoveredSecret2);
            Assert.Equal(521, split.SecurityLevel);
        }

        /// <summary>
        /// Tests <see cref="ShamirsSecretSharing{TNumber}"/> with random <see cref="BigInteger"/> value as secret and security level 500
        /// which is not a Mersenne prime exponent. Next Mersenne prime exponent is 521. The ctor of <see cref="ShamirsSecretSharing{TNumber}"/>
        /// must find 521 as the next Mersenne prime exponent of 500
        /// </summary>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Performance", "CA1822:MarkMembersAsStatic")]
        [Fact]
        public void TestRandomSecretWithSecruityLevel500 ()
        {
            var split = new ShamirsSecretSharing<BigInteger> (new ExtendedEuclideanAlgorithm<BigInteger> (), 500);
            var combine = new ShamirsSecretSharing<BigInteger> (new ExtendedEuclideanAlgorithm<BigInteger> (), 5);
            var x = split.MakeShares (3, 7);
            var secret = x.Item1;
            var subSet1 = x.Item2.Where (p => p.X.IsEven).ToList ();
            var recoveredSecret1 = combine.Reconstruction(subSet1.ToArray());
            var subSet2 = x.Item2.Where (p => !p.X.IsEven).ToList ();
            var recoveredSecret2 = combine.Reconstruction(subSet2.ToArray());
            Assert.Equal(secret, recoveredSecret1);
            Assert.Equal(secret, recoveredSecret2);
            Assert.Equal(521, split.SecurityLevel);
        }

        /// <summary>
        /// Tests <see cref="ShamirsSecretSharing{TNumber}"/> with random <see cref="BigInteger"/> value as secret and security level 1024
        /// which is not a Mersenne prime exponent. Next Mersenne prime exponent is 1279. The ctor of <see cref="ShamirsSecretSharing{TNumber}"/>
        /// must find 1279 as the next Mersenne prime exponent of 1024
        /// </summary>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Performance", "CA1822:MarkMembersAsStatic")]
        [Fact]
        public void TestRandomSecretWithSecurityLevel1279 ()
        {
            var split = new ShamirsSecretSharing<BigInteger> (new ExtendedEuclideanAlgorithm<BigInteger> (), 1024);
            var combine = new ShamirsSecretSharing<BigInteger> (new ExtendedEuclideanAlgorithm<BigInteger> (), 5);
            var x = split.MakeShares (2, 7);
            var secret = x.Item1;
            var subSet1 = x.Item2.Where (p => p.X.IsEven).ToList ();
            var recoveredSecret1 = combine.Reconstruction(subSet1.ToArray());
            var subSet2 = x.Item2.Where (p => !p.X.IsEven).ToList ();
            var recoveredSecret2 = combine.Reconstruction(subSet2.ToArray());
            Assert.Equal(secret, recoveredSecret1);
            Assert.Equal(secret, recoveredSecret2);
            Assert.Equal(1279, split.SecurityLevel);
        }

        /// <summary>
        /// Tests
        /// </summary>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Performance", "CA1822:MarkMembersAsStatic")]
        [Fact]
        public void TestMinimumSharedSecretsMake ()
        {
            var sss = new ShamirsSecretSharing<BigInteger> (new ExtendedEuclideanAlgorithm<BigInteger> (), 5);
            Assert.Throws<ArgumentOutOfRangeException>(() => sss.MakeShares (1, 7));
        }

        /// <summary>
        /// Tests
        /// </summary>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Performance", "CA1822:MarkMembersAsStatic")]
        [Fact]
        public void TestMinimumSharedSecretsReconstruction ()
        {
            var sss = new ShamirsSecretSharing<BigInteger> (new ExtendedEuclideanAlgorithm<BigInteger> (), 5);
            var x = sss.MakeShares (2, 7);
            var subSet1 = x.Item2.Where (p => p.X == Calculator<BigInteger>.One).ToList ();
            Assert.Throws<ArgumentOutOfRangeException>(() => sss.Reconstruction(subSet1.ToArray()));
        }

        /// <summary>
        /// Tests whether or not the <see cref="InvalidOperationException"/> is thrown if the security level
        /// is not initialized.
        /// </summary>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Performance", "CA1822:MarkMembersAsStatic")]
        [Fact]
        public void TestUninitializedSecurityLevel()
        {
            var sss = new ShamirsSecretSharing<BigInteger>(new ExtendedEuclideanAlgorithm<BigInteger>());
            Assert.Throws<InvalidOperationException>(() => sss.MakeShares(2, 7));
        }

        /// <summary>
        /// Tests whether or not bug #40 occurs [Maximum exceeded! (Parameter 'value') Actual value was 10912." #40].
        /// </summary>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Performance", "CA1822:MarkMembersAsStatic")]
        [Fact]
        public void MaximumExceeded()
        {
            const string longSecret = "-----BEGIN EC PRIVATE KEY-----MIIBUQIBAQQgxq7AWG9L6uleuTB9q5FGqnHjXF+kD4y9154SLYYKMDqggeMwgeACAQEwLAYHKoZIzj0BAQIhAP////////////////////////////////////7///wvMEQEIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABwRBBHm+Zn753LusVaBilc6HCwcCm/zbLc4o2VnygVsW+BeYSDradyajxGVdpPv8DhEIqP0XtEimhVQZnEfQj/sQ1LgCIQD////////////////////+uq7c5q9IoDu/0l6M0DZBQQIBAaFEA0IABE0XO6I8lZYzXqRQnHP/knSwLex7q77g4J2AN0cVyrADicGlUr6QjVIlIu9NXCHxD2i++ToWjO1zLVdxgNJbUUc=-----END EC PRIVATE KEY-----";
            var split = new ShamirsSecretSharing<BigInteger> (new ExtendedEuclideanAlgorithm<BigInteger> (), 1024);
            var combine = new ShamirsSecretSharing<BigInteger> (new ExtendedEuclideanAlgorithm<BigInteger> (), 5);
            var x = split.MakeShares (3, 7, longSecret);
            var subSet1 = x.Item2.Where (p => p.X.IsEven).ToList ();
            var recoveredSecret1 = combine.Reconstruction(subSet1.ToArray());
            var subSet2 = x.Item2.Where (p => !p.X.IsEven).ToList ();
            var recoveredSecret2 = combine.Reconstruction(subSet2.ToArray());
            Assert.Equal(longSecret, recoveredSecret1);
            Assert.Equal(longSecret, recoveredSecret2);
        }
    }
}
