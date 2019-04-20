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
    using System;
    using System.Linq;
    using System.Numerics;
    using System.Reflection;
    using Xunit;

    using Cryptography;
    using Math;

    public class ShamirsSecretSharingTest
    {
        /// <summary>
        /// Checks the following condition: denominator * DivMod(numerator, denominator, prime) % prime == numerator
        /// ToDo: Find another technical solution for this test. Code redundancy.
        /// </summary>
        [Fact]
        public void TestDivMod()
        {
            Func<Calculator<BigInteger>, Calculator<BigInteger> , Calculator<BigInteger>, Calculator<BigInteger>> divMod = (denominator, numerator, prime) =>
            {
                var gcd = new ExtendedEuclideanAlgorithm<BigInteger> ();
                var result = gcd.Compute (denominator, prime);
                return numerator * result.BezoutCoefficients[0] * result.GreatestCommonDivisor;
            };

            Calculator<BigInteger> d = (BigInteger)3000;
            Calculator<BigInteger> n = (BigInteger)3000;
            Calculator<BigInteger> p = Calculator<BigInteger>.Two.Pow (127) - Calculator<BigInteger>.One;
            Assert.Equal(n, d * divMod(d, n, p) % p);
        }

        /// <summary>
        /// Tests <see cref="ShamirsSecretSharing{TNumber}"/> with <see cref="string"/> as secret
        /// </summary>
        [Fact]
        public void TestPassword()
        {
            string password = "Hello World!!";
            var sss = new ShamirsSecretSharing<BigInteger>(new ExtendedEuclideanAlgorithm<BigInteger> (), 127);
            var x = sss.MakeShares (3, 7, password);
            var secret = x.Item1;
            var subSet1 = x.Item2.Where (p => p.X.IsEven).ToList ();
            var recoveredSecret1 = sss.Reconstruction(subSet1.ToArray());
            var subSet2 = x.Item2.Where (p => !p.X.IsEven).ToList ();
            var recoveredSecret2 = sss.Reconstruction(subSet2.ToArray());
            Assert.Equal(secret, recoveredSecret1);
            Assert.Equal(secret, recoveredSecret2);
        }

        /// <summary>
        /// Tests <see cref="ShamirsSecretSharing{TNumber}"/> with <see cref="BigInteger"/> as secret
        /// </summary>
        [Fact]
        public void TestNumber()
        {
            BigInteger number = 20000;
            var sss = new ShamirsSecretSharing<BigInteger>(new ExtendedEuclideanAlgorithm<BigInteger> (), 127);
            var x = sss.MakeShares (3, 7, number);
            var secret = x.Item1;
            var subSet1 = x.Item2.Where (p => p.X.IsEven).ToList ();
            var recoveredSecret1 = sss.Reconstruction(subSet1.ToArray());
            var subSet2 = x.Item2.Where (p => !p.X.IsEven).ToList ();
            var recoveredSecret2 = sss.Reconstruction(subSet2.ToArray());
            Assert.Equal(secret, recoveredSecret1);
            Assert.Equal(secret, recoveredSecret2);
        }

        /// <summary>
        /// Tests <see cref="ShamirsSecretSharing{TNumber}"/> with random <see cref="BigInteger"/> value as secret and security level 127
        /// </summary>
        [Fact]
        public void TestRandomSecretWithSecruityLevel127()
        {
            var sss = new ShamirsSecretSharing<BigInteger> (new ExtendedEuclideanAlgorithm<BigInteger> (), 127);
            var x = sss.MakeShares (3, 7);
            var secret = x.Item1;
            var subSet1 = x.Item2.Where (p => p.X.IsEven).ToList ();
            var recoveredSecret1 = sss.Reconstruction(subSet1.ToArray());
            var subSet2 = x.Item2.Where (p => !p.X.IsEven).ToList ();
            var recoveredSecret2 = sss.Reconstruction(subSet2.ToArray());
            Assert.Equal(secret, recoveredSecret1);
            Assert.Equal(secret, recoveredSecret2);
        }

        /// <summary>
        /// Tests <see cref="ShamirsSecretSharing{TNumber}"/> with random <see cref="BigInteger"/> value as secret and security level 5
        /// </summary>
        [Fact]
        public void TestRandomSecretWithSecruityLevel5 ()
        {
            var sss = new ShamirsSecretSharing<BigInteger> (new ExtendedEuclideanAlgorithm<BigInteger> (), 5);
            var x = sss.MakeShares (2, 7);
            var secret = x.Item1;
            var subSet1 = x.Item2.Where (p => p.X.IsEven).ToList ();
            var recoveredSecret1 = sss.Reconstruction(subSet1.ToArray());
            var subSet2 = x.Item2.Where (p => !p.X.IsEven).ToList ();
            var recoveredSecret2 = sss.Reconstruction(subSet2.ToArray());
            Assert.Equal(secret, recoveredSecret1);
            Assert.Equal(secret, recoveredSecret2);
        }

        /// <summary>
        /// Tests <see cref="ShamirsSecretSharing{TNumber}"/> with random <see cref="BigInteger"/> value as secret and security level 130
        /// which is not a Mersenne prime exponent. Next Mersenne prime exponent is 521. The ctor of <see cref="ShamirsSecretSharing{TNumber}"/>
        /// must find 521 as the next Mersenne prime exponent of 130
        /// </summary>
        [Fact]
        public void TestRandomSecretWithSecruityLevel130 ()
        {
            var sss = new ShamirsSecretSharing<BigInteger> (new ExtendedEuclideanAlgorithm<BigInteger> (), 130);
            var x = sss.MakeShares (3, 7);
            var secret = x.Item1;
            var subSet1 = x.Item2.Where (p => p.X.IsEven).ToList ();
            var recoveredSecret1 = sss.Reconstruction(subSet1.ToArray());
            var subSet2 = x.Item2.Where (p => !p.X.IsEven).ToList ();
            var recoveredSecret2 = sss.Reconstruction(subSet2.ToArray());
            Assert.Equal(secret, recoveredSecret1);
            Assert.Equal(secret, recoveredSecret2);
        }

        /// <summary>
        /// Tests <see cref="ShamirsSecretSharing{TNumber}"/> with random <see cref="BigInteger"/> value as secret and security level 500
        /// which is not a Mersenne prime exponent. Next Mersenne prime exponent is 521. The ctor of <see cref="ShamirsSecretSharing{TNumber}"/>
        /// must find 521 as the next Mersenne prime exponent of 500
        /// </summary>
        [Fact]
        public void TestRandomSecretWithSecruityLevel500 ()
        {
            var sss = new ShamirsSecretSharing<BigInteger> (new ExtendedEuclideanAlgorithm<BigInteger> (), 500);
            var x = sss.MakeShares (3, 7);
            var secret = x.Item1;
            var subSet1 = x.Item2.Where (p => p.X.IsEven).ToList ();
            var recoveredSecret1 = sss.Reconstruction(subSet1.ToArray());
            var subSet2 = x.Item2.Where (p => !p.X.IsEven).ToList ();
            var recoveredSecret2 = sss.Reconstruction(subSet2.ToArray());
            Assert.Equal(secret, recoveredSecret1);
            Assert.Equal(secret, recoveredSecret2);
        }

        /// <summary>
        /// Tests
        /// </summary>
        [Fact]
        public void TestMinimumSharedSecretsMake ()
        {
            var sss = new ShamirsSecretSharing<BigInteger> (new ExtendedEuclideanAlgorithm<BigInteger> (), 5);
            Assert.Throws<ArgumentOutOfRangeException>(() => sss.MakeShares (1, 7));
        }

        /// <summary>
        /// Tests
        /// </summary>
        [Fact]
        public void TestMinimumSharedSecretsReconstruction ()
        {
            var sss = new ShamirsSecretSharing<BigInteger> (new ExtendedEuclideanAlgorithm<BigInteger> (), 5);
            var x = sss.MakeShares (2, 7);
            var secret = x.Item1;
            var subSet1 = x.Item2.Where (p => p.X == Calculator<BigInteger>.One).ToList ();
            Assert.Throws<ArgumentOutOfRangeException>(() => sss.Reconstruction(subSet1.ToArray()));
        }
    }
}
