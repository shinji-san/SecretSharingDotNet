// ----------------------------------------------------------------------------
// <copyright file="SecretTest.cs" company="Private">
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
    using System.Xml.Linq;
    using Cryptography;
    using Math;
    using Xunit;

    public class SecretTest
    {
        private Secret<BigInteger> one = new Secret<BigInteger> (Calculator<BigInteger>.One);

        [Fact]
        public void TestSecretEqual ()
        {
            var s2 = new Secret<BigInteger> (Calculator<BigInteger>.One);
            Assert.Equal (this.one, s2);
        }

        [Fact]
        public void TestSecretNotEqual ()
        {
            var s2 = new Secret<BigInteger> (Calculator<BigInteger>.Two);
            Assert.NotEqual (this.one, s2);
        }

        [Fact]
        public void TestSecretToString ()
        {
            string secretText = "P&ssw0rd!";
            Secret<BigInteger> secret = secretText;
            Assert.Equal (secretText, secret.ToString());
        }

        [Fact]
        public void TestSecretNumber()
        {
            BigInteger number = 2007671;
            Secret<BigInteger> secret = number;
            Assert.Equal (number, (BigInteger)secret);
        }

        [Fact]
        public void TestSecretBase64()
        {
            BigInteger number = 333331;
            Secret<BigInteger> secret1 = number;
            string base64 = secret1.ToBase64();
            Secret<BigInteger> secret2 = Secret<BigInteger>.ParseBase64(base64);
            Assert.Equal (base64, secret2.ToBase64());
        }
    }
}