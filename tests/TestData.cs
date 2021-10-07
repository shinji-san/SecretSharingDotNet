// ----------------------------------------------------------------------------
// <copyright file="SharesTest.cs" company="Private">
// Copyright (c) 2021 All Rights Reserved
// </copyright>
// <author>Sebastian Walther</author>
// <date>05/12/2021 5:54:09 PM</date>
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

namespace SecretSharingDotNet
{
    using System.Collections.Generic;
    using System.Numerics;

    public static class TestData
    {
        /// <summary>
        /// A test password as secret.
        /// </summary>
        public const string DefaultTestPassword = "Hello World!!";

        /// <summary>
        /// A test number as secret (value is 2000).
        /// </summary>
        public static BigInteger TestNumber => 20000;

        /// <summary>
        /// Gets a list of data for tests with number as secret
        /// </summary>
        public static IEnumerable<object[]> TestNumberData =>
            new List<object[]>
            {
                new object[] {5, 17, TestNumber},
                new object[] {17, 17, TestNumber},
                new object[] {127, 127, TestNumber},
                new object[] {130, 521, TestNumber},
                new object[] {500, 521, TestNumber},
                new object[] {1279, 1279, TestNumber}
            };

        /// <summary>
        /// Gets a list of data for tests with string as secret
        /// </summary>
        public static IEnumerable<object[]> TestPasswordData =>
            new List<object[]>
            {
                new object[] {5, 521, DefaultTestPassword},
                new object[] {17, 521, DefaultTestPassword},
                new object[] {127, 521, DefaultTestPassword},
                new object[] {130, 521, DefaultTestPassword},
                new object[] {500, 521, DefaultTestPassword},
                new object[] {1279, 1279, DefaultTestPassword}
            };

        /// <summary>
        /// Gets a list of data for tests with random secret
        /// </summary>
        public static IEnumerable<object[]> TestRandomSecretData =>
            new List<object[]>
            {
                new object[] {5, 32, 5},
                new object[] {17, 521, 17},
                new object[] {127, 521, 127},
                new object[] {130, 5, 521},
                new object[] {500, 5, 521},
                new object[] {521, 5, 521},
                new object[] {1024, 5, 1279},
                new object[] {1279, 5, 1279}
            };

        /// <summary>
        /// Gets a list of data for tests with number as secret
        /// </summary>
        public static IEnumerable<object[]> SecurityLevelAutoDetectionData =>
            new List<object[]>
            {
                new object[] {TestNumber, 17},
                new object[] {DefaultTestPassword, 521},
            };

        /// <summary>
        /// A set of pre-defined shares for reconstruction tests
        /// </summary>
        public static string[] GetPredefinedShares() => new[]
        {
            "01-A096198683E02AA999D66B4710E69E0118EB81511E5971B3DFA1916DBC00A1B2B12F21802A4B350A562DFDD0376A2D930FCD5AFFEFA553FEB0F739F063B452E962",
            "02-D71CFE40BF6AB68BF92C24E9D5C8C5C3AB02714E9C001761B0F71D2C627995E65932DB4EE3F85827C14CD756B6D1D4731F4E5E442E97717C21975A062C6EB9910201",
            "03-ED9212311F9F0EA88E0349E5A7A8E3462D4739F7DDF611099301A53BF169DD9BF8072E6C2A096B57415E8E917B36F6A12F830ACFBAD3597A51DE6142582D34F9DE01",
            "04-E3F85656A37D33FE585ADA3B8685F88A9CB8DA4BE33B62AB87BF269C69D278D28DB019D8FF7B6B9AD66122818798911D406C5F9F955B0CF840CD4FA4E8F1C21FF800",
            "05-B84ECBB04B06258E5831D8EC705F0490F956554CACCF07488E31A34DCBB2678A192C9E9263515AF080579325DAF7A6E650095DB5BE2E89F5EF63242CDDBB65054E",
            "06-6B946F401839E3578D8842F8673607564422A9F838B202DFA6571A50160BAAC39B7ABB9B55893759403FE17E735436FD615A0311364DD0725EA2DFD9358B1CAAE001",
            "07-FEC9430509166E5BF75F195E6B0A01DD7C1AD65089E35270D1318CA34ADB3F7E149C71F3D52303D514190C8D53AE3F61735F52B2FBB6E16F8C8881ADF25FE70DB001"
        };
    }
}
