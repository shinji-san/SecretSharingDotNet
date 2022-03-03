// ----------------------------------------------------------------------------
// <copyright file="SharesTest.cs" company="Private">
// Copyright (c) 2022 All Rights Reserved
// </copyright>
// <author>Sebastian Walther</author>
// <date>05/12/2021 5:54:09 PM</date>
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
        /// A positive test number as secret (value is 2000).
        /// </summary>
        public static BigInteger DefaultPosTestNumber => 20000;

        /// <summary>
        /// A negative test number as secret (value is 2000).
        /// </summary>
        public static BigInteger DefaultNegTestNumber => -20000;

        /// <summary>
        /// Gets a list of data for tests with number as secret.
        /// Provides also split security level followed by expected split security level.
        /// </summary>
        public static IEnumerable<object[]> TestNumberData =>
            new List<object[]>
            {
                new object[] {5, 31, DefaultPosTestNumber},
                new object[] {17, 31, DefaultPosTestNumber},
                new object[] {127, 127, DefaultPosTestNumber},
                new object[] {130, 521, DefaultPosTestNumber},
                new object[] {500, 521, DefaultPosTestNumber},
                new object[] {1279, 1279, DefaultPosTestNumber},

                new object[] {5, 31, DefaultNegTestNumber},
                new object[] {17, 31, DefaultNegTestNumber},
                new object[] {127, 127, DefaultNegTestNumber},
                new object[] {130, 521, DefaultNegTestNumber},
                new object[] {500, 521, DefaultNegTestNumber},
                new object[] {1279, 1279, DefaultNegTestNumber }
            };

        /// <summary>
        /// Gets a list of data for tests with strings as secret
        /// Provides also split security level followed by expected split security level.
        /// </summary>
        public static IEnumerable<object[]> TestPasswordData =>
            new List<object[]>
            {
                new object[] {5, 31, " "},
                new object[] {5, 31, "0"},
                new object[] {5, 31, "A"},
                new object[] {5, 31, "Z"},
                new object[] {5, 31, "ÿ"},
                new object[] {5, 521, DefaultTestPassword},
                new object[] {17, 521, DefaultTestPassword},
                new object[] {127, 521, DefaultTestPassword},
                new object[] {130, 521, DefaultTestPassword},
                new object[] {500, 521, DefaultTestPassword},
                new object[] {1279, 1279, DefaultTestPassword}
            };

        /// <summary>
        /// Gets a list of data for tests with random secret
        /// Provides also split security level, combine security level followed by expected security level.
        /// </summary>
        public static IEnumerable<object[]> TestRandomSecretData =>
            new List<object[]>
            {
                new object[] {5, 13},
                new object[] {7, 13},
                new object[] {13, 13},
                new object[] {17, 17},
                new object[] {127, 127},
                new object[] {130, 521},
                new object[] {500, 521},
                new object[] {521, 521},
                new object[] {1024, 1279},
                new object[] {1279, 1279}
            };

        /// <summary>
        /// Gets a list of data for tests with number as secret
        /// </summary>
        public static IEnumerable<object[]> SecurityLevelAutoDetectionData =>
            new List<object[]>
            {
                new object[] {DefaultPosTestNumber, 31},
                new object[] {DefaultTestPassword, 521},
            };

        /// <summary>
        /// A set of pre-defined shares for reconstruction tests
        /// </summary>
        public static string[] GetPredefinedShares() => new[]
        {
            "01-0131621CFFE838F31347293CC1093C91C7BF50F64AD0F3F09AAF1844F26EECC7F84A23376E5786E8B34DDDFAC957F025201A42114D4C114B42DBC70B96453A19D600",
            "02-520CE6164D5030CC3670DE39F29EE241A5CC70B5FE5001C1C33A6551C5DE34065B486FAAEA4B51C738352496E78F36096915FF7FE6870E741B859AE72C8D0EF1BC01",
            "03-3C92F0EF5536528BD77B3FF9E9BF62120B27CC3D7F8249709BA15D28794FD9BA26F8E35975DD609C8EB6D4D158A8D2A9DAF1364CCCB2F77A8BFD7793C4D67C87B400",
            "04-BDC281A7199B9E30F6694C7AA86CBC02F9CE628FCC64CCFE21E401C90DC1D9E55B5A81450E0CB567B5D1EEAD1DA1C40775AFE975FECCCC5F9244600F5D2285DCBC01",
            "05-D79D993D987E15BC923A05BD2DA5EF126FC434AAE6F7896C5702523383333687FA6E476DB5D74D29AD86722A367A0C23384E17FD7CD68D22305A535BF66F27F0D500",
            "06-882338B2D1E0B62DADED69C17969FC426D07428ECD3B82B93BFC4D67D9A6EE9E023636D16A402BE175D55F47A233AAFB23CEBFE147CF3AC3643E517790BF63C2FF01",
            "07-D2535D05C6C1828545837A878CB9E292F3978A3B8130B5E5CED1F564101B032D74AF4D712E464D8F0FBEB60462CD9D91382FE3235FB7D34130F159632B113A533A01"

        };

        /// <summary>
        /// A set of pre-defined shares for reconstruction tests (Legacy mode for v0.6.0 or older)
        /// </summary>
        public static string[] GetPredefinedSharesLegacy() => new[]
        {
            "01-A096198683E02AA999D66B4710E69E0118EB81511E5971B3DFA1916DBC00A1B2B12F21802A4B350A562DFDD0376A2D930FCD5AFFEFA553FEB0F739F063B452E962",
            "02-D71CFE40BF6AB68BF92C24E9D5C8C5C3AB02714E9C001761B0F71D2C627995E65932DB4EE3F85827C14CD756B6D1D4731F4E5E442E97717C21975A062C6EB9910201",
            "03-ED9212311F9F0EA88E0349E5A7A8E3462D4739F7DDF611099301A53BF169DD9BF8072E6C2A096B57415E8E917B36F6A12F830ACFBAD3597A51DE6142582D34F9DE01",
            "04-E3F85656A37D33FE585ADA3B8685F88A9CB8DA4BE33B62AB87BF269C69D278D28DB019D8FF7B6B9AD66122818798911D406C5F9F955B0CF840CD4FA4E8F1C21FF800",
            "05-B84ECBB04B06258E5831D8EC705F0490F956554CACCF07488E31A34DCBB2678A192C9E9263515AF080579325DAF7A6E650095DB5BE2E89F5EF63242CDDBB65054E",
            "06-6B946F401839E3578D8842F8673607564422A9F838B202DFA6571A50160BAAC39B7ABB9B55893759403FE17E735436FD615A0311364DD0725EA2DFD9358B1CAAE001",
            "07-FEC9430509166E5BF75F195E6B0A01DD7C1AD65089E35270D1318CA34ADB3F7E149C71F3D52303D514190C8D53AE3F61735F52B2FBB6E16F8C8881ADF25FE70DB001"
        };

        /// <summary>
        /// Gets a list of byte array sizes for several tests
        /// </summary>
        public static IEnumerable<object[]> ByteArraySize =>
            new List<object[]>
            {
                new object[] { 1},
                new object[] { 27},
                new object[] { 32},
                new object[] { 53},
                new object[] { 64},
                new object[] { 77},
                new object[] { 128}
            };

        /// <summary>
        /// Gets a list of secrets of different data types
        /// </summary>
        public static IEnumerable<object[]> MixedSecrets =>
            new List<object[]>
            {
                new object[] { 333331},
                new object[] { -333331},
                new object[] { 2007671},
                new object[] { new BigInteger(2007671)},
                new object[] { new BigInteger(-2007671)},
                new object[] { DefaultPosTestNumber},
                new object[] { DefaultNegTestNumber},
                new object[] { DefaultTestPassword},
                new object[] { new byte[] {0x00}},
                new object[] { new byte[] {0xFF, 0XFF}},
            };
    }
}
