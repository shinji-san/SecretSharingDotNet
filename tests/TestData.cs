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

namespace SecretSharingDotNetTest;

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
            new object[] {13, 31, DefaultPosTestNumber},
            new object[] {17, 31, DefaultPosTestNumber},
            new object[] {127, 127, DefaultPosTestNumber},
            new object[] {130, 521, DefaultPosTestNumber},
            new object[] {500, 521, DefaultPosTestNumber},
            new object[] {1279, 1279, DefaultPosTestNumber},

            new object[] {13, 31, DefaultNegTestNumber},
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
            new object[] {13, 31, " "},
            new object[] {13, 31, "0"},
            new object[] {13, 31, "A"},
            new object[] {13, 31, "Z"},
            new object[] {13, 31, "ÿ"},
            new object[] {13, 521, DefaultTestPassword},
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
            new object[] {13, 13},
            new object[] {17, 17},
            new object[] {31, 31},
            new object[] {61, 61},
            new object[] {89, 89},
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
    /// <remarks>The reconstruction with these shares should be result in <see cref="DefaultTestPassword"/></remarks>
    public static string[] GetPredefinedShares() =>
    [
        "01-0131621CFFE838F31347293CC1093C91C7BF50F64AD0F3F09AAF1844F26EECC7F84A23376E5786E8B34DDDFAC957F025201A42114D4C114B42DBC70B96453A19D600",
        "02-520CE6164D5030CC3670DE39F29EE241A5CC70B5FE5001C1C33A6551C5DE34065B486FAAEA4B51C738352496E78F36096915FF7FE6870E741B859AE72C8D0EF1BC01",
        "03-3C92F0EF5536528BD77B3FF9E9BF62120B27CC3D7F8249709BA15D28794FD9BA26F8E35975DD609C8EB6D4D158A8D2A9DAF1364CCCB2F77A8BFD7793C4D67C87B400",
        "04-BDC281A7199B9E30F6694C7AA86CBC02F9CE628FCC64CCFE21E401C90DC1D9E55B5A81450E0CB567B5D1EEAD1DA1C40775AFE975FECCCC5F9244600F5D2285DCBC01",
        "05-D79D993D987E15BC923A05BD2DA5EF126FC434AAE6F7896C5702523383333687FA6E476DB5D74D29AD86722A367A0C23384E17FD7CD68D22305A535BF66F27F0D500",
        "06-882338B2D1E0B62DADED69C17969FC426D07428ECD3B82B93BFC4D67D9A6EE9E023636D16A402BE175D55F47A233AAFB23CEBFE147CF3AC3643E517790BF63C2FF01",
        "07-D2535D05C6C1828545837A878CB9E292F3978A3B8130B5E5CED1F564101B032D74AF4D712E464D8F0FBEB60462CD9D91382FE3235FB7D34130F159632B113A533A01"
    ];

    /// <summary>
    /// Gets a list of byte array sizes for several tests
    /// </summary>
    public static IEnumerable<object[]> ByteArraySize =>
        new List<object[]>
        {
            new object[] { 1},
            new object[] { 2},
            new object[] { 3},
            new object[] { 4},
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