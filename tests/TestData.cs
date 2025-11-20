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
            new object[] {13, 17, " "},
            new object[] {17, 17, " "},
            new object[] {31, 31, " "},
            new object[] {13, 17, "0"},
            new object[] {17, 17, "0"},
            new object[] {31, 31, "0"},
            new object[] {13, 17, "A"},
            new object[] {17, 17, "A"},
            new object[] {31, 31, "A"},
            new object[] {13, 17, "Z"},
            new object[] {17, 17, "Z"},
            new object[] {31, 31, "Z"},
            new object[] {13, 31, "ÿ"},
            new object[] {17, 31, "ÿ"},
            new object[] {31, 31, "ÿ"},
            new object[] {13, 127, DefaultTestPassword},
            new object[] {17, 127, DefaultTestPassword},
            new object[] {127, 127, DefaultTestPassword},
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
            new object[] {DefaultTestPassword, 127},
        };

    /// <summary>
    /// A set of pre-defined shares for reconstruction tests
    /// </summary>
    /// <remarks>The reconstruction with these shares should be result in <see cref="DefaultTestPassword"/></remarks>
    public static string[] GetPredefinedShares() =>
    [
        "01-F4E6D807C77FD480E7ABF046A8578331",
        "02-217BDFE1200E1C93D2C4A3A8249E3630",
        "03-CE2180FA7CCB2DA633B77D4696131A7C",
        "04-FDDABA51DBB709BA0A837E20FDB72D15",
        "05-ABA68FE73BD3AFCE5728A636598B717B",
        "06-DB84FEBB9E1D20E41AA7F488AA8DE52E",
        "07-8B7507CF03975AFA53FF6917F1BE892F"
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