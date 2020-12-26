// ----------------------------------------------------------------------------
// <copyright file="SharesTest.cs" company="Private">
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
    using System.Collections.Generic;
    using System.Numerics;
    using Cryptography;
    using Math;
    using Xunit;

    public class SharesTest
    {
        /// <summary>
        /// Tests the implicit cast  from <see cref="Shares{TNumber}"/> to <see cref="Tuple"/>.
        /// </summary>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Performance", "CA1822:MarkMembersAsStatic")]
        [Fact]
        public void TestSharesToTupleCast()
        {
            var split = new ShamirsSecretSharing<BigInteger>(new ExtendedEuclideanAlgorithm<BigInteger>());
            var shares = split.MakeShares(3, 6, TestData.DefaultTestPassword);
            Tuple<Secret<BigInteger>, ICollection<FinitePoint<BigInteger>>> tuple = shares;
            Assert.NotNull(tuple);
            Assert.NotNull(tuple.Item1);
            Assert.NotNull(tuple.Item2);
            Assert.Equal(6, tuple.Item2.Count);
            Assert.Equal(TestData.DefaultTestPassword, tuple.Item1);
        }


    }
}
