// ----------------------------------------------------------------------------
// <copyright file="MersennePrimeProviderStub.cs" company="Private">
// Copyright (c) 2026 All Rights Reserved
// </copyright>
// <author>Sebastian Walther</author>
// <date>09/18/2026 00:00:00 AM</date>
// ----------------------------------------------------------------------------

#region License
// ----------------------------------------------------------------------------
// Copyright 2026 Sebastian Walther
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

using Moq;
using SecretSharingDotNet.Math;
using System;

/// <summary>
/// Builds <see cref="IMersennePrimeProvider"/> stand-ins with a table of the test's choosing, for
/// tests that need a provider to disagree with the built-in one.
/// </summary>
internal static class MersennePrimeProviderStub
{
    /// <summary>
    /// A strict mock that supports exactly <paramref name="exponents"/>. Only the membership check
    /// is set up; any other member throws, so a test using it also shows that nothing else about
    /// the provider was consulted.
    /// </summary>
    /// <param name="exponents">The exponents the provider reports as supported.</param>
    /// <returns>The mock, so the test can verify the calls made on it.</returns>
    internal static Mock<IMersennePrimeProvider> Supporting(params int[] exponents)
    {
        var provider = new Mock<IMersennePrimeProvider>(MockBehavior.Strict);
        provider
            .Setup(p => p.IsValidMersennePrimeExponent(It.IsAny<int>()))
            .Returns((int exponent) => Array.IndexOf(exponents, exponent) >= 0);
        return provider;
    }
}
