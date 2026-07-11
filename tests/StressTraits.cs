// ----------------------------------------------------------------------------
// <copyright file="StressTraits.cs" company="Private">
// Copyright (c) 2026 All Rights Reserved
// </copyright>
// <author>Sebastian Walther</author>
// <date>07/11/2026 00:00:00 AM</date>
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

#if NET8_0_OR_GREATER

namespace SecretSharingDotNetTest;

/// <summary>
/// xUnit trait constants for the opt-in concurrency stress tests.
/// </summary>
/// <remarks>
/// Stress tests spawn multiple threads inside a single test method to exercise the library's
/// supported concurrency contract (independent splitter/reconstructor instances used in parallel).
/// They carry the <c>Category=Stress</c> trait so they can be run in isolation or excluded, and are
/// gated to net8.0+ to avoid the intermittent Mono fatal-signal artefacts observed when the
/// .NET Framework target frameworks run under concurrency. Run only the stress category explicitly
/// with <c>--filter "Category=Stress"</c>.
/// </remarks>
internal static class StressTraits
{
    public const string CategoryKey = "Category";

    public const string CategoryValue = "Stress";
}

#endif
