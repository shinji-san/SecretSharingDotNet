// ----------------------------------------------------------------------------
// <copyright file="TimingTraits.cs" company="Private">
// Copyright (c) 2026 All Rights Reserved
// </copyright>
// <author>Sebastian Walther</author>
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

namespace SecretSharingDotNetTest.Timing;

/// <summary>
/// xUnit trait constants for the constant-time validation harness.
/// </summary>
/// <remarks>
/// Timing tests are excluded from default <c>dotnet test</c> runs because
/// they are slow (10⁵ paired measurements per test, on the order of minutes)
/// and require a quiet machine for stable results. Run them with
/// <c>--filter "Category=Timing"</c>.
/// </remarks>
internal static class TimingTraits
{
    public const string CategoryKey = "Category";

    public const string CategoryValue = "Timing";
}

#endif