// ----------------------------------------------------------------------------
// <copyright file="PercentileCropper.cs" company="Private">
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

using System;
using System.Linq;

/// <summary>
/// Crops a sample array at a given percentile threshold from above. Used to
/// remove outlier observations (GC pauses, thread preemption, OS interrupts)
/// that would otherwise inflate variance and mask real timing differences.
/// </summary>
internal static class PercentileCropper
{
    /// <summary>
    /// Returns the subset of <paramref name="samples"/> whose values are at
    /// or below the <paramref name="percentile"/>-th percentile.
    /// </summary>
    /// <param name="samples">The input timing samples.</param>
    /// <param name="percentile">A value in <c>(0, 1]</c>. <c>1.0</c> is a no-op.</param>
    public static long[] CropAbove(long[] samples, double percentile)
    {
        if (samples is null)
        {
            throw new ArgumentNullException(nameof(samples));
        }

        if (percentile <= 0 || percentile > 1)
        {
            throw new ArgumentOutOfRangeException(nameof(percentile));
        }

        if (samples.Length == 0 || percentile >= 1.0)
        {
            return samples;
        }

        var sorted = samples.OrderBy(x => x).ToArray();
        int idx = (int)Math.Ceiling(sorted.Length * percentile) - 1;
        long threshold = sorted[Math.Max(0, idx)];
        return samples.Where(x => x <= threshold).ToArray();
    }
}

#endif