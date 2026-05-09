// ----------------------------------------------------------------------------
// <copyright file="TimingHarness.cs" company="Private">
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
using System.Diagnostics;

/// <summary>
/// Collects paired timing measurements of two operation variants ("class A"
/// and "class B") for downstream statistical analysis. Used to detect whether
/// an operation's runtime depends on a secret-class distinction in its inputs.
/// </summary>
/// <remarks>
/// <para>
/// The harness JIT-warms both classes for <see cref="warmupIterations"/>
/// iterations, forces a generation-2 GC, then alternates the within-pair
/// ordering of the two classes to remove any cache- or branch-predictor
/// bias coupled to a fixed measurement order.
/// </para>
/// <para>
/// Timing precision is bounded by <see cref="Stopwatch.Frequency"/>
/// (typically 100 ns on modern x86_64). Operations whose mean runtime is
/// shorter than ~10 stopwatch ticks should be measured in batches.
/// </para>
/// </remarks>
internal sealed class TimingHarness
{
    private readonly int sampleSize;
    private readonly int warmupIterations;

    public TimingHarness(int sampleSize = 100_000, int warmupIterations = 1_000)
    {
        if (sampleSize < 2)
        {
            throw new ArgumentOutOfRangeException(nameof(sampleSize));
        }

        if (warmupIterations < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(warmupIterations));
        }

        this.sampleSize = sampleSize;
        this.warmupIterations = warmupIterations;
    }

    public PairedTimingSamples MeasurePair(Action classA, Action classB)
    {
        if (classA is null)
        {
            throw new ArgumentNullException(nameof(classA));
        }

        if (classB is null)
        {
            throw new ArgumentNullException(nameof(classB));
        }

        for (int i = 0; i < this.warmupIterations; i++)
        {
            classA();
            classB();
        }

        GC.Collect();
        GC.WaitForPendingFinalizers();
        GC.Collect();

        var samplesA = new long[this.sampleSize];
        var samplesB = new long[this.sampleSize];

        for (int i = 0; i < this.sampleSize; i++)
        {
            if ((i & 1) == 0)
            {
                samplesA[i] = MeasureOne(classA);
                samplesB[i] = MeasureOne(classB);
            }
            else
            {
                samplesB[i] = MeasureOne(classB);
                samplesA[i] = MeasureOne(classA);
            }
        }

        return new PairedTimingSamples(samplesA, samplesB);
    }

    private static long MeasureOne(Action op)
    {
        long start = Stopwatch.GetTimestamp();
        op();
        long end = Stopwatch.GetTimestamp();
        return end - start;
    }
}

internal readonly struct PairedTimingSamples
{
    public PairedTimingSamples(long[] classASamples, long[] classBSamples)
    {
        this.ClassASamples = classASamples;
        this.ClassBSamples = classBSamples;
    }

    public long[] ClassASamples { get; }

    public long[] ClassBSamples { get; }
}

#endif