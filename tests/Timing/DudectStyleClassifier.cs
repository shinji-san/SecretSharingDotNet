// ----------------------------------------------------------------------------
// <copyright file="DudectStyleClassifier.cs" company="Private">
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
using System.Globalization;

/// <summary>
/// Combines percentile-based outlier cropping with Welch's t-test to classify
/// a paired timing sample as either CT-consistent (null hypothesis of equal
/// means not rejected) or variable-time (rejected with high confidence).
/// </summary>
/// <remarks>
/// Mirrors the dudect approach: when GC pauses, OS interrupts and thread
/// preemption inflate the variance of one or both classes, the t-statistic
/// shrinks and a real CT violation can be missed. To guard against this the
/// classifier evaluates Welch's t-test at multiple upper-percentile crops
/// (typically 100% / 95% / 90% / 75% / 50%) and reports the strongest
/// evidence — i.e. the lowest p-value — across all crops. A genuine CT op
/// will yield large p-values at every crop; a variable-time op will betray
/// itself at at least one.
/// </remarks>
internal sealed class DudectStyleClassifier
{
    private readonly double pThreshold;
    private readonly double[] cropPercentiles;

    public DudectStyleClassifier(double pThreshold = 0.001, double[]? cropPercentiles = null)
    {
        if (pThreshold <= 0 || pThreshold >= 1)
        {
            throw new ArgumentOutOfRangeException(nameof(pThreshold));
        }

        this.pThreshold = pThreshold;
        this.cropPercentiles = cropPercentiles ?? new[] { 1.0, 0.95, 0.90, 0.75, 0.50 };
    }

    public ClassificationResult Classify(PairedTimingSamples samples)
    {
        WelchResult bestResult = default;
        double bestPercentile = 0;
        bool any = false;

        foreach (var pct in this.cropPercentiles)
        {
            long[] aCropped = pct >= 1.0
                ? samples.ClassASamples
                : PercentileCropper.CropAbove(samples.ClassASamples, pct);
            long[] bCropped = pct >= 1.0
                ? samples.ClassBSamples
                : PercentileCropper.CropAbove(samples.ClassBSamples, pct);

            if (aCropped.Length < 2 || bCropped.Length < 2)
            {
                continue;
            }

            var result = WelchTTest.Compute(aCropped, bCropped);
            if (!any || result.PValue < bestResult.PValue)
            {
                bestResult = result;
                bestPercentile = pct;
                any = true;
            }
        }

        if (!any)
        {
            throw new InvalidOperationException("No valid percentile crop produced enough samples.");
        }

        bool reject = bestResult.PValue < this.pThreshold;
        return new ClassificationResult(
            isConstantTime: !reject,
            tStatistic: bestResult.TStatistic,
            pValue: bestResult.PValue,
            bestPercentile: bestPercentile,
            samplesA: samples.ClassASamples.Length,
            samplesB: samples.ClassBSamples.Length,
            meanA: bestResult.MeanA,
            meanB: bestResult.MeanB);
    }
}

internal readonly struct ClassificationResult
{
    public ClassificationResult(
        bool isConstantTime,
        double tStatistic,
        double pValue,
        double bestPercentile,
        int samplesA,
        int samplesB,
        double meanA,
        double meanB)
    {
        this.IsConstantTime = isConstantTime;
        this.TStatistic = tStatistic;
        this.PValue = pValue;
        this.BestPercentile = bestPercentile;
        this.SamplesA = samplesA;
        this.SamplesB = samplesB;
        this.MeanA = meanA;
        this.MeanB = meanB;
    }

    public bool IsConstantTime { get; }

    public double TStatistic { get; }

    public double PValue { get; }

    public double BestPercentile { get; }

    public int SamplesA { get; }

    public int SamplesB { get; }

    public double MeanA { get; }

    public double MeanB { get; }

    public string Diagnostic =>
        string.Format(
            CultureInfo.InvariantCulture,
            "{0}: |t|={1:F2}, p={2:E2}, crop={3:F2}, n=({4},{5}), means=({6:F1},{7:F1}) ticks",
            this.IsConstantTime ? "CT-consistent" : "VARIABLE-TIME",
            Math.Abs(this.TStatistic),
            this.PValue,
            this.BestPercentile,
            this.SamplesA,
            this.SamplesB,
            this.MeanA,
            this.MeanB);
}

#endif