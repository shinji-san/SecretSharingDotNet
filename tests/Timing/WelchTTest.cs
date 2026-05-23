// ----------------------------------------------------------------------------
// <copyright file="WelchTTest.cs" company="Private">
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

/// <summary>
/// Welch's two-sample t-test for unequal variances. Tests the null hypothesis
/// that two samples have the same population mean without assuming equal
/// variances. Suitable for timing-distribution comparisons where the two
/// input classes may have systematically different jitter profiles.
/// </summary>
/// <remarks>
/// For sample sizes typical in CT validation (n ≥ 10⁴ per class) the
/// Welch-Satterthwaite degrees of freedom are well into the regime where
/// Student's t converges to the standard normal, so the two-tailed p-value
/// is computed via a standard-normal CDF approximation
/// (Abramowitz &amp; Stegun 26.2.17, accurate to ~7.5e-8).
/// </remarks>
internal static class WelchTTest
{
    public static WelchResult Compute(long[] samplesA, long[] samplesB)
    {
        if (samplesA is null)
        {
            throw new ArgumentNullException(nameof(samplesA));
        }

        if (samplesB is null)
        {
            throw new ArgumentNullException(nameof(samplesB));
        }

        if (samplesA.Length < 2 || samplesB.Length < 2)
        {
            throw new ArgumentException("Both samples must contain at least two observations.");
        }

        int nA = samplesA.Length;
        int nB = samplesB.Length;
        double meanA = Mean(samplesA);
        double meanB = Mean(samplesB);
        double varA = SampleVariance(samplesA, meanA);
        double varB = SampleVariance(samplesB, meanB);

        double seSquared = varA / nA + varB / nB;
        double t = seSquared > 0 ? (meanA - meanB) / Math.Sqrt(seSquared) : 0.0;

        double df = WelchSatterthwaiteDf(varA, varB, nA, nB);
        double pValue = 2.0 * (1.0 - StandardNormalCdf(Math.Abs(t)));

        return new WelchResult(t, df, pValue, meanA, meanB, varA, varB);
    }

    private static double Mean(long[] xs)
    {
        double sum = 0;
        for (int i = 0; i < xs.Length; i++)
        {
            sum += xs[i];
        }

        return sum / xs.Length;
    }

    private static double SampleVariance(long[] xs, double mean)
    {
        double sum = 0;
        for (int i = 0; i < xs.Length; i++)
        {
            double d = xs[i] - mean;
            sum += d * d;
        }

        return sum / (xs.Length - 1);
    }

    private static double WelchSatterthwaiteDf(double varA, double varB, int nA, int nB)
    {
        double a = varA / nA;
        double b = varB / nB;
        double num = (a + b) * (a + b);
        double den = (a * a / (nA - 1)) + (b * b / (nB - 1));
        return den > 0 ? num / den : nA + nB - 2;
    }

    // Abramowitz & Stegun 26.2.17 — standard-normal CDF via polynomial of t = 1/(1+px).
    private static double StandardNormalCdf(double x)
    {
        if (x < 0)
        {
            return 1.0 - StandardNormalCdf(-x);
        }

        const double p = 0.2316419;
        const double a1 = 0.319381530;
        const double a2 = -0.356563782;
        const double a3 = 1.781477937;
        const double a4 = -1.821255978;
        const double a5 = 1.330274429;

        double t = 1.0 / (1.0 + p * x);
        double phi = Math.Exp(-x * x / 2.0) / Math.Sqrt(2.0 * Math.PI);
        double poly = ((((a5 * t + a4) * t + a3) * t + a2) * t + a1) * t;
        return 1.0 - phi * poly;
    }
}

internal readonly struct WelchResult
{
    public WelchResult(double t, double df, double pValue, double meanA, double meanB, double varA, double varB)
    {
        this.TStatistic = t;
        this.DegreesOfFreedom = df;
        this.PValue = pValue;
        this.MeanA = meanA;
        this.MeanB = meanB;
        this.VarianceA = varA;
        this.VarianceB = varB;
    }

    public double TStatistic { get; }

    public double DegreesOfFreedom { get; }

    public double PValue { get; }

    public double MeanA { get; }

    public double MeanB { get; }

    public double VarianceA { get; }

    public double VarianceB { get; }
}

#endif