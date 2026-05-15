// ----------------------------------------------------------------------------
// <copyright file="HarnessSelfTest.cs" company="Private">
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

namespace SecretSharingDotNetTest.Timing.Self;

using System;
using SecretSharingDotNet.Math.Numerics;
using Xunit;

/// <summary>
/// Negative controls for the timing-test harness. Each test feeds the
/// classifier an operation that is documented to be variable-time and
/// asserts the harness flags it. If any of these tests pass with
/// <see cref="ClassificationResult.IsConstantTime"/> equal to <c>true</c>,
/// the harness is producing false negatives and the CT validation tests
/// in subsequent phases (D3–D9) cannot be trusted.
/// </summary>
public sealed class HarnessSelfTest
{
    /// <summary>
    /// Tests that the dudect-style classifier flags
    /// <see cref="SecureBigInteger"/>'s <c>Multiply</c> as variable-time when the
    /// harness samples it on two operand-size classes (tiny vs 512-bit). Multiply
    /// is intentionally not constant-time on operand width (its schoolbook inner
    /// loop iterates over both widths), so this is a negative-control self-test
    /// for the harness — if it passes as "constant-time", the harness is producing
    /// false negatives and the CT validation tests downstream cannot be trusted.
    /// </summary>
    [Fact]
    [Trait(TimingTraits.CategoryKey, TimingTraits.CategoryValue)]
    public void Multiply_OnDistinctOperandSizes_DetectedAsVariableTime()
    {
        // Class A: tiny operands — Multiply finishes in microseconds.
        using var smallLeft = new SecureBigInteger(7);
        using var smallRight = new SecureBigInteger(13);

        // Class B: 512-bit operands — Multiply is orders of magnitude slower
        // because the schoolbook inner loop iterates over both operand widths.
        var hugeBytes1 = new byte[64];
        var hugeBytes2 = new byte[64];
        var rng = new Random(42);
        rng.NextBytes(hugeBytes1);
        rng.NextBytes(hugeBytes2);
        hugeBytes1[63] &= 0x7F;
        hugeBytes2[63] &= 0x7F;

        using var hugeLeft = new SecureBigInteger(hugeBytes1, isNegative: false);
        using var hugeRight = new SecureBigInteger(hugeBytes2, isNegative: false);

        var harness = new TimingHarness(sampleSize: 50_000, warmupIterations: 500);
        var samples = harness.MeasurePair(
            classA: () => { using var _ = smallLeft * smallRight; },
            classB: () => { using var _ = hugeLeft * hugeRight; });

        var classifier = new DudectStyleClassifier();
        var result = classifier.Classify(samples);

        Assert.False(
            result.IsConstantTime,
            "Harness self-test failed: SecureBigInteger.Multiply was NOT detected as variable-time. "
            + "The classifier cannot be trusted for CT validation in subsequent phases. "
            + result.Diagnostic);
    }
}

#endif