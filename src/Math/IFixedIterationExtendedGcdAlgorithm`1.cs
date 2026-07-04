// ----------------------------------------------------------------------------
// <copyright file="IFixedIterationExtendedGcdAlgorithm`1.cs" company="Private">
// Copyright (c) 2026 All Rights Reserved
// </copyright>
// <author>Sebastian Walther</author>
// <date>07/04/2026 12:00:00 PM</date>
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

namespace SecretSharingDotNet.Math;

/// <summary>
/// Capability marker for extended-GCD strategies whose iteration count is fixed on public
/// parameters (operand bit length, configured Mersenne exponent) and does not vary with
/// secret operand values — removing the operand-value-dependent iteration-count side channel
/// of a plain extended-Euclidean GCD.
/// </summary>
/// <typeparam name="TNumber">Numeric data type (An integer type)</typeparam>
/// <remarks>
/// <para>
/// This interface adds no members over <see cref="IExtendedGcdAlgorithm{TNumber}"/>; it
/// exists to type-tag the fixed-iteration members of the GCD-strategy family. The tag is
/// load-bearing rather than documentary: the fixed-iteration reconstructor
/// (<c>FixedIterationSecretReconstructor&lt;TNumber&gt;</c>) accepts only implementations of
/// this interface, so a variable-time strategy cannot be supplied to it by mistake — the
/// mispairing becomes a compile-time error instead of a silent side-channel.
/// </para>
/// <para>
/// <see cref="MersenneSafeGcdAlgorithm{TNumber}"/> implements this marker.
/// <see cref="ExtendedEuclideanAlgorithm{TNumber}"/> deliberately does not: its iteration
/// count is variable on the operand values.
/// </para>
/// <para>
/// This marker asserts iteration-count / control-flow operand-independence, <b>not</b>
/// per-operation uniform wall-clock timing: an implementation's per-iteration cost may still
/// vary with secret operands (see the implementing type's threat-model documentation for its
/// exact scope — for example <see cref="MersenneSafeGcdAlgorithm{TNumber}"/> is
/// "outer-iteration-count constant-time" but not per-iteration uniform on the
/// <c>SecureBigInteger</c> backend). Like the rest of the library's constant-time surface it
/// is best-effort against passive timing analysis and has not been audited against active
/// co-located attackers, and it is only meaningful when the underlying
/// <see cref="Calculator{TNumber}"/> arithmetic is itself constant-time (the
/// <c>SecureBigInteger</c> backend). See the Security &amp; Threat Model section of the README.
/// </para>
/// </remarks>
public interface IFixedIterationExtendedGcdAlgorithm<TNumber> : IExtendedGcdAlgorithm<TNumber>;
