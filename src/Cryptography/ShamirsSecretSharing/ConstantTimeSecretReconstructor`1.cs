// ----------------------------------------------------------------------------
// <copyright file="ConstantTimeSecretReconstructor`1.cs" company="Private">
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

namespace SecretSharingDotNet.Cryptography.ShamirsSecretSharing;

using Math;

/// <summary>
/// A <see cref="SecretReconstructor{TNumber}"/> that is constant-time by construction: it
/// accepts only constant-time extended-GCD strategies
/// (<see cref="IConstantTimeExtendedGcdAlgorithm{TNumber}"/>), so it cannot be paired with
/// a variable-time modular inverse by mistake.
/// </summary>
/// <typeparam name="TNumber">
/// The mathematical type used in the secret reconstruction process.
/// </typeparam>
/// <remarks>
/// <para>
/// Supplying a variable-time strategy such as <see cref="ExtendedEuclideanAlgorithm{TNumber}"/>
/// is a compile-time error here, because it does not carry the
/// <see cref="IConstantTimeExtendedGcdAlgorithm{TNumber}"/> marker. Consumers that need a
/// variable-time strategy (for example the <c>BigInteger</c> backend, where constant time is
/// not a goal) use the base <see cref="SecretReconstructor{TNumber}"/> directly.
/// </para>
/// <para>
/// The parameterless constructor wires the library's recommended constant-time default,
/// <see cref="MersenneSafeGcdAlgorithm{TNumber}"/>. That default may change in a future
/// <b>major</b> version; pass an explicit strategy if you need the choice pinned across
/// upgrades.
/// </para>
/// <para>
/// The constant-time guarantee is scoped and best-effort. It is only meaningful when the
/// underlying <see cref="Math.Calculator{TNumber}"/> arithmetic is itself constant-time
/// (the <c>SecureBigInteger</c> backend); on a variable-time backend this type is
/// constant-time in shape only. Even on <c>SecureBigInteger</c>,
/// <see cref="MersenneSafeGcdAlgorithm{TNumber}"/> guarantees a constant <em>outer</em>
/// iteration count on the public Mersenne exponent, not per-iteration uniform timing — see
/// the Security &amp; Threat Model section of the README and the strategy's own documentation
/// for the exact scope.
/// </para>
/// </remarks>
public sealed class ConstantTimeSecretReconstructor<TNumber> : SecretReconstructor<TNumber>
{
    /// <summary>
    /// Initializes a new instance of the <see cref="ConstantTimeSecretReconstructor{TNumber}"/>
    /// class using the recommended constant-time modular-inverse strategy
    /// (<see cref="MersenneSafeGcdAlgorithm{TNumber}"/>).
    /// </summary>
    /// <remarks>
    /// <para>
    /// The recommended default may change in a future major version. Use one of the
    /// strategy-supplying constructors to pin the choice.
    /// </para>
    /// <para>
    /// This is the only constructor that creates its own GCD strategy rather than receiving
    /// one. That is safe today because no <see cref="IConstantTimeExtendedGcdAlgorithm{TNumber}"/>
    /// implementation is <see cref="System.IDisposable"/>, and the base reconstructor disposes
    /// only the security-level manager, never the GCD strategy. Should a future constant-time
    /// strategy hold disposable state, GCD ownership would need to be tracked on the base
    /// <see cref="SecretReconstructor{TNumber}"/>, since this internally created instance has
    /// no other owner.
    /// </para>
    /// </remarks>
    public ConstantTimeSecretReconstructor() : base(new MersenneSafeGcdAlgorithm<TNumber>()) { }

    /// <summary>
    /// Initializes a new instance of the <see cref="ConstantTimeSecretReconstructor{TNumber}"/>
    /// class with a caller-supplied constant-time extended-GCD strategy.
    /// </summary>
    /// <param name="constantTimeGcd">A constant-time extended greatest common divisor algorithm.</param>
    /// <exception cref="System.ArgumentNullException">
    /// The <paramref name="constantTimeGcd"/> parameter is <see langword="null"/>.
    /// </exception>
    public ConstantTimeSecretReconstructor(IConstantTimeExtendedGcdAlgorithm<TNumber> constantTimeGcd)
        : base(constantTimeGcd) { }

    /// <summary>
    /// Initializes a new instance of the <see cref="ConstantTimeSecretReconstructor{TNumber}"/>
    /// class with a caller-supplied constant-time extended-GCD strategy and a caller-supplied
    /// <see cref="ISecurityLevelManager{TNumber}"/>. Ownership of the manager remains with the
    /// caller; this instance will not dispose it.
    /// </summary>
    /// <param name="constantTimeGcd">A constant-time extended greatest common divisor algorithm.</param>
    /// <param name="securityLevelManager">Manages security level configuration.</param>
    /// <exception cref="System.ArgumentNullException">
    /// The <paramref name="constantTimeGcd"/> or <paramref name="securityLevelManager"/> parameter
    /// is <see langword="null"/>.
    /// </exception>
    public ConstantTimeSecretReconstructor(
        IConstantTimeExtendedGcdAlgorithm<TNumber> constantTimeGcd,
        ISecurityLevelManager<TNumber> securityLevelManager)
        : base(constantTimeGcd, securityLevelManager) { }
}
