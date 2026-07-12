// ----------------------------------------------------------------------------
// <copyright file="FixedIterationSecretReconstructor`1.cs" company="Private">
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
/// A <see cref="SecretReconstructor{TNumber}"/> that accepts only fixed-iteration
/// extended-GCD strategies (<see cref="IFixedIterationExtendedGcdAlgorithm{TNumber}"/>) —
/// strategies whose iteration count does not vary with secret operand values. Pairing it
/// with a variable-time strategy is a compile-time error, so the operand-value-dependent
/// iteration-count side channel of a plain extended-Euclidean GCD cannot be reintroduced
/// by mistake.
/// </summary>
/// <typeparam name="TNumber">
/// The mathematical type used in the secret reconstruction process.
/// </typeparam>
/// <remarks>
/// <para>
/// Supplying a variable-time strategy such as <see cref="ExtendedEuclideanAlgorithm{TNumber}"/>
/// is a compile-time error here, because it does not carry the
/// <see cref="IFixedIterationExtendedGcdAlgorithm{TNumber}"/> marker. Consumers that need a
/// variable-time strategy (for example the <c>BigInteger</c> backend, where timing side
/// channels are not a goal) use the base <see cref="SecretReconstructor{TNumber}"/> directly.
/// </para>
/// <para>
/// The parameterless constructor wires the library's recommended fixed-iteration default,
/// <see cref="MersenneSafeGcdAlgorithm{TNumber}"/>. That default may change in a future
/// <b>major</b> version; pass an explicit strategy if you need the choice pinned across
/// upgrades.
/// </para>
/// <para>
/// The guarantee is scoped and relative to a fixed security level: for a given Mersenne
/// modulus, the GCD iteration count depends only on that (public) modulus, not on the secret
/// operand values — which removes the operand-value-dependent iteration-count side channel of
/// a plain extended-Euclidean GCD. It is <b>not</b> a per-operation constant-time guarantee —
/// even on the <c>SecureBigInteger</c> backend, <see cref="MersenneSafeGcdAlgorithm{TNumber}"/>
/// is constant in its <em>outer</em> iteration count but its per-iteration timing is not
/// uniform, and full constant-time in managed .NET is best-effort regardless.
/// </para>
/// <para>
/// The security level is not pinned by this type: the base reconstructor's <c>Reconstruction</c>
/// selects it from the shares — it calls <see cref="ISecurityLevelManager{TNumber}"/>'s
/// <c>AdjustSecurityLevel</c> with the maximum share value — so across reconstructions of
/// different secrets the chosen modulus, and therefore the iteration count, reflects that
/// level. The level is already revealed by the share sizes, so this leaks nothing to anyone
/// who holds or has seen the shares; only a pure-timing observer with no share access could
/// infer the (coarse, usually deployment-fixed) level from it. What this type removes is the
/// operand-value dependence <em>within</em> a level; the level-selection dependence is
/// inherent to <c>Reconstruction</c>. See the Security &amp; Threat Model section of the README
/// and the strategy's own documentation for the exact scope.
/// </para>
/// </remarks>
public sealed class FixedIterationSecretReconstructor<TNumber> : SecretReconstructor<TNumber>
{
    /// <summary>
    /// Initializes a new instance of the <see cref="FixedIterationSecretReconstructor{TNumber}"/>
    /// class using the recommended fixed-iteration modular-inverse strategy
    /// (<see cref="MersenneSafeGcdAlgorithm{TNumber}"/>).
    /// </summary>
    /// <remarks>
    /// <para>
    /// The recommended default may change in a future major version. Use one of the
    /// strategy-supplying constructors to pin the choice.
    /// </para>
    /// <para>
    /// This is the only constructor that creates its own GCD strategy rather than receiving
    /// one. That is safe today because no <see cref="IFixedIterationExtendedGcdAlgorithm{TNumber}"/>
    /// implementation is <see cref="System.IDisposable"/>, and the base reconstructor disposes
    /// only the security-level manager, never the GCD strategy. Should a future fixed-iteration
    /// strategy hold disposable state, GCD ownership would need to be tracked on the base
    /// <see cref="SecretReconstructor{TNumber}"/>, since this internally created instance has
    /// no other owner.
    /// </para>
    /// </remarks>
    public FixedIterationSecretReconstructor() : base(new MersenneSafeGcdAlgorithm<TNumber>()) { }

    /// <summary>
    /// Initializes a new instance of the <see cref="FixedIterationSecretReconstructor{TNumber}"/>
    /// class with a caller-supplied fixed-iteration extended-GCD strategy.
    /// </summary>
    /// <param name="fixedIterationGcd">A fixed-iteration extended greatest common divisor algorithm.</param>
    /// <exception cref="System.ArgumentNullException">
    /// The <paramref name="fixedIterationGcd"/> parameter is <see langword="null"/>.
    /// </exception>
    public FixedIterationSecretReconstructor(IFixedIterationExtendedGcdAlgorithm<TNumber> fixedIterationGcd)
        : base(fixedIterationGcd) { }

    /// <summary>
    /// Initializes a new instance of the <see cref="FixedIterationSecretReconstructor{TNumber}"/>
    /// class with a caller-supplied fixed-iteration extended-GCD strategy and a caller-supplied
    /// <see cref="ISecurityLevelManager{TNumber}"/>. Ownership of the manager remains with the
    /// caller; this instance will not dispose it.
    /// </summary>
    /// <param name="fixedIterationGcd">A fixed-iteration extended greatest common divisor algorithm.</param>
    /// <param name="securityLevelManager">Manages security level configuration.</param>
    /// <exception cref="System.ArgumentNullException">
    /// The <paramref name="fixedIterationGcd"/> or <paramref name="securityLevelManager"/> parameter
    /// is <see langword="null"/>.
    /// </exception>
    public FixedIterationSecretReconstructor(
        IFixedIterationExtendedGcdAlgorithm<TNumber> fixedIterationGcd,
        ISecurityLevelManager<TNumber> securityLevelManager)
        : base(fixedIterationGcd, securityLevelManager) { }
}
