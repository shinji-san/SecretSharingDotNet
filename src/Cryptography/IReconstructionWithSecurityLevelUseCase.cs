// ----------------------------------------------------------------------------
// <copyright file="IReconstructionWithSecurityLevelUseCase.cs" company="Private">
// Copyright (c) 2026 All Rights Reserved
// </copyright>
// <author>Sebastian Walther</author>
// <date>09/14/2026 10:00:00 PM</date>
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
namespace SecretSharingDotNet.Cryptography;

using ShamirsSecretSharing;
using System;

/// <summary>
/// Reconstruction with the finite field named by the caller instead of inferred from the shares.
/// </summary>
/// <typeparam name="TNumber">Numeric data type</typeparam>
/// <remarks>
/// <para>
/// Inherits <see cref="IReconstructionUseCase{TNumber}"/>, so one injected abstraction offers both
/// call shapes. It is a <em>separate</em> interface because adding a member to
/// <see cref="IReconstructionUseCase{TNumber}"/> would break every external implementation, and a
/// default interface member is not available on <c>netstandard2.0</c> or the <c>net4x</c> targets.
/// </para>
/// <para>
/// <b>Interface inheritance does not create a second DI registration.</b> Registering
/// <c>IReconstructionUseCase&lt;T&gt;</c> leaves this interface unresolvable; a consumer who needs
/// the explicit form registers it as well. The existing registration can stay as it is.
/// </para>
/// <para>
/// This exists for shares that carry no record of the field they were created in — anything split
/// before the level became part of the share, or built from raw coordinates. For shares that do
/// carry a level, <see cref="IReconstructionUseCase{TNumber}.Reconstruction"/> already uses it and
/// needs no help.
/// </para>
/// </remarks>
public interface IReconstructionWithSecurityLevelUseCase<TNumber> : IReconstructionUseCase<TNumber>
{
    /// <summary>
    /// Recovers the secret from <paramref name="shares"/>, interpolating in the field named by
    /// <paramref name="securityLevel"/>.
    /// </summary>
    /// <param name="shares">The k or more shares to reconstruct from.</param>
    /// <param name="securityLevel">
    /// The Mersenne prime exponent the shares were created under. Used <b>as given</b>: it is
    /// never rounded up to the next supported exponent and never silently reduced.
    /// </param>
    /// <returns>The reconstructed secret.</returns>
    /// <remarks>
    /// The caller is responsible for supplying the exponent the split actually used, <em>after</em>
    /// any auto-raise inside <c>MakeShares</c>. A one-byte secret split without an explicit level
    /// lands on 17, which is rarely the number a caller remembers. A wrong but supported exponent
    /// cannot be detected here and will produce a wrong secret or an error, depending on the
    /// values — the same failure this overload exists to avoid, moved from guesswork to a
    /// documented caller obligation.
    /// </remarks>
    /// <exception cref="ArgumentNullException"><paramref name="shares"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentOutOfRangeException">
    /// <paramref name="shares"/> contains fewer than two entries, or
    /// <paramref name="securityLevel"/> is not a supported Mersenne prime exponent.
    /// </exception>
    /// <exception cref="ReconstructionException">
    /// <paramref name="securityLevel"/> contradicts a level recorded on one of the shares, a share
    /// coordinate lies outside the named field, or reconstruction fails for one of the reasons
    /// documented on <see cref="IReconstructionUseCase{TNumber}.Reconstruction"/>.
    /// </exception>
    /// <exception cref="ObjectDisposedException">This instance has been disposed.</exception>
    Secret<TNumber> Reconstruction(Shares<TNumber> shares, int securityLevel);
}
