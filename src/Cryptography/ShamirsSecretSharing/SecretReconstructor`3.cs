// ----------------------------------------------------------------------------
// <copyright file="SecretReconstructor`3.cs" company="Private">
// Copyright (c) 2025 All Rights Reserved
// </copyright>
// <author>Sebastian Walther</author>
// <date>10/03/2025 01:42:17 AM</date>
// ----------------------------------------------------------------------------

#region License
// ----------------------------------------------------------------------------
// Copyright 2025 Sebastian Walther
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

using Extension;
using Math;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;

/// <summary>
/// Represents a class used for reconstructing secrets using Shamir's Secret Sharing scheme.
/// </summary>
/// <typeparam name="TNumber">The numeric type used in the calculations, typically an integer or big integer.</typeparam>
/// <typeparam name="TExtendedGcdAlgorithm">The type of the implementation for the extended greatest common divisor (GCD) algorithm.</typeparam>
/// <typeparam name="TExtendedGcdResult">The result type returned by the specified extended GCD algorithm.</typeparam>
public class SecretReconstructor<TNumber, TExtendedGcdAlgorithm, TExtendedGcdResult> : IReconstructionUseCase<TNumber>
    where TExtendedGcdAlgorithm : class, IExtendedGcdAlgorithm<TNumber, TExtendedGcdResult>
    where TExtendedGcdResult : struct, IExtendedGcdResult<TNumber>
{
    /// <summary>
    /// Saves the extended greatest common divisor algorithm
    /// </summary>
    private readonly TExtendedGcdAlgorithm extendedGcd;

    /// <summary>
    /// Represents a security level manager that handles the configuration of
    /// security levels and provides the necessary Mersenne prime for secure computations.
    /// </summary>
    private readonly ISecurityLevelManager<TNumber> securityLevelManager;

    /// <summary>
    /// Indicates whether this instance owns <see cref="securityLevelManager"/> and is therefore
    /// responsible for disposing it. <see langword="true"/> when the manager was created internally
    /// by the parameterless constructor; <see langword="false"/> when it was supplied by the caller.
    /// </summary>
    private readonly bool ownsSecurityLevelManager;

    /// <summary>
    /// Disposal flag manipulated atomically via <see cref="Interlocked.Exchange(ref int, int)"/>:
    /// 0 = alive, 1 = disposed.
    /// </summary>
    private int disposed;

    /// <summary>
    /// Initializes a new instance of the <see cref="SecretReconstructor{TNumber, TExtendedGcdAlgorithm, TExtendedGcdResult}"/> class
    /// using a default <see cref="SecurityLevelManager{TNumber}"/>. The created manager is owned by this
    /// instance and disposed together with it.
    /// </summary>
    /// <param name="extendedGcd">Extended greatest common divisor algorithm</param>
    /// <exception cref="T:System.ArgumentNullException">The <paramref name="extendedGcd"/> parameter is <see langword="null"/>.</exception>
    public SecretReconstructor(TExtendedGcdAlgorithm extendedGcd)
    {
        this.extendedGcd = extendedGcd ?? throw new ArgumentNullException(nameof(extendedGcd));
        this.securityLevelManager = new SecurityLevelManager<TNumber>();
        this.ownsSecurityLevelManager = true;
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="SecretReconstructor{TNumber, TExtendedGcdAlgorithm, TExtendedGcdResult}"/> class
    /// with a caller-supplied <see cref="ISecurityLevelManager{TNumber}"/>. Ownership of the manager
    /// remains with the caller; this instance will not dispose it.
    /// </summary>
    /// <param name="extendedGcd">Extended greatest common divisor algorithm</param>
    /// <param name="securityLevelManager">Manages security level configuration</param>
    /// <exception cref="T:System.ArgumentNullException">
    /// The <paramref name="extendedGcd"/> or <paramref name="securityLevelManager"/> parameter is <see langword="null"/>.
    /// </exception>
    public SecretReconstructor(TExtendedGcdAlgorithm extendedGcd, ISecurityLevelManager<TNumber> securityLevelManager)
    {
        this.extendedGcd = extendedGcd ?? throw new ArgumentNullException(nameof(extendedGcd));
        this.securityLevelManager = securityLevelManager ?? throw new ArgumentNullException(nameof(securityLevelManager));
        this.ownsSecurityLevelManager = false;
    }

    /// <summary>
    /// Finalizes an instance of the <see cref="SecretReconstructor{TNumber, TExtendedGcdAlgorithm, TExtendedGcdResult}"/> class.
    /// </summary>
    ~SecretReconstructor()
    {
        this.Dispose(false);
    }

    /// <summary>
    /// Gets the security level (in bits) of the underlying
    /// <see cref="ISecurityLevelManager{TNumber}"/>.
    /// </summary>
    /// <remarks>
    /// Read-only on this type. Each <see cref="Reconstruction"/> call invokes
    /// <see cref="ISecurityLevelManager{TNumber}.AdjustSecurityLevel"/> on the manager,
    /// which fits the level to <c>maximumY</c>; a value pinned by the caller would be
    /// overwritten and is therefore not exposed via a setter. Callers who need to control
    /// the level must inject their own <see cref="ISecurityLevelManager{TNumber}"/> via
    /// the 2-arg constructor and configure it directly.
    /// </remarks>
    /// <exception cref="ObjectDisposedException">This instance has been disposed.</exception>
    public int SecurityLevel
    {
        get
        {
            this.ThrowIfDisposed();
            return this.securityLevelManager.SecurityLevel;
        }
    }

    /// <summary>
    /// Reconstructs the secret (the constant term <c>a₀</c> of the original polynomial) from
    /// <paramref name="shares"/> by Lagrange interpolation in the finite field defined by
    /// <paramref name="prime"/>, evaluated at <c>x = 0</c>.
    /// </summary>
    /// <param name="shares">The k or more shares (distinct-index points) on the polynomial.</param>
    /// <param name="prime">The Mersenne prime modulus that defines the finite field. Must be the
    /// same prime used during share creation.</param>
    /// <returns>The reconstructed secret.</returns>
    /// <exception cref="ArgumentNullException">
    /// <paramref name="shares"/> or <paramref name="prime"/> is <see langword="null"/>.
    /// </exception>
    /// <exception cref="ArgumentOutOfRangeException">
    /// <paramref name="shares"/> contains fewer than two entries.
    /// </exception>
    /// <exception cref="ArgumentException">
    /// Two or more entries in <paramref name="shares"/> share the same <see cref="Share{TNumber}.Index"/>.
    /// </exception>
    /// <remarks>
    /// The <paramref name="shares"/> are borrowed — this method reads <see cref="Share{TNumber}.Index"/>
    /// and <see cref="Share{TNumber}.Value"/> but never disposes them. Ownership of the shares remains
    /// with the caller (typically a <see cref="Shares{TNumber}"/> collection).
    /// </remarks>
    private Secret<TNumber> LagrangeInterpolate(IReadOnlyList<Share<TNumber>> shares)
    {
        if (shares is null)
        {
            throw new ArgumentNullException(nameof(shares));
        }

        int mersenneExponent = this.securityLevelManager.SecurityLevel;

        int numberOfPoints = shares.Count;
        if (numberOfPoints < 2)
        {
            throw new ArgumentOutOfRangeException(nameof(shares), numberOfPoints, ErrorMessages.MinNumberOfSharesLowerThanTwo);
        }

        if (shares.Select(s => s.Index).Distinct().Count() != numberOfPoints)
        {
            throw new ArgumentException(ErrorMessages.ShareIndicesNotDistinct, nameof(shares));
        }

        using var zero = Calculator<TNumber>.Zero;
        var numeratorProducts = new Calculator<TNumber>[numberOfPoints];
        var denominatorProducts = new Calculator<TNumber>[numberOfPoints];
        Calculator<TNumber> denominator = null;
        Calculator<TNumber> numerator = null;
        try
        {
            denominator = Calculator<TNumber>.One;

            for (int i = 0; i < numberOfPoints; i++)
            {
                var numeratorProduct = Calculator<TNumber>.One;
                var denominatorProduct = Calculator<TNumber>.One;
                try
                {
                    for (int j = 0; j < numberOfPoints; j++)
                    {
                        if (i == j)
                        {
                            continue;
                        }

                        using var numeratorTerm = zero - shares[j].Index;
                        using var denominatorTerm = shares[i].Index - shares[j].Index;
                        var numeratorPrev = numeratorProduct;
                        numeratorProduct = numeratorProduct * numeratorTerm;
                        numeratorPrev.Dispose();
                        var denominatorPrev = denominatorProduct;
                        denominatorProduct = denominatorProduct * denominatorTerm;
                        denominatorPrev.Dispose();
                    }

                    numeratorProducts[i] = numeratorProduct;
                    denominatorProducts[i] = denominatorProduct;
                    // Ownership transferred to the *Products arrays; the outer finally
                    // is now responsible. Null the locals so the catch below does not
                    // double-dispose values already owned by the arrays.
                    numeratorProduct = denominatorProduct = null;
                    var denominatorTemp = denominator;
                    denominator *= denominatorProducts[i];
                    denominatorTemp.Dispose();
                }
                catch
                {
                    numeratorProduct?.Dispose();
                    denominatorProduct?.Dispose();
                    throw;
                }
            }

            numerator = zero.Clone();
            for (int i = 0; i < numberOfPoints; i++)
            {
                using var weightedNumerator = numeratorProducts[i] * denominator;
                using var normalizedYCoordinate = shares[i].Value.MersenneModulo(mersenneExponent);
                using var currentNumerator = weightedNumerator * normalizedYCoordinate;
                using var modInversePerPoint = this.DivMod(currentNumerator, denominatorProducts[i]);
                var numeratorTemp = numerator;
                numerator += modInversePerPoint;
                numeratorTemp.Dispose();
            }

            // DivMod returns the result already reduced into [0, p-1], so it is the
            // normalised secret coefficient a0 directly.
            using var a0 = this.DivMod(numerator, denominator);

            return Secret<TNumber>.FromCoefficient(a0);
        }
        finally
        {
            // prime is provided from Mersenne prime provider and is not disposed here.
            // Shares are provided from outside and are not disposed here.
            numerator?.Dispose();
            denominator?.Dispose();
            numeratorProducts.DisposeAll();
            denominatorProducts.DisposeAll();
        }
    }

    /// <summary>
    /// Recovers the secret from the given <paramref name="shares"/> (points with x and y on the polynomial)
    /// </summary>
    /// <param name="shares">For details <see cref="Shares{TNumber}"/></param>
    /// <returns>Re-constructed secret</returns>
    /// <exception cref="ArgumentNullException"><paramref name="shares"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentOutOfRangeException">
    /// <paramref name="shares"/> contains fewer than two entries.
    /// </exception>
    /// <exception cref="ArgumentException">
    /// <paramref name="shares"/> has no maximum y-value, or contains entries with duplicate
    /// <see cref="Share{TNumber}.Index"/> values.
    /// </exception>
    /// <exception cref="ObjectDisposedException">This instance has been disposed.</exception>
    public Secret<TNumber> Reconstruction(Shares<TNumber> shares)
    {
        this.ThrowIfDisposed();
        if (shares is null)
        {
            throw new ArgumentNullException(nameof(shares));
        }

        if (shares.Count < 2)
        {
            throw new ArgumentOutOfRangeException(nameof(shares), ErrorMessages.MinNumberOfSharesLowerThanTwo);
        }

        var shareList = shares.ToArray();
        var maximumY = shareList.Select(share => share.Value).Max();
        if (maximumY is null)
        {
            throw new ArgumentException(ErrorMessages.NoMaximumY, nameof(shares));
        }

        this.securityLevelManager.AdjustSecurityLevel(maximumY);
        return this.LagrangeInterpolate(shareList);
    }

    /// <summary>
    /// Performs division in the finite field defined by the configured Mersenne
    /// prime, returning the modular result of dividing the numerator by the
    /// denominator. The prime modulus and exponent are sourced from
    /// <see cref="securityLevelManager"/>; callers must ensure the manager is
    /// configured before invoking this method (the public
    /// <see cref="Reconstruction"/> entry point handles that automatically).
    /// </summary>
    /// <param name="numerator">The value to be divided.</param>
    /// <param name="denominator">The value by which the numerator is divided.</param>
    /// <returns>The result of the division operation in the finite field, reduced modulo the prime.</returns>
    /// <exception cref="System.ArgumentNullException">
    /// Thrown when the <paramref name="numerator"/> or <paramref name="denominator"/> parameter is null.
    /// </exception>
    /// <exception cref="System.ArgumentException">
    /// Thrown when the <paramref name="denominator"/> is zero (its modular inverse does not exist) or
    /// when the denominator is not invertible modulo the prime (gcd does not equal 1).
    /// </exception>
    /// <exception cref="ObjectDisposedException">This instance has been disposed.</exception>
    internal Calculator<TNumber> DivMod(
        Calculator<TNumber> numerator,
        Calculator<TNumber> denominator)
    {
        this.ThrowIfDisposed();
        if (numerator is null)
        {
            throw new ArgumentNullException(nameof(numerator));
        }

        if (denominator is null)
        {
            throw new ArgumentNullException(nameof(denominator));
        }

        var prime = this.securityLevelManager.MersennePrime;
        int mersenneExponent = this.securityLevelManager.SecurityLevel;

        // Normalize denominator into [0, p-1]
        using var normalizedDenominator = denominator.MersenneModulo(mersenneExponent);
        if (normalizedDenominator.IsZero)
        {
            throw new ArgumentException(ErrorMessages.InverseOfZeroDoesNotExist, nameof(denominator));
        }

        // The extended GCD still operates on the prime VALUE: the algorithm is
        // generic and does not exploit the Mersenne structure. Mersenne-fold
        // optimisation only kicks in for the modulo reductions below.
        using var result = this.extendedGcd.Compute(normalizedDenominator, prime);
        // Check whether the denominator is invertible modulo the prime
        if (!result.GreatestCommonDivisor.IsOne)
        {
            throw new ArgumentException(ErrorMessages.DenominatorIsNotInvertibleModuloPrime, nameof(denominator));
        }

        // Normalize inverse: x mod M_p (Bezout coefficient may be negative)
        using var inverse = result.BezoutCoefficients[0].MersenneModulo(mersenneExponent);

        // Normalize numerator: numerator mod M_p (caller may pass signed values)
        using var normalizedNumerator = numerator.MersenneModulo(mersenneExponent);

        // (numerator * inverse) mod M_p
        using var modInverse = normalizedNumerator * inverse;
        return modInverse.MersenneModulo(mersenneExponent);
    }

    /// <summary>
    /// Releases all resources used by the current instance of the
    /// <see cref="SecretReconstructor{TNumber, TExtendedGcdAlgorithm, TExtendedGcdResult}"/> class.
    /// </summary>
    /// <remarks>
    /// Idempotent and safe to call from multiple threads concurrently. The owned
    /// <see cref="ISecurityLevelManager{TNumber}"/> (when present) is disposed exactly once.
    /// </remarks>
    public void Dispose()
    {
        if (Interlocked.Exchange(ref this.disposed, 1) == 1)
        {
            return;
        }

        this.Dispose(true);
        GC.SuppressFinalize(this);
    }

    /// <summary>
    /// Releases the resources used by the
    /// <see cref="SecretReconstructor{TNumber, TExtendedGcdAlgorithm, TExtendedGcdResult}"/> instance.
    /// </summary>
    /// <param name="disposing">A boolean value indicating whether to release managed resources (<see langword="true"/>)
    /// or only unmanaged resources (<see langword="false"/>).</param>
    /// <remarks>
    /// Disposes the contained <see cref="ISecurityLevelManager{TNumber}"/> only when this instance owns it
    /// (i.e. when constructed via the parameterless-manager overload).
    /// </remarks>
    protected virtual void Dispose(bool disposing)
    {
        if (disposing && this.ownsSecurityLevelManager)
        {
            this.securityLevelManager.Dispose();
        }
    }

    /// <summary>
    /// Throws <see cref="ObjectDisposedException"/> if this instance has already been disposed.
    /// </summary>
    /// <exception cref="ObjectDisposedException">This instance has been disposed.</exception>
    private void ThrowIfDisposed()
    {
        if (Volatile.Read(ref this.disposed) == 1)
        {
            throw new ObjectDisposedException(this.GetType().FullName);
        }
    }
}