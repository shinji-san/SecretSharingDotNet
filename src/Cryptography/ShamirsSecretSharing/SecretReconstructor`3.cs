// ----------------------------------------------------------------------------
// <copyright file="ShamirsSecretSharing`3.cs" company="Private">
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
    /// Gets or sets the security level
    /// </summary>
    /// <remarks>The value is lower than 13 or greater than 43.112.609.</remarks>
    /// <exception cref="T:System.ArgumentOutOfRangeException" accessor="set">The value is lower than 13 or greater than 43.112.609.</exception>
    /// <exception cref="ObjectDisposedException">This instance has been disposed.</exception>
    public int SecurityLevel
    {
        get
        {
            this.ThrowIfDisposed();
            return this.securityLevelManager.SecurityLevel;
        }
        set
        {
            this.ThrowIfDisposed();
            this.securityLevelManager.SecurityLevel = value;
        }
    }

    /// <summary>
    /// Find the y-value for the given x, given n (x, y) points;
    /// k points will define a polynomial of up to kth order.
    /// </summary>
    /// <param name="shares">The shares representing points on the polynomial.</param>
    /// <param name="prime">A prime number must be defined to avoid computation with real numbers. In fact, it is finite field arithmetic.
    /// The prime number must be the same as used for the construction of shares.</param>
    /// <exception cref="ArgumentException"></exception>
    /// <returns>The re-constructed secret.</returns>
    /// <remarks>
    /// The <paramref name="shares"/> are borrowed — this method reads <see cref="Share{TNumber}.Index"/>
    /// and <see cref="Share{TNumber}.Value"/> but never disposes them. Ownership of the shares remains
    /// with the caller (typically a <see cref="Shares{TNumber}"/> collection).
    /// </remarks>
    private Secret<TNumber> LagrangeInterpolate(IReadOnlyList<Share<TNumber>> shares, Calculator<TNumber> prime)
    {
        if (shares is null)
        {
            throw new ArgumentNullException(nameof(shares));
        }

        if (prime is null)
        {
            throw new ArgumentNullException(nameof(prime));
        }

        int numberOfPoints = shares.Count;
        if (shares.Distinct().Count() != numberOfPoints)
        {
            throw new ArgumentException(ErrorMessages.FinitePointsNotDistinct, nameof(shares));
        }

        using var zero = Calculator<TNumber>.Zero;
        var numeratorProducts = new Calculator<TNumber>[numberOfPoints];
        var denominatorProducts = new Calculator<TNumber>[numberOfPoints];
        var denominator = Calculator<TNumber>.One;

        for (int i = 0; i < numberOfPoints; i++)
        {
            var numeratorProduct = Calculator<TNumber>.One;
            var denominatorProduct = Calculator<TNumber>.One;
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
            var denominatorTemp = denominator;
            denominator *= denominatorProducts[i];
            denominatorTemp.Dispose();
        }

        var numerator = zero;
        for (int i = 0; i < numberOfPoints; i++)
        {
            using var weightedNumerator = numeratorProducts[i] * denominator;
            using var normalizedYCoordinate = shares[i].Value.MathematicalModulo(prime);
            using var currentNumerator = weightedNumerator * normalizedYCoordinate;
            using var modInversePerPoint = this.DivMod(currentNumerator, denominatorProducts[i], prime);
            var numeratorTemp = numerator;
            numerator += modInversePerPoint;
            numeratorTemp.Dispose();
        }

        using var modInverse = this.DivMod(numerator, denominator, prime);
        using var secretCoefficient = modInverse + prime;
        // Normalized coefficient a0 is the secret
        using var a0 = secretCoefficient.MathematicalModulo(prime);

        // Disposes all used calculators, but not prime.
        // Prime is provided from Mersenne prime provider and should not be disposed here.
        // Shares are provided from outside and should not be disposed here.
        numerator.Dispose();
        denominator.Dispose();
        numeratorProducts.DisposeAll();
        denominatorProducts.DisposeAll();

        return Secret<TNumber>.FromCoefficient(a0);
    }

    /// <summary>
    /// Recovers the secret from the given <paramref name="shares"/> (points with x and y on the polynomial)
    /// </summary>
    /// <param name="shares">For details <see cref="Shares{TNumber}"/></param>
    /// <returns>Re-constructed secret</returns>
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
        return this.LagrangeInterpolate(shareList, this.securityLevelManager.MersennePrime);
    }

    /// <summary>
    /// Performs division in a finite field, returning the modular result of dividing the numerator by the denominator modulo a given prime.
    /// </summary>
    /// <param name="numerator">The value to be divided.</param>
    /// <param name="denominator">The value by which the numerator is divided.</param>
    /// <param name="prime">The prime modulus for the finite field operations.</param>
    /// <returns>The result of the division operation in the finite field, reduced modulo the prime.</returns>
    /// <exception cref="System.ArgumentNullException">
    /// Thrown when the <paramref name="numerator"/>, <paramref name="denominator"/> or <paramref name="prime"/> parameter is null.
    /// </exception>
    /// <exception cref="System.ArgumentException">
    /// Thrown when the <paramref name="denominator"/> is zero (its modular inverse does not exist) or
    /// when the denominator is not invertible modulo the prime (gcd does not equal 1).
    /// </exception>
    /// <exception cref="ObjectDisposedException">This instance has been disposed.</exception>
    internal Calculator<TNumber> DivMod(
        Calculator<TNumber> numerator,
        Calculator<TNumber> denominator,
        Calculator<TNumber> prime)
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

        if (prime is null)
        {
            throw new ArgumentNullException(nameof(prime));
        }

        // Normalize denominator into [0, p-1]
        using var normalizedDenominator = ModReduce(denominator, prime);
        if (normalizedDenominator.IsZero)
        {
            throw new ArgumentException(ErrorMessages.InverseOfZeroDoesNotExist, nameof(denominator));
        }

        using var result = this.extendedGcd.Compute(normalizedDenominator, prime);
        // Check whether the denominator is invertible modulo the prime
        if (!result.GreatestCommonDivisor.IsOne)
        {
            throw new ArgumentException(ErrorMessages.DenominatorIsNotInvertibleModuloPrime, nameof(denominator));
        }

        // Normalize inverse: x mod prime
        using var inverse = result.BezoutCoefficients[0].MathematicalModulo(prime);

        // Normalize numerator: numerator mod prime
        using var normalizedNumerator = numerator.MathematicalModulo(prime);

        // (numerator * inverse) mod prime
        using var modInverse = normalizedNumerator * inverse;
        return modInverse.MathematicalModulo(prime);
    }

    /// <summary>
    /// Reduces <paramref name="x"/> into the canonical range [0, p-1].
    /// </summary>
    private static Calculator<TNumber> ModReduce(Calculator<TNumber> x, Calculator<TNumber> prime)
    {
        using var r = x.MathematicalModulo(prime);
        return r.Sign < 0 ? r + prime : r.Clone();
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