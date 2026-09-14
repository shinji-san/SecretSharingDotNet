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
public class SecretReconstructor<TNumber, TExtendedGcdAlgorithm, TExtendedGcdResult> : IReconstructionWithSecurityLevelUseCase<TNumber>
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
    /// Read-only on this type. Every reconstruction sets the level itself — from the exponent the
    /// shares record, from the one the caller named, or, only when neither is available, from the
    /// share values through <see cref="ISecurityLevelManager{TNumber}.AdjustSecurityLevel"/>. A
    /// value pinned in advance through a setter would be overwritten in all three cases, which is
    /// why none is offered. Callers who need to name the field pass it to
    /// <see cref="IReconstructionWithSecurityLevelUseCase{TNumber}.Reconstruction(Shares{TNumber}, int)"/>;
    /// callers who need to control the manager itself inject their own via the 2-arg constructor.
    /// After a successful call this property reports the level the interpolation ran under.
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
    /// <paramref name="shares"/> by Lagrange interpolation in the finite field defined by the
    /// Mersenne prime corresponding to <see cref="SecurityLevel"/>, evaluated at <c>x = 0</c>.
    /// The security level must match the one used during share creation.
    /// </summary>
    /// <param name="shares">The k or more shares (distinct-index points) on the polynomial.</param>
    /// <returns>The reconstructed secret.</returns>
    /// <exception cref="ArgumentNullException">
    /// <paramref name="shares"/> is <see langword="null"/>.
    /// </exception>
    /// <exception cref="ArgumentOutOfRangeException">
    /// <paramref name="shares"/> contains fewer than two entries.
    /// </exception>
    /// <exception cref="ReconstructionException">
    /// Two or more entries in <paramref name="shares"/> share the same <see cref="Share{TNumber}.Index"/>,
    /// or the interpolated coefficient carries no payload beyond its mark byte and therefore decodes
    /// to no secret at all.
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

        // Explicit HashSet loop instead of shares.Select(s => s.Index).Distinct().Count()
        // — avoids the SelectIterator + DistinctIterator + enumerator allocations on the
        // unpinned managed heap. Throws on first-duplicate detection instead of after full
        // enumeration; eager-vs-lazy throw on the public x-coordinates yields the same
        // exception type and message, no observable difference on the success path.
        //
        // Indices are hashed through PublicValueEqualityComparer: Calculator.GetHashCode delegates
        // to TNumber.GetHashCode, and the SecureBigInteger backend deliberately hashes only public
        // metadata (sign + limb count) so a value-derived hash of secret material cannot be observed.
        // That makes every small positive one-limb index hash identically, which would collapse this
        // check into one bucket (O(n²)). Indices are public (the X coordinate on the "INDEX-VALUE"
        // wire), so a value-based hash of them is safe and restores O(n).
#if NET8_0_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        var seenIndices = new HashSet<Calculator<TNumber>>(numberOfPoints, PublicValueEqualityComparer<TNumber>.Instance);
#else
        var seenIndices = new HashSet<Calculator<TNumber>>(PublicValueEqualityComparer<TNumber>.Instance);
#endif
        for (int i = 0; i < numberOfPoints; i++)
        {
            if (!seenIndices.Add(shares[i].Index))
            {
                throw new ReconstructionException(ErrorMessages.ShareIndicesNotDistinct);
            }
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

            // Secret.FromCoefficient strips the trailing mark byte, so a coefficient that
            // occupies no more than that byte leaves nothing behind and the Secret constructor
            // rejects it with ArgumentException from two layers down -- an error naming neither
            // the cause nor the operation. Reject it here instead, on the reconstruction
            // contract. The message states only what is provable here: the exponent the
            // interpolation ran under. It does not name a cause, because a tampered share
            // produces exactly the same picture. It also no longer says anything about what
            // the shares do or do not record -- since step 1 they may carry a level, and this
            // method does not yet consult it, so any claim about their metadata would be a
            // claim this code has not checked. Step 2 is where the level is read and where a
            // sharper diagnosis becomes possible.
            if (a0.ByteCount <= Secret<TNumber>.MarkByteCount)
            {
                throw new ReconstructionException(
                    string.Format(ErrorMessages.ReconstructionYieldedNoDecodableSecret, mersenneExponent));
            }

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
    /// <exception cref="ReconstructionException">
    /// <paramref name="shares"/> has no maximum y-value; the shares record different security
    /// levels, or some record one and others do not, so there is no field to choose without being
    /// told; a recorded level is not a supported Mersenne prime exponent; a coordinate lies outside
    /// the recorded field; two entries share the same <see cref="Share{TNumber}.Index"/>; or the
    /// interpolation produces a coefficient that decodes to no secret.
    /// <para>
    /// The last case carries the Mersenne exponent the interpolation ran under and identifies no
    /// cause, because a tampered share is indistinguishable from an ill-fitting field here. It is
    /// reachable only for shares that record no level — where one is recorded, it is used, and the
    /// mismatch that produced this failure does not arise.
    /// </para>
    /// <para>
    /// Where the shares disagree or say nothing, naming the field through
    /// <see cref="IReconstructionWithSecurityLevelUseCase{TNumber}.Reconstruction(Shares{TNumber}, int)"/>
    /// is the way forward.
    /// </para>
    /// </exception>
    /// <exception cref="ObjectDisposedException">This instance has been disposed.</exception>
    public Secret<TNumber> Reconstruction(Shares<TNumber> shares) => this.ReconstructionCore(shares, null);

    /// <inheritdoc cref="IReconstructionWithSecurityLevelUseCase{TNumber}.Reconstruction(Shares{TNumber}, int)"/>
    public Secret<TNumber> Reconstruction(Shares<TNumber> shares, int securityLevel) =>
        this.ReconstructionCore(shares, securityLevel);

    /// <summary>
    /// The single reconstruction path. Both public overloads run through it; they differ only in
    /// where the finite field comes from.
    /// </summary>
    /// <param name="shares">The k or more shares to reconstruct from.</param>
    /// <param name="explicitLevel">
    /// The exponent supplied by the caller, or <see langword="null"/> to take it from the shares.
    /// </param>
    /// <returns>The reconstructed secret.</returns>
    /// <remarks>
    /// <para>
    /// The field is chosen in three phases — determine, validate, commit — so that an input error
    /// is rejected before the manager moves, wherever the manager makes that possible:
    /// </para>
    /// <list type="number">
    /// <item><description>
    /// An explicit exponent is validated and checked against every level the shares record;
    /// contradictory or mixed metadata aborts here, with nothing moved.
    /// </description></item>
    /// <item><description>
    /// The coordinates are checked against the resulting field — but only where the exponent was
    /// asserted from outside the values. Where it was derived from them, the field admits them by
    /// construction.
    /// </description></item>
    /// <item><description>
    /// Only then is the level committed, and read back to catch a manager that normalised it
    /// upward instead of using it as given.
    /// </description></item>
    /// </list>
    /// <para>
    /// Without <see cref="IInspectableSecurityLevelManager{TNumber}"/> the first phase cannot run
    /// for the derived case: learning that manager's answer means letting it commit one. Its own
    /// selection logic is preserved — which is the point — but the state has moved before
    /// validation. That is a supported path, not an error.
    /// </para>
    /// </remarks>
    private Secret<TNumber> ReconstructionCore(Shares<TNumber> shares, int? explicitLevel)
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
        // Explicit loop instead of shareList.Select(share => share.Value).Max() —
        // avoids the SelectArrayIterator + enumerator allocations on the unpinned
        // managed heap. Null-skip matches Enumerable.Max semantics for reference
        // types: the maximum of all non-null values, or null if every value is null.
        Calculator<TNumber> maximumY = null;
        for (int i = 0; i < shareList.Length; i++)
        {
            var candidate = shareList[i].Value;
            if (candidate is null)
            {
                continue;
            }

            if (maximumY is null || candidate > maximumY)
            {
                maximumY = candidate;
            }
        }

        if (maximumY is null)
        {
            throw new ReconstructionException(ErrorMessages.NoMaximumY);
        }

        // Phase 1 — determine a candidate. Nothing below moves the manager except the one
        // fallback branch that says so.
        var recorded = ReadRecordedLevels(shareList);
        int securityLevel;
        bool derivedFromValues = false;
        bool alreadyCommitted = false;

        if (explicitLevel.HasValue)
        {
            securityLevel = explicitLevel.Value;
            this.ValidateExponent(securityLevel, explicitlySupplied: true);
            if (recorded.AnyRecorded && (recorded.Differing || recorded.First != securityLevel))
            {
                throw new ReconstructionException(
                    string.Format(ErrorMessages.ExplicitSecurityLevelContradictsShares, securityLevel));
            }
        }
        else if (recorded.Differing)
        {
            throw new ReconstructionException(ErrorMessages.SharesCarryDifferentSecurityLevels);
        }
        else if (recorded.AnyRecorded && recorded.AnyMissing)
        {
            throw new ReconstructionException(ErrorMessages.SharesCarryMixedSecurityLevelMetadata);
        }
        else if (recorded.AnyRecorded)
        {
            securityLevel = recorded.First;
            this.ValidateExponent(securityLevel, explicitlySupplied: false);
        }
        else
        {
            derivedFromValues = true;
            if (this.securityLevelManager is IInspectableSecurityLevelManager<TNumber> inspectable)
            {
                securityLevel = inspectable.DetermineSecurityLevel(maximumY);
            }
            else
            {
                this.securityLevelManager.AdjustSecurityLevel(maximumY);
                securityLevel = this.securityLevelManager.SecurityLevel;
                alreadyCommitted = true;
            }
        }

        // Phase 2 — validate against the candidate. Skipped where the candidate was derived from
        // the coordinates: that field admits them by construction, and running the check there
        // would change the legacy path this fix leaves alone.
        if (!derivedFromValues)
        {
            ValidateCoordinatesFit(shareList, securityLevel);
        }

        // Phase 3 — commit.
        if (!alreadyCommitted)
        {
            this.CommitSecurityLevel(securityLevel, explicitLevel.HasValue);
        }

        return this.LagrangeInterpolate(shareList);
    }

    /// <summary>
    /// Summarises the security levels the shares record, in one pass and without allocating.
    /// </summary>
    /// <param name="shareList">The shares to inspect.</param>
    /// <returns>
    /// Whether any share records a level, whether any records none, whether two recorded levels
    /// differ, and the first recorded level (meaningful only when <c>AnyRecorded</c>).
    /// </returns>
    private static (bool AnyRecorded, bool AnyMissing, bool Differing, int First) ReadRecordedLevels(
        IReadOnlyList<Share<TNumber>> shareList)
    {
        bool anyRecorded = false;
        bool anyMissing = false;
        bool differing = false;
        int first = 0;
        for (int i = 0; i < shareList.Count; i++)
        {
            int? level = shareList[i].SecurityLevel;
            if (level is null)
            {
                anyMissing = true;
                continue;
            }

            if (!anyRecorded)
            {
                anyRecorded = true;
                first = level.Value;
            }
            else if (first != level.Value)
            {
                differing = true;
            }
        }

        return (anyRecorded, anyMissing, differing, first);
    }

    /// <summary>
    /// Rejects an exponent the manager does not support, exactly and without rounding.
    /// </summary>
    /// <param name="securityLevel">The exponent to check.</param>
    /// <param name="explicitlySupplied">
    /// <see langword="true"/> when the caller handed the exponent in, <see langword="false"/> when
    /// it was read off the shares.
    /// </param>
    /// <remarks>
    /// One check, two exception types: the API boundary decides which. An exponent handed in by
    /// the caller is an argument error; one read off a share is a reconstruction failure. Without
    /// <see cref="IInspectableSecurityLevelManager{TNumber}"/> there is nothing to check against
    /// here — the set-and-read-back in <see cref="CommitSecurityLevel"/> catches a normalised
    /// value instead. Missing that capability is not by itself a reason to throw.
    /// </remarks>
    private void ValidateExponent(int securityLevel, bool explicitlySupplied)
    {
        if (this.securityLevelManager is not IInspectableSecurityLevelManager<TNumber> inspectable
            || inspectable.IsValidSecurityLevel(securityLevel))
        {
            return;
        }

        string message = string.Format(ErrorMessages.SecurityLevelNotSupported, securityLevel);
        if (explicitlySupplied)
        {
            throw new ArgumentOutOfRangeException(nameof(securityLevel), securityLevel, message);
        }

        throw new ReconstructionException(message);
    }

    /// <summary>
    /// Rejects share coordinates that do not fit the field of the given exponent.
    /// </summary>
    /// <param name="shareList">The shares to check.</param>
    /// <param name="securityLevel">The exponent naming the field.</param>
    /// <remarks>
    /// The prime is computed here rather than read from the manager: the manager's
    /// <c>MersennePrime</c> belongs to the level it currently holds, and asking it for this one
    /// would mean moving it first — which is precisely what this check runs before.
    /// </remarks>
    private static void ValidateCoordinatesFit(IReadOnlyList<Share<TNumber>> shareList, int securityLevel)
    {
        using var one = Calculator<TNumber>.One;
        using var two = Calculator<TNumber>.Two;
        using var power = two.Pow(securityLevel);
        using var prime = power - one;

        for (int i = 0; i < shareList.Count; i++)
        {
            if (shareList[i].Index >= prime || shareList[i].Value >= prime)
            {
                throw new ReconstructionException(
                    string.Format(ErrorMessages.ShareCoordinateOutsideField, securityLevel));
            }
        }
    }

    /// <summary>
    /// Moves the manager to the chosen level and confirms it got there.
    /// </summary>
    /// <param name="securityLevel">The exponent to apply.</param>
    /// <param name="explicitlySupplied">
    /// <see langword="true"/> when the caller handed the exponent in, <see langword="false"/> when
    /// it was read off the shares.
    /// </param>
    /// <remarks>
    /// The read-back happens after <em>every</em> successful set, not only where rounding is
    /// suspected. Without the non-mutating check this method cannot tell which case it is in, and
    /// that not knowing is what put it here. A manager that normalised the value upward has
    /// quietly chosen a different field than the one named, which is the defect this whole path
    /// exists to prevent.
    /// </remarks>
    private void CommitSecurityLevel(int securityLevel, bool explicitlySupplied)
    {
        this.securityLevelManager.SecurityLevel = securityLevel;
        int applied = this.securityLevelManager.SecurityLevel;
        if (applied == securityLevel)
        {
            return;
        }

        string message = string.Format(ErrorMessages.SecurityLevelNotAppliedByManager, securityLevel, applied);
        if (explicitlySupplied)
        {
            throw new ArgumentOutOfRangeException(nameof(securityLevel), securityLevel, message);
        }

        throw new ReconstructionException(message);
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
    /// <exception cref="ReconstructionException">
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
            throw new ReconstructionException(ErrorMessages.InverseOfZeroDoesNotExist);
        }

        // The extended GCD still operates on the prime VALUE: the algorithm is
        // generic and does not exploit the Mersenne structure. Mersenne-fold
        // optimisation only kicks in for the modulo reductions below.
        using var result = this.extendedGcd.Compute(normalizedDenominator, prime);
        // Check whether the denominator is invertible modulo the prime
        if (!result.GreatestCommonDivisor.IsOne)
        {
            throw new ReconstructionException(ErrorMessages.DenominatorIsNotInvertibleModuloPrime);
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
