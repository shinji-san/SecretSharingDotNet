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
    /// The interpolated coefficient carries no payload beyond its mark byte and therefore decodes
    /// to no secret at all. Index distinctness is <em>not</em> checked here — see
    /// <see cref="EnsureDistinctIndices"/>, which runs before the security level is committed
    /// except where the value-derived selection on a manager without
    /// <see cref="IInspectableSecurityLevelManager{TNumber}"/> has already committed it.
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

        // Index distinctness is checked by ReconstructionCore before it moves the security level
        // manager: rejecting a duplicate here would mean rejecting it after the state had already
        // changed, which is the one thing input validation is supposed to avoid.
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
    /// The shares record different security levels, or some record one and others do not, so
    /// there is no field to choose without being told; a recorded level is not a supported Mersenne prime exponent; a coordinate lies outside
    /// the recorded field; two entries share the same <see cref="Share{TNumber}.Index"/>; or the
    /// interpolation produces a coefficient that decodes to no secret.
    /// <para>
    /// The last case carries the Mersenne exponent the interpolation ran under and identifies no
    /// cause, because a tampered share is indistinguishable from an ill-fitting field here. Using
    /// the recorded level removes the ill-fitting field as a cause, not the failure: a tampered
    /// share whose value drives the interpolated coefficient to zero produces it just the same,
    /// and the shares may record a level throughout.
    /// </para>
    /// <para>
    /// Where the shares say nothing, naming the field through
    /// <see cref="IReconstructionWithSecurityLevelUseCase{TNumber}.Reconstruction(Shares{TNumber}, int)"/>
    /// is the way forward. Where they <em>disagree</em>, it is not: any exponent supplied would
    /// contradict at least one of them, so that overload refuses the set as well. Shares recording
    /// different fields cannot all come from the same split.
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
    /// An explicit exponent is validated and checked against every level the shares record.
    /// Contradictory levels abort here whether or not one was supplied; mixed metadata aborts
    /// when none was. Nothing has moved at that point.
    /// </description></item>
    /// <item><description>
    /// Index distinctness, then the coordinates against the resulting field — on every path,
    /// including the one where the exponent was derived from the values. That derivation bounds
    /// the maximum y and nothing else: it says nothing about a negative y and nothing at all
    /// about the indices.
    /// </description></item>
    /// <item><description>
    /// The level is committed and read back, to catch a manager that normalised it upward instead
    /// of using it as given. With the exact check available the commit comes last; without it the
    /// commit comes first, so an unsupported exponent is refused by the manager rather than by
    /// whatever <c>2^exponent</c> does with it.
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

        // Phase 1 — determine a candidate. Nothing below moves the manager except the one
        // fallback branch that says so.
        var recorded = ReadRecordedLevels(shareList);
        int securityLevel;
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
            // Only this branch derives the field from the values, so only this branch needs their
            // maximum. With a recorded or an explicit level the values play no part in the choice.
            var maximumY = MaximumValue(shareList);
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

        // Phase 2 — validate. Distinctness first: it needs no field, and a duplicate index makes
        // the Lagrange denominator zero whatever the level is.
        EnsureDistinctIndices(shareList);

        // The coordinate check and the commit swap places depending on what the manager can
        // answer. With the exact check the exponent is already known to be supported, so the
        // coordinates are validated first and the state moves last. Without it, nothing has
        // vetted the exponent yet — so the manager is asked to accept it first, which keeps an
        // unsupported value out of the big-integer arithmetic below and gives a single, uniform
        // rejection instead of whatever `2^exponent` happens to do with it.
        if (alreadyCommitted)
        {
            ValidateCoordinatesFit(shareList, securityLevel);
        }
        else if (this.securityLevelManager is IInspectableSecurityLevelManager<TNumber>)
        {
            ValidateCoordinatesFit(shareList, securityLevel);
            this.CommitSecurityLevel(securityLevel, explicitLevel.HasValue);
        }
        else
        {
            this.CommitSecurityLevel(securityLevel, explicitLevel.HasValue);
            ValidateCoordinatesFit(shareList, securityLevel);
        }

        return this.LagrangeInterpolate(shareList);
    }

    /// <summary>
    /// Returns the largest <see cref="Share{TNumber}.Value"/> among the shares — the input of the
    /// value-derived field selection.
    /// </summary>
    /// <param name="shareList">The shares; at least two.</param>
    /// <returns>The largest value, borrowed from its share rather than copied.</returns>
    /// <remarks>
    /// An explicit loop rather than <c>Select(...).Max()</c>, which would allocate an iterator and
    /// an enumerator on the unpinned managed heap. There is no null handling: every constructor of
    /// <see cref="Share{TNumber}"/> rejects a null value and the getter throws once a share is
    /// disposed, so a maximum always exists once there are shares at all.
    /// </remarks>
    private static Calculator<TNumber> MaximumValue(IReadOnlyList<Share<TNumber>> shareList)
    {
        var maximum = shareList[0].Value;
        for (int i = 1; i < shareList.Count; i++)
        {
            var candidate = shareList[i].Value;
            if (candidate > maximum)
            {
                maximum = candidate;
            }
        }

        return maximum;
    }

    /// <summary>
    /// Rejects a set containing two shares with the same index.
    /// </summary>
    /// <param name="shareList">The shares to check.</param>
    /// <remarks>
    /// <para>
    /// Runs before the security level is committed, except on the compatibility path, where the
    /// value-derived selection has already committed the level: shares recording no level, with a
    /// manager lacking <see cref="IInspectableSecurityLevelManager{TNumber}"/>, which cannot report
    /// that selection without committing it. Duplicate indices make the Lagrange denominator zero,
    /// so this has to be caught either way; everywhere else, catching it after the manager had
    /// moved would break the promise that input validation leaves the state alone.
    /// </para>
    /// <para>
    /// Explicit <see cref="HashSet{T}"/> loop instead of <c>Select(...).Distinct().Count()</c> —
    /// avoids the iterator and enumerator allocations on the unpinned managed heap, and throws on
    /// the first duplicate rather than after a full enumeration.
    /// </para>
    /// <para>
    /// Indices are hashed through <c>PublicValueEqualityComparer</c>:
    /// <c>Calculator.GetHashCode</c> delegates to <typeparamref name="TNumber"/>, and the
    /// <c>SecureBigInteger</c> backend deliberately hashes only public metadata (sign and limb
    /// count) so a value-derived hash of secret material cannot be observed. That makes every
    /// small positive one-limb index hash identically, which would collapse this check into a
    /// single bucket and make it quadratic. Indices are public — they travel as the X coordinate
    /// of every serialised share — so hashing them by value is safe and restores the linear cost.
    /// </para>
    /// </remarks>
    /// <exception cref="ReconstructionException">Two entries share the same index.</exception>
    private static void EnsureDistinctIndices(IReadOnlyList<Share<TNumber>> shareList)
    {
#if NET8_0_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        var seenIndices = new HashSet<Calculator<TNumber>>(shareList.Count, PublicValueEqualityComparer<TNumber>.Instance);
#else
        var seenIndices = new HashSet<Calculator<TNumber>>(PublicValueEqualityComparer<TNumber>.Instance);
#endif
        for (int i = 0; i < shareList.Count; i++)
        {
            if (!seenIndices.Add(shareList[i].Index))
            {
                throw new ReconstructionException(ErrorMessages.ShareIndicesNotDistinct);
            }
        }
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

        throw RejectSecurityLevel(
            securityLevel,
            explicitlySupplied,
            string.Format(ErrorMessages.SecurityLevelNotSupported, securityLevel));
    }

    /// <summary>
    /// Rejects share coordinates that do not lie in the field of the given exponent:
    /// <c>0 &lt; x &lt; p</c> and <c>0 &lt;= y &lt; p</c>.
    /// </summary>
    /// <param name="shareList">The shares to check.</param>
    /// <param name="securityLevel">The exponent naming the field.</param>
    /// <remarks>
    /// <para>
    /// Runs on every path, including the one where the exponent was derived from the share values.
    /// That derivation looks at the <em>maximum</em> y only, so it establishes an upper bound on
    /// one coordinate and nothing else: it says nothing about a negative y, and nothing at all
    /// about the indices. An index at or above the prime is simply outside the permitted
    /// coordinate range — it need not collide with another one to be invalid, and often does not:
    /// with <c>p = 8191</c> the index 8192 reduces to 1, which may well be free.
    /// </para>
    /// <para>
    /// The prime is computed here rather than read from the manager: the manager's
    /// <c>MersennePrime</c> belongs to the level it currently holds, which on the pre-commit paths
    /// is not yet this one.
    /// </para>
    /// </remarks>
    private static void ValidateCoordinatesFit(IReadOnlyList<Share<TNumber>> shareList, int securityLevel)
    {
        if (!Share<TNumber>.AllFitField(shareList, securityLevel))
        {
            throw new ReconstructionException(
                string.Format(ErrorMessages.ShareCoordinateOutsideField, securityLevel));
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
        try
        {
            this.securityLevelManager.SecurityLevel = securityLevel;
        }
        catch (ArgumentOutOfRangeException)
        {
            // Targeted, not blanket. This assignment takes exactly one argument, so an
            // out-of-range rejection from it is about that exponent and nothing else. It is
            // re-typed to this boundary's contract because the manager names its own parameter,
            // which the caller has never seen and cannot act on.
            throw RejectSecurityLevel(
                securityLevel,
                explicitlySupplied,
                string.Format(ErrorMessages.SecurityLevelNotSupported, securityLevel));
        }

        int applied = this.securityLevelManager.SecurityLevel;
        if (applied == securityLevel)
        {
            return;
        }

        throw RejectSecurityLevel(
            securityLevel,
            explicitlySupplied,
            string.Format(ErrorMessages.SecurityLevelNotAppliedByManager, securityLevel, applied));
    }

    /// <summary>
    /// Builds the rejection for an unusable security level, typed by where the level came from.
    /// </summary>
    /// <param name="securityLevel">The exponent that was refused.</param>
    /// <param name="explicitlySupplied">
    /// <see langword="true"/> when the caller handed the exponent in, <see langword="false"/> when
    /// it was read off the shares.
    /// </param>
    /// <param name="message">The message describing the refusal.</param>
    /// <returns>The exception to throw.</returns>
    /// <remarks>
    /// One rule in one place: an exponent the caller passed is an argument error naming the
    /// parameter; the same exponent read off a share is a reconstruction failure, because the
    /// caller supplied no such argument to be told about.
    /// </remarks>
    private static Exception RejectSecurityLevel(int securityLevel, bool explicitlySupplied, string message) =>
        explicitlySupplied
            ? new ArgumentOutOfRangeException(nameof(securityLevel), securityLevel, message)
            : (Exception)new ReconstructionException(message);

    /// <summary>
    /// Performs division in the finite field defined by the configured Mersenne
    /// prime, returning the modular result of dividing the numerator by the
    /// denominator. The prime modulus and exponent are sourced from
    /// <see cref="securityLevelManager"/>; callers must ensure the manager is
    /// configured before invoking this method (the public entry points
    /// <see cref="Reconstruction(Shares{TNumber})"/> and
    /// <see cref="Reconstruction(Shares{TNumber}, int)"/> both handle that automatically).
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
