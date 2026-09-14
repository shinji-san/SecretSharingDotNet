// ----------------------------------------------------------------------------
// <copyright file="SecretReconstructorTest.cs" company="Private">
// Copyright (c) 2026 All Rights Reserved
// </copyright>
// <author>Sebastian Walther</author>
// <date>05/03/2026 00:00:00 AM</date>
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


namespace SecretSharingDotNetTest.Cryptography.ShamirsSecretSharing.SecureBigInteger;

using Moq;
using SecretSharingDotNet;
using SecretSharingDotNet.Cryptography;
using SecretSharingDotNet.Cryptography.ShamirsSecretSharing;
using SecretSharingDotNet.Math;
using SecretSharingDotNet.Math.Numerics;
using System;
using System.Linq;
using Xunit;

/// <summary>
/// Tests for <see cref="SecretReconstructor{TNumber}"/> on the <see cref="SecureBigInteger"/>
/// backend — disposal contract, share-distinctness validation, and the modular-inverse
/// <c>DivMod</c> round-trip used by Lagrange interpolation. Mirror of the BigInteger-side
/// test class.
/// </summary>
public class SecretReconstructorTest
{
    private static SecretReconstructor<SecureBigInteger> CreateWithMock(Mock<ISecurityLevelManager<SecureBigInteger>> managerMock) =>
        new(new ExtendedEuclideanAlgorithm<SecureBigInteger>(), managerMock.Object);

    /// <summary>
    /// Tests that disposing a <see cref="SecretReconstructor{TNumber}"/> built around a
    /// caller-supplied <see cref="ISecurityLevelManager{TNumber}"/> does NOT cascade dispose
    /// to the injected manager — ownership stays with the caller.
    /// </summary>
    [Fact]
    public void Dispose_WithInjectedManager_DoesNotDisposeIt()
    {
        // Arrange
        var managerMock = new Mock<ISecurityLevelManager<SecureBigInteger>>();
        var reconstructor = CreateWithMock(managerMock);

        // Act — caller-supplied manager: must NOT be disposed by reconstructor.
        reconstructor.Dispose();
        reconstructor.Dispose();
        reconstructor.Dispose();

        // Assert
        managerMock.Verify(m => m.Dispose(), Times.Never);
    }

    /// <summary>
    /// Tests that calling <see cref="SecretReconstructor{TNumber}.Dispose"/> repeatedly is
    /// idempotent — second and third calls do not throw.
    /// </summary>
    [Fact]
    public void Dispose_CalledMultipleTimes_IsIdempotent()
    {
        // Arrange
        var reconstructor = new SecretReconstructor<SecureBigInteger>(new ExtendedEuclideanAlgorithm<SecureBigInteger>());

        // Act
        var ex = Record.Exception(() =>
        {
            reconstructor.Dispose();
            reconstructor.Dispose();
            reconstructor.Dispose();
        });

        // Assert
        Assert.Null(ex);
    }

    /// <summary>
    /// Tests that reading <see cref="SecretReconstructor{TNumber}.SecurityLevel"/> after
    /// disposal throws <see cref="ObjectDisposedException"/>.
    /// </summary>
    [Fact]
    public void SecurityLevel_Get_AfterDispose_ThrowsObjectDisposedException()
    {
        // Arrange
        var reconstructor = new SecretReconstructor<SecureBigInteger>(new ExtendedEuclideanAlgorithm<SecureBigInteger>());
        reconstructor.Dispose();

        // Act & Assert
        Assert.Throws<ObjectDisposedException>(() => _ = reconstructor.SecurityLevel);
    }

    /// <summary>
    /// Tests that <see cref="SecretReconstructor{TNumber}.Reconstruction"/> rejects calls
    /// after the reconstructor was disposed with <see cref="ObjectDisposedException"/>.
    /// </summary>
    [Fact]
    public void Reconstruction_AfterDispose_ThrowsObjectDisposedException()
    {
        // Arrange
        var reconstructor = new SecretReconstructor<SecureBigInteger>(new ExtendedEuclideanAlgorithm<SecureBigInteger>());
        Shares<SecureBigInteger> emptyShares = Array.Empty<Share<SecureBigInteger>>();
        reconstructor.Dispose();

        // Act & Assert
        Assert.Throws<ObjectDisposedException>(() => reconstructor.Reconstruction(emptyShares));
    }

    /// <summary>
    /// Tests that <see cref="SecretReconstructor{TNumber}.DivMod"/> (the modular-inverse
    /// helper used by Lagrange interpolation) rejects calls after the reconstructor was
    /// disposed with <see cref="ObjectDisposedException"/>.
    /// </summary>
    [Fact]
    public void DivMod_AfterDispose_ThrowsObjectDisposedException()
    {
        // Arrange
        var reconstructor = new SecretReconstructor<SecureBigInteger>(new ExtendedEuclideanAlgorithm<SecureBigInteger>());
        using var d = (Calculator<SecureBigInteger>)(SecureBigInteger)3;
        using var n = (Calculator<SecureBigInteger>)(SecureBigInteger)5;
        reconstructor.Dispose();

        // Act & Assert
        Assert.Throws<ObjectDisposedException>(() => reconstructor.DivMod(n, d));
    }

    /// <summary>
    /// Tests the algebraic round-trip <c>d · DivMod(d, n) mod p ≡ n</c> with the
    /// Mersenne prime <c>M127</c>. The security-level manager is injected pre-configured
    /// to exponent 127 so <c>DivMod</c> reads the matching prime.
    /// </summary>
    [Fact]
    public void DivMod_RoundTrip_DenominatorTimesQuotientModPrime_EqualsNumerator()
    {
        // Arrange — checks `d * DivMod(d, n) % p == n` with the M127 Mersenne prime.
        // DivMod sources prime + exponent from the security-level manager, so the
        // test injects a manager pre-configured to security level 127 (= the
        // Mersenne exponent for M127).
        var manager = new SecurityLevelManager<SecureBigInteger>
        {
            SecurityLevel = 127,
        };
        using var reconstructor = new SecretReconstructor<SecureBigInteger>(
            new ExtendedEuclideanAlgorithm<SecureBigInteger>(),
            manager);
        using Calculator<SecureBigInteger> d = (SecureBigInteger)3000;
        using Calculator<SecureBigInteger> n = (SecureBigInteger)3000;
        using var two       = Calculator<SecureBigInteger>.Two;
        using var twoPow127 = two.Pow(127);
        using var one       = Calculator<SecureBigInteger>.One;
        using var p         = twoPow127 - one;

        // Act
        using var divModResult = reconstructor.DivMod(d, n);
        using var dTimesDivMod = d * divModResult;
        using var modulo       = dTimesDivMod % p;

        // Assert
        Assert.Equal(n, modulo);
    }

    /// <summary>
    /// Tests that the <c>using</c> pattern over a default-constructed
    /// <see cref="SecretReconstructor{TNumber}"/> (which internally owns its
    /// security-level manager) completes without exception.
    /// </summary>
    [Fact]
    public void UsingPattern_WithOwnedManager_DoesNotThrow()
    {
        // Arrange & Act — owned-manager round-trip via using.
        using (var reconstructor = new SecretReconstructor<SecureBigInteger>(new ExtendedEuclideanAlgorithm<SecureBigInteger>()))
        {
            Assert.True(reconstructor.SecurityLevel > 0);
        }

        // Assert — implicit: no exception escaped.
    }

    /// <summary>
    /// Tests that <see cref="SecretReconstructor{TNumber}.Reconstruction"/> rejects share
    /// arrays that contain two entries with the same x-coordinate but inconsistent values
    /// at the input-validation layer (<see cref="ReconstructionException"/>), rather than
    /// failing deep inside <c>DivMod</c> with a misleading "inverse of zero" diagnostic.
    /// </summary>
    [Fact]
    public void Reconstruction_WithDuplicateShareIndices_ThrowsReconstructionException()
    {
        // Arrange — two shares carrying the same index but inconsistent values
        // (e.g. mixed in from two different splits). Pre-fix this passed the
        // structural Distinct() check on Share and only failed deep inside
        // DivMod with the misleading "inverse of zero" message. Values are
        // chosen large enough to clear the minimum-security-level adjustment
        // in Reconstruction so the distinctness validation is the actual gate
        // hit.
        using var reconstructor = new SecretReconstructor<SecureBigInteger>(new ExtendedEuclideanAlgorithm<SecureBigInteger>());
        var idx1 = (Calculator<SecureBigInteger>)(SecureBigInteger)1;
        var idx2 = (Calculator<SecureBigInteger>)(SecureBigInteger)1;
        var v1 = (Calculator<SecureBigInteger>)(SecureBigInteger)1_000_000;
        var v2 = (Calculator<SecureBigInteger>)(SecureBigInteger)2_000_000;
        using Shares<SecureBigInteger> shares = new[]
        {
            new Share<SecureBigInteger>(idx1, v1),
            new Share<SecureBigInteger>(idx2, v2),
        };

        // Act & Assert — fail at the input-validation layer, not in DivMod.
        var ex = Assert.Throws<ReconstructionException>(() => reconstructor.Reconstruction(shares));
        Assert.IsAssignableFrom<SecretSharingException>(ex);
    }

    /// <summary>
    /// Tests that <see cref="SecretReconstructor{TNumber}.Reconstruction"/> with distinct
    /// share indices but identical y-values does not trip the share-distinctness validation
    /// — the validation is by x-coordinate only, since duplicate y-values are legitimate
    /// on a polynomial that happens to be locally flat. Reconstruction may legitimately
    /// fail later (the shares are not on a real polynomial), but never with the
    /// share-distinctness ReconstructionException.
    /// </summary>
    [Fact]
    public void Reconstruction_WithDistinctIndicesAndDuplicateValues_DoesNotThrowAtValidation()
    {
        // Arrange — two shares with distinct indices but identical values. Under
        // the old Share-structural Distinct() check this would still pass; under
        // the index-only check it must continue to pass. The reconstruction
        // itself may legitimately fail later (these shares aren't on a real
        // polynomial), but never with the share-distinctness ReconstructionException.
        using var reconstructor = new SecretReconstructor<SecureBigInteger>(new ExtendedEuclideanAlgorithm<SecureBigInteger>());
        var idx1 = (Calculator<SecureBigInteger>)(SecureBigInteger)1;
        var idx2 = (Calculator<SecureBigInteger>)(SecureBigInteger)2;
        var v1 = (Calculator<SecureBigInteger>)(SecureBigInteger)1_000_000;
        var v2 = (Calculator<SecureBigInteger>)(SecureBigInteger)1_000_000;
        using Shares<SecureBigInteger> shares = new[]
        {
            new Share<SecureBigInteger>(idx1, v1),
            new Share<SecureBigInteger>(idx2, v2),
        };

        // Act & Assert — reconstruction completes (or fails later) but does not
        // raise the share-distinctness validation.
        var ex = Record.Exception(() => reconstructor.Reconstruction(shares));
        if (ex is ReconstructionException re)
        {
            Assert.DoesNotContain(ErrorMessages.ShareIndicesNotDistinct, re.Message);
        }
    }
    /// <summary>
    /// The escape hatch for shares that record no level: naming the field explicitly restores the
    /// round trip on exactly the input that loses the secret without it. Same shares, same values,
    /// one argument.
    /// Mirror of the BigInteger-side fact of the same name.
    /// </summary>
    [Fact]
    public void Reconstruction_WithExplicitLevel_RecoversWhatTheDerivationLoses()
    {
        // Arrange — vector C with the level stripped by rebuilding from bare coordinates.
        using var secret = new Secret<SecureBigInteger>(new byte[] { 0xFF }, 1, new DeterministicRandomSource(35));
        using var splitter = new SecretSplitter<SecureBigInteger>(new DeterministicRandomSource(270));
        splitter.SecurityLevel = 17;
        using var shares = splitter.MakeShares(2, 280, secret);
        var byIndex = shares.ToArray();
        using var legacy = new Shares<SecureBigInteger>(new[]
        {
            new Share<SecureBigInteger>(byIndex[0].Index.Clone(), byIndex[0].Value.Clone()),
            new Share<SecureBigInteger>(byIndex[279].Index.Clone(), byIndex[279].Value.Clone()),
        });
        using var derivingReconstructor = new SecretReconstructor<SecureBigInteger>(new MersenneSafeGcdAlgorithm<SecureBigInteger>());
        using var toldReconstructor = new SecretReconstructor<SecureBigInteger>(new MersenneSafeGcdAlgorithm<SecureBigInteger>());

        // Act
        using var derived = derivingReconstructor.Reconstruction(legacy);
        using var told = toldReconstructor.Reconstruction(legacy, 17);

        // Assert
        Assert.NotEqual(secret, derived);
        Assert.Equal(secret, told);
        Assert.Equal(17, toldReconstructor.SecurityLevel);
    }

    /// <summary>
    /// An explicit level that contradicts what a share records is refused rather than silently
    /// preferred. The parameter outranks the metadata in precedence, not in truth.
    /// Mirror of the BigInteger-side fact of the same name.
    /// </summary>
    [Fact]
    public void Reconstruction_WithExplicitLevelContradictingTheShares_Throws()
    {
        // Arrange
        using var shares = new Shares<SecureBigInteger>(new[]
        {
            new Share<SecureBigInteger>(new SecureBigIntCalculator(1), new SecureBigIntCalculator(10), 17),
            new Share<SecureBigInteger>(new SecureBigIntCalculator(2), new SecureBigIntCalculator(20), 17),
        });
        using var reconstructor = new SecretReconstructor<SecureBigInteger>(new MersenneSafeGcdAlgorithm<SecureBigInteger>());

        // Act & Assert
        Assert.Throws<ReconstructionException>(() => reconstructor.Reconstruction(shares, 19));
    }

    /// <summary>
    /// An exponent the manager does not support is an argument error on the overload that takes
    /// it, naming the parameter — not a reconstruction failure, and never rounded up to the next
    /// supported exponent.
    /// Mirror of the BigInteger-side theory of the same name.
    /// </summary>
    /// <param name="securityLevel">An exponent that is not a supported Mersenne prime exponent.</param>
    [Theory]
    [InlineData(18)]
    [InlineData(12)]
    [InlineData(0)]
    [InlineData(-1)]
    public void Reconstruction_WithUnsupportedExplicitLevel_ThrowsArgumentOutOfRange(int securityLevel)
    {
        // Arrange
        using var shares = new Shares<SecureBigInteger>(new[]
        {
            new Share<SecureBigInteger>(new SecureBigIntCalculator(1), new SecureBigIntCalculator(10)),
            new Share<SecureBigInteger>(new SecureBigIntCalculator(2), new SecureBigIntCalculator(20)),
        });
        using var reconstructor = new SecretReconstructor<SecureBigInteger>(new MersenneSafeGcdAlgorithm<SecureBigInteger>());

        // Act & Assert
        var error = Assert.Throws<ArgumentOutOfRangeException>(
            () => reconstructor.Reconstruction(shares, securityLevel));
        Assert.Equal("securityLevel", error.ParamName);
    }

    /// <summary>
    /// Shares recording different levels are refused with no level supplied: there is nothing to
    /// choose between them, and picking one would be the guesswork this fix removes.
    /// Mirror of the BigInteger-side fact of the same name.
    /// </summary>
    [Fact]
    public void Reconstruction_WhenSharesRecordDifferentLevels_Throws()
    {
        // Arrange
        using var shares = new Shares<SecureBigInteger>(new[]
        {
            new Share<SecureBigInteger>(new SecureBigIntCalculator(1), new SecureBigIntCalculator(10), 17),
            new Share<SecureBigInteger>(new SecureBigIntCalculator(2), new SecureBigIntCalculator(20), 19),
        });
        using var reconstructor = new SecretReconstructor<SecureBigInteger>(new MersenneSafeGcdAlgorithm<SecureBigInteger>());

        // Act & Assert
        Assert.Throws<ReconstructionException>(() => reconstructor.Reconstruction(shares));
    }

    /// <summary>
    /// A set in which some shares record a level and others do not is refused as well. The recorded
    /// level cannot be assumed to govern the others, and assuming it would reintroduce exactly the
    /// unverified inference this fix exists to remove.
    /// Mirror of the BigInteger-side fact of the same name.
    /// </summary>
    [Fact]
    public void Reconstruction_WhenShareMetadataIsMixed_Throws()
    {
        // Arrange
        using var shares = new Shares<SecureBigInteger>(new[]
        {
            new Share<SecureBigInteger>(new SecureBigIntCalculator(1), new SecureBigIntCalculator(10), 17),
            new Share<SecureBigInteger>(new SecureBigIntCalculator(2), new SecureBigIntCalculator(20)),
        });
        using var reconstructor = new SecretReconstructor<SecureBigInteger>(new MersenneSafeGcdAlgorithm<SecureBigInteger>());

        // Act & Assert
        Assert.Throws<ReconstructionException>(() => reconstructor.Reconstruction(shares));
    }

    /// <summary>
    /// A coordinate outside the named field is refused before the interpolation runs. The level is
    /// asserted here rather than derived from the values, so the two can disagree — and a value
    /// that does not fit cannot have come from that field.
    /// Mirror of the BigInteger-side fact of the same name.
    /// </summary>
    [Fact]
    public void Reconstruction_WhenACoordinateDoesNotFitTheNamedField_Throws()
    {
        // Arrange — 9000 exceeds M13 = 8191.
        using var shares = new Shares<SecureBigInteger>(new[]
        {
            new Share<SecureBigInteger>(new SecureBigIntCalculator(1), new SecureBigIntCalculator(9000)),
            new Share<SecureBigInteger>(new SecureBigIntCalculator(2), new SecureBigIntCalculator(20)),
        });
        using var reconstructor = new SecretReconstructor<SecureBigInteger>(new MersenneSafeGcdAlgorithm<SecureBigInteger>());

        // Act & Assert
        Assert.Throws<ReconstructionException>(() => reconstructor.Reconstruction(shares, 13));
    }

    /// <summary>
    /// The explicit form is reachable through an abstraction, not only through the concrete type.
    /// The interface inherits <see cref="IReconstructionUseCase{TNumber}"/>, so one injected
    /// reference offers both call shapes — but a container registration for the base interface does
    /// not resolve this one, which is why the DI guidance registers it separately.
    /// Mirror of the BigInteger-side fact of the same name.
    /// </summary>
    [Fact]
    public void Reconstruction_ExplicitForm_IsReachableThroughTheInterface()
    {
        // Arrange
        using var secret = new Secret<SecureBigInteger>(new byte[] { 0x2A });
        using var splitter = new SecretSplitter<SecureBigInteger>();
        splitter.SecurityLevel = 17;
        using var shares = splitter.MakeShares(2, 2, secret);
        using var reconstructor = new SecretReconstructor<SecureBigInteger>(new MersenneSafeGcdAlgorithm<SecureBigInteger>());

        // Act
        IReconstructionWithSecurityLevelUseCase<SecureBigInteger> useCase = reconstructor;
        using var viaExplicit = useCase.Reconstruction(shares, splitter.SecurityLevel);
        using var viaBase = ((IReconstructionUseCase<SecureBigInteger>)useCase).Reconstruction(shares);

        // Assert
        Assert.Equal(secret, viaExplicit);
        Assert.Equal(secret, viaBase);
    }
    /// <summary>
    /// A security level manager without
    /// <see cref="IInspectableSecurityLevelManager{TNumber}"/> — an external implementation as it
    /// existed before the capability. It delegates everything, and deliberately does not offer the
    /// non-mutating members, so the reconstructor has to take the compatibility path.
    /// </summary>
    private sealed class PlainSecurityLevelManager : ISecurityLevelManager<SecureBigInteger>
    {
        private readonly SecurityLevelManager<SecureBigInteger> inner = new SecurityLevelManager<SecureBigInteger>();

        public int SecurityLevel
        {
            get => this.inner.SecurityLevel;
            set => this.inner.SecurityLevel = value;
        }

        public Calculator<SecureBigInteger> MersennePrime => this.inner.MersennePrime;

        public void AdjustSecurityLevel(Calculator<SecureBigInteger> maximumY) => this.inner.AdjustSecurityLevel(maximumY);

        public void Dispose() => this.inner.Dispose();
    }

    /// <summary>
    /// A manager lacking the non-mutating capability is a supported configuration, not an error:
    /// reconstruction still works, and a level recorded on the shares is still used.
    /// Mirror of the BigInteger-side fact of the same name.
    /// </summary>
    [Fact]
    public void Reconstruction_WithAManagerLackingTheCapability_StillUsesTheRecordedLevel()
    {
        // Arrange
        using var secret = new Secret<SecureBigInteger>(new byte[] { 0x2A });
        using var splitter = new SecretSplitter<SecureBigInteger>();
        splitter.SecurityLevel = 17;
        using var shares = splitter.MakeShares(2, 2, secret);
        using var plainManager = new PlainSecurityLevelManager();
        using var reconstructor = new SecretReconstructor<SecureBigInteger>(new MersenneSafeGcdAlgorithm<SecureBigInteger>(), plainManager);

        // Act
        using var reconstructed = reconstructor.Reconstruction(shares);

        // Assert
        Assert.Equal(17, reconstructor.SecurityLevel);
        Assert.Equal(secret, reconstructed);
    }

    /// <summary>
    /// Without the exact check there is nothing to validate an exponent against beforehand, so the
    /// compatibility path sets it and reads it back. A manager that normalised 18 upward to 19 has
    /// quietly chosen a different field than the one named, and the read-back is what turns that
    /// into an error instead of a wrong secret. The failure still names the parameter, because the
    /// exponent came from the caller.
    /// Mirror of the BigInteger-side fact of the same name.
    /// </summary>
    [Fact]
    public void Reconstruction_WithAManagerLackingTheCapability_CatchesANormalisedLevelOnReadBack()
    {
        // Arrange
        using var shares = new Shares<SecureBigInteger>(new[]
        {
            new Share<SecureBigInteger>(new SecureBigIntCalculator(1), new SecureBigIntCalculator(10)),
            new Share<SecureBigInteger>(new SecureBigIntCalculator(2), new SecureBigIntCalculator(20)),
        });
        using var plainManager = new PlainSecurityLevelManager();
        using var reconstructor = new SecretReconstructor<SecureBigInteger>(new MersenneSafeGcdAlgorithm<SecureBigInteger>(), plainManager);

        // Act & Assert — 18 is not a Mersenne exponent; the setter would round it to 19.
        var error = Assert.Throws<ArgumentOutOfRangeException>(() => reconstructor.Reconstruction(shares, 18));
        Assert.Equal("securityLevel", error.ParamName);
    }
    /// <summary>
    /// Without the exact check the exponent is vetted by the manager, before any of it reaches the
    /// big-integer arithmetic. Every rejection comes back as the same argument error naming the
    /// same parameter, whatever the manager's own setter would have called it — a caller cannot act
    /// on a parameter name it never supplied.
    /// Mirror of the BigInteger-side theory of the same name.
    /// </summary>
    /// <param name="securityLevel">An exponent that is not a supported Mersenne prime exponent.</param>
    [Theory]
    [InlineData(18)]
    [InlineData(12)]
    [InlineData(0)]
    [InlineData(-1)]
    [InlineData(int.MaxValue)]
    public void Reconstruction_WithAManagerLackingTheCapability_RejectsEveryUnsupportedLevelAlike(int securityLevel)
    {
        // Arrange
        using var shares = new Shares<SecureBigInteger>(new[]
        {
            new Share<SecureBigInteger>(new SecureBigIntCalculator(1), new SecureBigIntCalculator(10)),
            new Share<SecureBigInteger>(new SecureBigIntCalculator(2), new SecureBigIntCalculator(20)),
        });
        using var plainManager = new PlainSecurityLevelManager();
        using var reconstructor = new SecretReconstructor<SecureBigInteger>(new MersenneSafeGcdAlgorithm<SecureBigInteger>(), plainManager);

        // Act & Assert
        var error = Assert.Throws<ArgumentOutOfRangeException>(
            () => reconstructor.Reconstruction(shares, securityLevel));
        Assert.Equal("securityLevel", error.ParamName);
    }

    /// <summary>
    /// A negative y-coordinate is outside the field even though it is below the prime. Comparing
    /// only against the upper bound would let it through, and the interpolation would run on a
    /// point that is not in the field it claims to be in.
    /// Mirror of the BigInteger-side fact of the same name.
    /// </summary>
    [Fact]
    public void Reconstruction_WithANegativeCoordinate_Throws()
    {
        // Arrange
        using var shares = new Shares<SecureBigInteger>(new[]
        {
            new Share<SecureBigInteger>(new SecureBigIntCalculator(1), new SecureBigIntCalculator(-489)),
            new Share<SecureBigInteger>(new SecureBigIntCalculator(2), new SecureBigIntCalculator(-1489)),
        });
        using var reconstructor = new SecretReconstructor<SecureBigInteger>(new MersenneSafeGcdAlgorithm<SecureBigInteger>());

        // Act & Assert
        Assert.Throws<ReconstructionException>(() => reconstructor.Reconstruction(shares, 13));
    }

    /// <summary>
    /// The legacy path checks coordinates too. Deriving the field from the maximum y bounds one
    /// coordinate and says nothing about the indices: an index at or above the prime collides
    /// modulo <c>p</c> with another and drives the Lagrange denominator to zero.
    /// Mirror of the BigInteger-side fact of the same name.
    /// </summary>
    [Fact]
    public void Reconstruction_WhenAnIndexExceedsTheDerivedField_Throws()
    {
        // Arrange — maximumY 2511 derives M13 = 8191, which index 8192 does not fit.
        using var shares = new Shares<SecureBigInteger>(new[]
        {
            new Share<SecureBigInteger>(new SecureBigIntCalculator(8192), new SecureBigIntCalculator(1511)),
            new Share<SecureBigInteger>(new SecureBigIntCalculator(2), new SecureBigIntCalculator(2511)),
        });
        using var reconstructor = new SecretReconstructor<SecureBigInteger>(new MersenneSafeGcdAlgorithm<SecureBigInteger>());

        // Act & Assert
        Assert.Throws<ReconstructionException>(() => reconstructor.Reconstruction(shares));
    }

    /// <summary>
    /// Duplicate indices are refused before the security level moves. The check has to happen
    /// either way — a repeated index makes the Lagrange denominator zero — but running it after the
    /// commit would leave the manager on a level the caller never asked for, and its previous prime
    /// instance disposed, on an input that was never usable.
    /// Mirror of the BigInteger-side fact of the same name.
    /// </summary>
    [Fact]
    public void Reconstruction_WithDuplicateIndices_LeavesTheManagerUntouched()
    {
        // Arrange
        using var manager = new SecurityLevelManager<SecureBigInteger>();
        manager.SecurityLevel = 31;
        using var shares = new Shares<SecureBigInteger>(new[]
        {
            new Share<SecureBigInteger>(new SecureBigIntCalculator(1), new SecureBigIntCalculator(10), 17),
            new Share<SecureBigInteger>(new SecureBigIntCalculator(1), new SecureBigIntCalculator(20), 17),
        });
        using var reconstructor = new SecretReconstructor<SecureBigInteger>(new MersenneSafeGcdAlgorithm<SecureBigInteger>(), manager);

        // Act & Assert
        Assert.Throws<ReconstructionException>(() => reconstructor.Reconstruction(shares));
        Assert.Equal(31, manager.SecurityLevel);
    }
}
