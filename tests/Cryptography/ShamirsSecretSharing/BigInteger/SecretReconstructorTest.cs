// ----------------------------------------------------------------------------
// <copyright file="SecretReconstructorTest.cs" company="Private">
// Copyright (c) 2026 All Rights Reserved
// </copyright>
// <author>Sebastian Walther</author>
// <date>05/08/2026 00:00:00 AM</date>
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


namespace SecretSharingDotNetTest.Cryptography.ShamirsSecretSharing.BigInteger;

using Moq;
using SecretSharingDotNet;
using SecretSharingDotNet.Cryptography;
using SecretSharingDotNet.Cryptography.ShamirsSecretSharing;
using SecretSharingDotNet.Math;
using SecretSharingDotNet.Math.Numerics;
using System;
using System.Linq;
using System.Numerics;
using System.Runtime.CompilerServices;
using System.Threading;
using System.Threading.Tasks;
using Xunit;

/// <summary>
/// Tests for <see cref="SecretReconstructor{TNumber}"/> on the <see cref="BigInteger"/>
/// backend — disposal contract, share-distinctness validation, and the modular-inverse
/// <c>DivMod</c> round-trip used by Lagrange interpolation.
/// </summary>
public class SecretReconstructorTest
{
    private static SecretReconstructor<BigInteger> CreateWithMock(Mock<ISecurityLevelManager<BigInteger>> managerMock) =>
        new(new ExtendedEuclideanAlgorithm<BigInteger>(), managerMock.Object);

    /// <summary>
    /// Tests that disposing a <see cref="SecretReconstructor{TNumber}"/> built around a
    /// caller-supplied <see cref="ISecurityLevelManager{TNumber}"/> does NOT cascade dispose
    /// to the injected manager — ownership stays with the caller.
    /// </summary>
    [Fact]
    public void Dispose_WithInjectedManager_DoesNotDisposeIt()
    {
        // Arrange
        var managerMock = new Mock<ISecurityLevelManager<BigInteger>>();
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
        var reconstructor = new SecretReconstructor<BigInteger>(new ExtendedEuclideanAlgorithm<BigInteger>());

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
    /// The idempotency guard in the non-virtual <c>Dispose()</c> covers the whole override chain: a
    /// derived type that cleans up in its override and then calls <c>base.Dispose(disposing)</c>
    /// sees the override run once — after two sequential calls, and after a hundred concurrent
    /// ones. With the guard in <c>Dispose(bool)</c>, as the dispose pattern suggests, only the base
    /// body would be protected and the override would run on every call.
    /// Mirror of the SecureBigInteger-side fact of the same name.
    /// </summary>
    [Fact]
    public void Dispose_OnADerivedType_RunsTheOverrideOnce()
    {
        // Arrange
        var sequential = new CountingReconstructor();
        var concurrent = new CountingReconstructor();

        // Act
        sequential.Dispose();
        sequential.Dispose();
        Parallel.For(0, 100, _ => concurrent.Dispose());

        // Assert
        Assert.Equal(1, sequential.OverrideRuns);
        Assert.Equal(1, concurrent.OverrideRuns);
    }

    /// <summary>
    /// A derived reconstructor that counts how often its <c>Dispose(bool)</c> override runs.
    /// </summary>
    private sealed class CountingReconstructor : SecretReconstructor<BigInteger>
    {
        private int overrideRuns;

        public CountingReconstructor()
            : base(new ExtendedEuclideanAlgorithm<BigInteger>())
        {
        }

        public int OverrideRuns => Volatile.Read(ref this.overrideRuns);

        protected override void Dispose(bool disposing)
        {
            Interlocked.Increment(ref this.overrideRuns);
            base.Dispose(disposing);
        }
    }

    /// <summary>
    /// A derived reconstructor that is never disposed still reaches its <c>Dispose(bool)</c>
    /// override — with <c>disposing</c> set to <see langword="false"/> — through the finalizer
    /// of <c>SecretReconstructor</c>. The finalizer releases nothing of the base type's own; it is
    /// kept because an existing derivation may rely on it to clean up, and removing it is reserved
    /// for the next major version. This test is what makes that removal a deliberate step.
    /// <para>
    /// The instance is created in a separate, non-inlined method so no stack slot keeps it alive,
    /// and collection is retried a few times because Mono scans the stack conservatively.
    /// </para>
    /// Mirror of the SecureBigInteger-side fact of the same name.
    /// </summary>
    [Fact]
    public void Finalizer_OfAnUndisposedDerivedType_CallsDisposeWithDisposingFalse()
    {
        // Arrange
        var recorder = new FinalizationRecorder();

        // Act
        AbandonFinalizingReconstructor(recorder);
        for (int attempt = 0; attempt < 10 && !recorder.Called; attempt++)
        {
            GC.Collect();
            GC.WaitForPendingFinalizers();
        }

        // Assert
        Assert.True(recorder.Called);
        Assert.False(recorder.Disposing);
    }

    /// <summary>
    /// Creates a <see cref="FinalizingReconstructor"/> and drops it without disposing it, which is
    /// the point: only the finalizer can reach it afterwards.
    /// </summary>
    /// <param name="recorder">Receives the call the finalizer makes.</param>
    [MethodImpl(MethodImplOptions.NoInlining)]
    private static void AbandonFinalizingReconstructor(FinalizationRecorder recorder)
    {
        _ = new FinalizingReconstructor(recorder);
    }

    /// <summary>
    /// Records whether <c>Dispose(bool)</c> was reached and with which argument. Holds no reference
    /// to the reconstructor, so it does not keep it alive.
    /// </summary>
    private sealed class FinalizationRecorder
    {
        private int called;
        private int disposing;

        public bool Called => Volatile.Read(ref this.called) == 1;

        public bool Disposing => Volatile.Read(ref this.disposing) == 1;

        public void Record(bool value)
        {
            Volatile.Write(ref this.disposing, value ? 1 : 0);
            Volatile.Write(ref this.called, 1);
        }
    }

    /// <summary>
    /// A derived reconstructor whose <c>Dispose(bool)</c> override reports to a recorder.
    /// </summary>
    private sealed class FinalizingReconstructor : SecretReconstructor<BigInteger>
    {
        private readonly FinalizationRecorder recorder;

        public FinalizingReconstructor(FinalizationRecorder recorder)
            : base(new ExtendedEuclideanAlgorithm<BigInteger>())
        {
            this.recorder = recorder;
        }

        protected override void Dispose(bool disposing)
        {
            this.recorder.Record(disposing);
            base.Dispose(disposing);
        }
    }

    /// <summary>
    /// Tests that reading <see cref="SecretReconstructor{TNumber}.SecurityLevel"/> after
    /// disposal throws <see cref="ObjectDisposedException"/>.
    /// </summary>
    [Fact]
    public void SecurityLevel_Get_AfterDispose_ThrowsObjectDisposedException()
    {
        // Arrange
        var reconstructor = new SecretReconstructor<BigInteger>(new ExtendedEuclideanAlgorithm<BigInteger>());
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
        var reconstructor = new SecretReconstructor<BigInteger>(new ExtendedEuclideanAlgorithm<BigInteger>());
        Shares<BigInteger> emptyShares = Array.Empty<Share<BigInteger>>();
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
        var reconstructor = new SecretReconstructor<BigInteger>(new ExtendedEuclideanAlgorithm<BigInteger>());
        using var d = (Calculator<BigInteger>)(BigInteger)3;
        using var n = (Calculator<BigInteger>)(BigInteger)5;
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
        var manager = new SecurityLevelManager<BigInteger>
        {
            SecurityLevel = 127,
        };
        using var reconstructor = new SecretReconstructor<BigInteger>(
            new ExtendedEuclideanAlgorithm<BigInteger>(),
            manager);
        using Calculator<BigInteger> d = (BigInteger)3000;
        using Calculator<BigInteger> n = (BigInteger)3000;
        using var two       = Calculator<BigInteger>.Two;
        using var twoPow127 = two.Pow(127);
        using var one       = Calculator<BigInteger>.One;
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
        using (var reconstructor = new SecretReconstructor<BigInteger>(new ExtendedEuclideanAlgorithm<BigInteger>()))
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
        using var reconstructor = new SecretReconstructor<BigInteger>(new ExtendedEuclideanAlgorithm<BigInteger>());
        var idx1 = (Calculator<BigInteger>)(BigInteger)1;
        var idx2 = (Calculator<BigInteger>)(BigInteger)1;
        var v1 = (Calculator<BigInteger>)(BigInteger)1_000_000;
        var v2 = (Calculator<BigInteger>)(BigInteger)2_000_000;
        using Shares<BigInteger> shares = new[]
        {
            new Share<BigInteger>(idx1, v1),
            new Share<BigInteger>(idx2, v2),
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
        using var reconstructor = new SecretReconstructor<BigInteger>(new ExtendedEuclideanAlgorithm<BigInteger>());
        var idx1 = (Calculator<BigInteger>)(BigInteger)1;
        var idx2 = (Calculator<BigInteger>)(BigInteger)2;
        var v1 = (Calculator<BigInteger>)(BigInteger)1_000_000;
        var v2 = (Calculator<BigInteger>)(BigInteger)1_000_000;
        using Shares<BigInteger> shares = new[]
        {
            new Share<BigInteger>(idx1, v1),
            new Share<BigInteger>(idx2, v2),
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
    /// Mirror of the SecureBigInteger-side fact of the same name.
    /// </summary>
    [Fact]
    public void Reconstruction_WithExplicitLevel_RecoversWhatTheDerivationLoses()
    {
        // Arrange — vector C with the level stripped by rebuilding from bare coordinates.
        using var secret = new Secret<BigInteger>(new byte[] { 0xFF }, 1, new DeterministicRandomSource(35));
        using var splitter = new SecretSplitter<BigInteger>(new DeterministicRandomSource(270));
        splitter.SecurityLevel = 17;
        using var shares = splitter.MakeShares(2, 280, secret);
        var byIndex = shares.ToArray();
        using var legacy = new Shares<BigInteger>(new[]
        {
            new Share<BigInteger>(byIndex[0].Index.Clone(), byIndex[0].Value.Clone()),
            new Share<BigInteger>(byIndex[279].Index.Clone(), byIndex[279].Value.Clone()),
        });
        using var derivingReconstructor = new SecretReconstructor<BigInteger>(new ExtendedEuclideanAlgorithm<BigInteger>());
        using var toldReconstructor = new SecretReconstructor<BigInteger>(new ExtendedEuclideanAlgorithm<BigInteger>());

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
    /// Mirror of the SecureBigInteger-side fact of the same name.
    /// </summary>
    [Fact]
    public void Reconstruction_WithExplicitLevelContradictingTheShares_Throws()
    {
        // Arrange
        using var shares = new Shares<BigInteger>(new[]
        {
            new Share<BigInteger>(new BigIntCalculator(1), new BigIntCalculator(10), 17),
            new Share<BigInteger>(new BigIntCalculator(2), new BigIntCalculator(20), 17),
        });
        using var reconstructor = new SecretReconstructor<BigInteger>(new ExtendedEuclideanAlgorithm<BigInteger>());

        // Act & Assert
        Assert.Throws<ReconstructionException>(() => reconstructor.Reconstruction(shares, 19));
    }

    /// <summary>
    /// An exponent the manager does not support is an argument error on the overload that takes
    /// it, naming the parameter — not a reconstruction failure, and never rounded up to the next
    /// supported exponent.
    /// Mirror of the SecureBigInteger-side theory of the same name.
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
        using var shares = new Shares<BigInteger>(new[]
        {
            new Share<BigInteger>(new BigIntCalculator(1), new BigIntCalculator(10)),
            new Share<BigInteger>(new BigIntCalculator(2), new BigIntCalculator(20)),
        });
        using var reconstructor = new SecretReconstructor<BigInteger>(new ExtendedEuclideanAlgorithm<BigInteger>());

        // Act & Assert
        var error = Assert.Throws<ArgumentOutOfRangeException>(
            () => reconstructor.Reconstruction(shares, securityLevel));
        Assert.Equal("securityLevel", error.ParamName);
    }

    /// <summary>
    /// Shares recording different levels are refused with no level supplied: there is nothing to
    /// choose between them, and picking one would be the guesswork this fix removes.
    /// Mirror of the SecureBigInteger-side fact of the same name.
    /// </summary>
    [Fact]
    public void Reconstruction_WhenSharesRecordDifferentLevels_Throws()
    {
        // Arrange
        using var shares = new Shares<BigInteger>(new[]
        {
            new Share<BigInteger>(new BigIntCalculator(1), new BigIntCalculator(10), 17),
            new Share<BigInteger>(new BigIntCalculator(2), new BigIntCalculator(20), 19),
        });
        using var reconstructor = new SecretReconstructor<BigInteger>(new ExtendedEuclideanAlgorithm<BigInteger>());

        // Act & Assert
        Assert.Throws<ReconstructionException>(() => reconstructor.Reconstruction(shares));
    }

    /// <summary>
    /// A set in which some shares record a level and others do not is refused as well. The recorded
    /// level cannot be assumed to govern the others, and assuming it would reintroduce exactly the
    /// unverified inference this fix exists to remove.
    /// Mirror of the SecureBigInteger-side fact of the same name.
    /// </summary>
    [Fact]
    public void Reconstruction_WhenShareMetadataIsMixed_Throws()
    {
        // Arrange
        using var shares = new Shares<BigInteger>(new[]
        {
            new Share<BigInteger>(new BigIntCalculator(1), new BigIntCalculator(10), 17),
            new Share<BigInteger>(new BigIntCalculator(2), new BigIntCalculator(20)),
        });
        using var reconstructor = new SecretReconstructor<BigInteger>(new ExtendedEuclideanAlgorithm<BigInteger>());

        // Act & Assert
        Assert.Throws<ReconstructionException>(() => reconstructor.Reconstruction(shares));
    }

    /// <summary>
    /// A coordinate outside the named field is refused before the interpolation runs. The level is
    /// asserted here rather than derived from the values, so the two can disagree — and a value
    /// that does not fit cannot have come from that field.
    /// Mirror of the SecureBigInteger-side fact of the same name.
    /// </summary>
    [Fact]
    public void Reconstruction_WhenACoordinateDoesNotFitTheNamedField_Throws()
    {
        // Arrange — 9000 exceeds M13 = 8191.
        using var shares = new Shares<BigInteger>(new[]
        {
            new Share<BigInteger>(new BigIntCalculator(1), new BigIntCalculator(9000)),
            new Share<BigInteger>(new BigIntCalculator(2), new BigIntCalculator(20)),
        });
        using var reconstructor = new SecretReconstructor<BigInteger>(new ExtendedEuclideanAlgorithm<BigInteger>());

        // Act & Assert
        Assert.Throws<ReconstructionException>(() => reconstructor.Reconstruction(shares, 13));
    }

    /// <summary>
    /// The explicit form is reachable through an abstraction, not only through the concrete type.
    /// The interface inherits <see cref="IReconstructionUseCase{TNumber}"/>, so one injected
    /// reference offers both call shapes — but a container registration for the base interface does
    /// not resolve this one, which is why the DI guidance registers it separately.
    /// Mirror of the SecureBigInteger-side fact of the same name.
    /// </summary>
    [Fact]
    public void Reconstruction_ExplicitForm_IsReachableThroughTheInterface()
    {
        // Arrange
        using var secret = new Secret<BigInteger>(new byte[] { 0x2A });
        using var splitter = new SecretSplitter<BigInteger>();
        splitter.SecurityLevel = 17;
        using var shares = splitter.MakeShares(2, 2, secret);
        using var reconstructor = new SecretReconstructor<BigInteger>(new ExtendedEuclideanAlgorithm<BigInteger>());

        // Act
        IReconstructionWithSecurityLevelUseCase<BigInteger> useCase = reconstructor;
        using var viaExplicit = useCase.Reconstruction(shares, splitter.SecurityLevel);
        using var viaBase = ((IReconstructionUseCase<BigInteger>)useCase).Reconstruction(shares);

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
    private sealed class PlainSecurityLevelManager : ISecurityLevelManager<BigInteger>
    {
        private readonly SecurityLevelManager<BigInteger> inner = new SecurityLevelManager<BigInteger>();

        public int SecurityLevel
        {
            get => this.inner.SecurityLevel;
            set => this.inner.SecurityLevel = value;
        }

        public Calculator<BigInteger> MersennePrime => this.inner.MersennePrime;

        public void AdjustSecurityLevel(Calculator<BigInteger> maximumY) => this.inner.AdjustSecurityLevel(maximumY);

        public void Dispose() => this.inner.Dispose();
    }

    /// <summary>
    /// A manager lacking the non-mutating capability is a supported configuration, not an error:
    /// reconstruction still works, and a level recorded on the shares is still used.
    /// Mirror of the SecureBigInteger-side fact of the same name.
    /// </summary>
    [Fact]
    public void Reconstruction_WithAManagerLackingTheCapability_StillUsesTheRecordedLevel()
    {
        // Arrange
        using var secret = new Secret<BigInteger>(new byte[] { 0x2A });
        using var splitter = new SecretSplitter<BigInteger>();
        splitter.SecurityLevel = 17;
        using var shares = splitter.MakeShares(2, 2, secret);
        using var plainManager = new PlainSecurityLevelManager();
        using var reconstructor = new SecretReconstructor<BigInteger>(new ExtendedEuclideanAlgorithm<BigInteger>(), plainManager);

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
    /// Mirror of the SecureBigInteger-side fact of the same name.
    /// </summary>
    [Fact]
    public void Reconstruction_WithAManagerLackingTheCapability_CatchesANormalisedLevelOnReadBack()
    {
        // Arrange
        using var shares = new Shares<BigInteger>(new[]
        {
            new Share<BigInteger>(new BigIntCalculator(1), new BigIntCalculator(10)),
            new Share<BigInteger>(new BigIntCalculator(2), new BigIntCalculator(20)),
        });
        using var plainManager = new PlainSecurityLevelManager();
        using var reconstructor = new SecretReconstructor<BigInteger>(new ExtendedEuclideanAlgorithm<BigInteger>(), plainManager);

        // Act & Assert — 18 is not a Mersenne exponent; the setter would round it to 19.
        var error = Assert.Throws<ArgumentOutOfRangeException>(() => reconstructor.Reconstruction(shares, 18));
        Assert.Equal("securityLevel", error.ParamName);
    }
    /// <summary>
    /// Without the exact check the exponent is vetted by the manager, before any of it reaches the
    /// big-integer arithmetic. Every rejection comes back as the same argument error naming the
    /// same parameter, whatever the manager's own setter would have called it — a caller cannot act
    /// on a parameter name it never supplied.
    /// Mirror of the SecureBigInteger-side theory of the same name.
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
        using var shares = new Shares<BigInteger>(new[]
        {
            new Share<BigInteger>(new BigIntCalculator(1), new BigIntCalculator(10)),
            new Share<BigInteger>(new BigIntCalculator(2), new BigIntCalculator(20)),
        });
        using var plainManager = new PlainSecurityLevelManager();
        using var reconstructor = new SecretReconstructor<BigInteger>(new ExtendedEuclideanAlgorithm<BigInteger>(), plainManager);

        // Act & Assert
        var error = Assert.Throws<ArgumentOutOfRangeException>(
            () => reconstructor.Reconstruction(shares, securityLevel));
        Assert.Equal("securityLevel", error.ParamName);
    }

    /// <summary>
    /// A negative y-coordinate is outside the field even though it is below the prime. Comparing
    /// only against the upper bound would let it through, and the interpolation would run on a
    /// point that is not in the field it claims to be in.
    /// Mirror of the SecureBigInteger-side fact of the same name.
    /// </summary>
    [Fact]
    public void Reconstruction_WithANegativeCoordinate_Throws()
    {
        // Arrange
        using var shares = new Shares<BigInteger>(new[]
        {
            new Share<BigInteger>(new BigIntCalculator(1), new BigIntCalculator(-489)),
            new Share<BigInteger>(new BigIntCalculator(2), new BigIntCalculator(-1489)),
        });
        using var reconstructor = new SecretReconstructor<BigInteger>(new ExtendedEuclideanAlgorithm<BigInteger>());

        // Act & Assert
        Assert.Throws<ReconstructionException>(() => reconstructor.Reconstruction(shares, 13));
    }

    /// <summary>
    /// The legacy path checks coordinates too. Deriving the field from the maximum y bounds one
    /// coordinate and says nothing about the indices: an index at or above the prime lies outside
    /// the permitted coordinate range. It need not collide with another to be invalid — here
    /// <c>8192</c> reduces to <c>1</c> modulo <c>8191</c>, and no share holds index 1.
    /// Mirror of the SecureBigInteger-side fact of the same name.
    /// </summary>
    [Fact]
    public void Reconstruction_WhenAnIndexExceedsTheDerivedField_Throws()
    {
        // Arrange — maximumY 2511 derives M13 = 8191, which index 8192 does not fit.
        using var shares = new Shares<BigInteger>(new[]
        {
            new Share<BigInteger>(new BigIntCalculator(8192), new BigIntCalculator(1511)),
            new Share<BigInteger>(new BigIntCalculator(2), new BigIntCalculator(2511)),
        });
        using var reconstructor = new SecretReconstructor<BigInteger>(new ExtendedEuclideanAlgorithm<BigInteger>());

        // Act & Assert
        Assert.Throws<ReconstructionException>(() => reconstructor.Reconstruction(shares));
    }

    /// <summary>
    /// With an inspectable manager, duplicate indices are refused before the security level moves.
    /// The check has to happen either way — a repeated index makes the Lagrange denominator zero —
    /// but running it after the commit would leave the manager on a level the caller never asked
    /// for, on an input that was never usable. On the compatibility path a rejected input may leave
    /// the manager moved, as
    /// <c>Reconstruction_WithAManagerLackingTheCapability_MayLeaveTheManagerMoved</c> pins for an
    /// out-of-field coordinate.
    /// <para>
    /// Comparing the level number alone would not catch that: the setter swaps in a freshly built
    /// prime and disposes the previous instance, so a manager moved to 17 and back to 31 reports
    /// 31 while every reference handed out beforehand is dead. The assertion therefore holds the
    /// prime instance from before the call and checks both that it is the same object and that it
    /// is still usable.
    /// </para>
    /// Mirror of the SecureBigInteger-side fact of the same name.
    /// </summary>
    [Fact]
    public void Reconstruction_WithDuplicateIndices_LeavesTheManagerUntouched()
    {
        // Arrange
        using var manager = new SecurityLevelManager<BigInteger>();
        manager.SecurityLevel = 31;
        var primeBefore = manager.MersennePrime;
        using var shares = new Shares<BigInteger>(new[]
        {
            new Share<BigInteger>(new BigIntCalculator(1), new BigIntCalculator(10), 17),
            new Share<BigInteger>(new BigIntCalculator(1), new BigIntCalculator(20), 17),
        });
        using var reconstructor = new SecretReconstructor<BigInteger>(new ExtendedEuclideanAlgorithm<BigInteger>(), manager);

        // Act & Assert
        Assert.Throws<ReconstructionException>(() => reconstructor.Reconstruction(shares));
        Assert.Equal(31, manager.SecurityLevel);
        Assert.Same(primeBefore, manager.MersennePrime);
        Assert.True(primeBefore.ByteCount > 0);
    }

    /// <summary>
    /// An unsupported exponent read off the shares is a reconstruction failure, not an argument
    /// error: the caller supplied no such argument to be told about. Same check as the explicit
    /// form, different boundary.
    /// Mirror of the SecureBigInteger-side fact of the same name.
    /// </summary>
    [Fact]
    public void Reconstruction_WhenTheSharesRecordAnUnsupportedLevel_ThrowsReconstructionException()
    {
        // Arrange — 18 is not a Mersenne prime exponent.
        using var shares = new Shares<BigInteger>(new[]
        {
            new Share<BigInteger>(new BigIntCalculator(1), new BigIntCalculator(10), 18),
            new Share<BigInteger>(new BigIntCalculator(2), new BigIntCalculator(20), 18),
        });
        using var reconstructor = new SecretReconstructor<BigInteger>(new ExtendedEuclideanAlgorithm<BigInteger>());

        // Act & Assert
        Assert.Throws<ReconstructionException>(() => reconstructor.Reconstruction(shares));
    }

    /// <summary>
    /// The same holds on the compatibility path, where the exponent is vetted by setting it and
    /// reading it back rather than by an exact check. The manager would have normalised 18 up to
    /// 19; the read-back catches that, and the failure keeps the type the boundary calls for.
    /// Mirror of the SecureBigInteger-side fact of the same name.
    /// </summary>
    [Fact]
    public void Reconstruction_WithAManagerLackingTheCapability_TypesAMetadataLevelFailureAsReconstruction()
    {
        // Arrange
        using var shares = new Shares<BigInteger>(new[]
        {
            new Share<BigInteger>(new BigIntCalculator(1), new BigIntCalculator(10), 18),
            new Share<BigInteger>(new BigIntCalculator(2), new BigIntCalculator(20), 18),
        });
        using var plainManager = new PlainSecurityLevelManager();
        using var reconstructor = new SecretReconstructor<BigInteger>(new ExtendedEuclideanAlgorithm<BigInteger>(), plainManager);

        // Act & Assert
        Assert.Throws<ReconstructionException>(() => reconstructor.Reconstruction(shares));
    }

    /// <summary>
    /// The state guarantee is narrower than it first looks, and the compatibility path is where it
    /// stops. Without <see cref="IInspectableSecurityLevelManager{TNumber}"/> there is no way to
    /// learn the field a value-derived selection would land on other than committing it, so
    /// <c>AdjustSecurityLevel</c> runs before anything is validated: here a manager sitting on 31
    /// is left on 13 although the index is outside that field and the call throws. The prime
    /// instance is replaced along with the level, so a reference handed out beforehand is dead.
    /// <para>
    /// This is pinned rather than only documented because it is the price of supporting a manager
    /// written before the capability existed, and the boundary between "rejected input leaves the
    /// manager alone" and "may not" has to stay visible.
    /// </para>
    /// Mirror of the SecureBigInteger-side fact of the same name.
    /// </summary>
    [Fact]
    public void Reconstruction_WithAManagerLackingTheCapability_MayLeaveTheManagerMoved()
    {
        // Arrange — 9000 exceeds M13 = 8191, the field the values 300 and 400 select.
        using var plainManager = new PlainSecurityLevelManager();
        plainManager.SecurityLevel = 31;
        using var primeBefore = plainManager.MersennePrime.Clone();
        using var shares = new Shares<BigInteger>(new[]
        {
            new Share<BigInteger>(new BigIntCalculator(9000), new BigIntCalculator(300)),
            new Share<BigInteger>(new BigIntCalculator(2), new BigIntCalculator(400)),
        });
        using var reconstructor = new SecretReconstructor<BigInteger>(new ExtendedEuclideanAlgorithm<BigInteger>(), plainManager);

        // Act & Assert
        Assert.Throws<ReconstructionException>(() => reconstructor.Reconstruction(shares));
        Assert.Equal(13, plainManager.SecurityLevel);
        Assert.False(primeBefore.Equals(plainManager.MersennePrime));
    }

    /// <summary>
    /// Mixed metadata is refused only where there is nothing to choose between the shares. Naming
    /// the field removes that problem: a set in which one share records 17 and the other records
    /// nothing reconstructs through <c>Reconstruction(shares, 17)</c>, because the explicit level
    /// decides and the recorded one is merely checked against it. The same set without the
    /// argument is refused, which is what makes this pair worth pinning — the two calls differ
    /// only in whether the caller supplied the field.
    /// Mirror of the SecureBigInteger-side fact of the same name.
    /// </summary>
    [Fact]
    public void Reconstruction_WithAnExplicitLevel_AcceptsMixedShareMetadata()
    {
        // Arrange
        using var secret = new Secret<BigInteger>(new byte[] { 0x2A });
        using var splitter = new SecretSplitter<BigInteger>();
        splitter.SecurityLevel = 17;
        using var tagged = splitter.MakeShares(2, 2, secret);
        var byIndex = tagged.ToArray();
        using var mixed = new Shares<BigInteger>(new[]
        {
            byIndex[0].ReissueWithSecurityLevel(17),
            new Share<BigInteger>(byIndex[1].Index.Clone(), byIndex[1].Value.Clone()),
        });
        using var reconstructor = new SecretReconstructor<BigInteger>(new ExtendedEuclideanAlgorithm<BigInteger>());

        // Act
        using var named = reconstructor.Reconstruction(mixed, 17);

        // Assert
        Assert.Equal(secret, named);
        Assert.Throws<ReconstructionException>(() => reconstructor.Reconstruction(mixed));
    }
}
