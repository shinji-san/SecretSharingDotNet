// ----------------------------------------------------------------------------
// <copyright file="ShamirsSecretSharingTest.cs" company="Private">
// Copyright (c) 2022 All Rights Reserved
// </copyright>
// <author>Sebastian Walther</author>
// <date>04/20/2019 10:52:28 PM</date>
// ----------------------------------------------------------------------------

#region License
// ----------------------------------------------------------------------------
// Copyright 2022 Sebastian Walther
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

using SecretSharingDotNet.Cryptography;
using SecretSharingDotNet.Cryptography.SecureInput;
using SecretSharingDotNet.Cryptography.ShamirsSecretSharing;
using SecretSharingDotNet.Math;
using SecretSharingDotNet.Math.Numerics;
using System;
using System.Linq;
using System.Numerics;
using System.Text;
using Xunit;

/// <summary>
/// Roundtrip integration tests covering <see cref="SecretSplitter{TNumber}"/> together with
/// <see cref="SecretReconstructor{TNumber}"/>.
/// </summary>
public class ShamirsSecretSharingTest
{
    /// <summary>
    /// Tests the security level auto-detection of <see cref="SecretSplitter{TNumber}"/>.
    /// </summary>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Performance", "CA1822:MarkMembersAsStatic")]
    [Theory]
    [MemberData(nameof(TestData.SecurityLevelAutoDetectionData), MemberType = typeof(TestData))]
    public void MakeShares_AutoUpgradesSecurityLevel_MatchesExpectedLevel(object secret, int expectedSecurityLevel)
    {
        // Arrange
        using var secretSplitter = new SecretSplitter<SecureBigInteger>();
        using var secretReconstructor = new SecretReconstructor<SecureBigInteger>(new MersenneSafeGcdAlgorithm<SecureBigInteger>());

        // Act & Assert
        switch (secret)
        {
            case string password:
                using (var pinnedText = password.ToPinnedSecure())
                using (var s = Secret<SecureBigInteger>.FromText(pinnedText))
                {
                    RunAutoDetectionRoundTrip(secretSplitter, secretReconstructor, s, expectedSecurityLevel,
                        recovered => SecretAssertions.AssertSecretEqualsString(password, recovered));
                }
                break;
            case BigInteger number:
                using (var secretNumber = number.ToSecureBigInteger())
                using (var s = (Secret<SecureBigInteger>)secretNumber)
                {
                    RunAutoDetectionRoundTrip(secretSplitter, secretReconstructor, s, expectedSecurityLevel,
                        recovered =>
                        {
                            using var secureBigInteger = (SecureBigInteger)recovered;
                            var bigInteger = secureBigInteger.ToBigInteger();
                            Assert.Equal(number, bigInteger);
                        });
                }
                break;
            case null:
                return;
        }
    }

    private static void RunAutoDetectionRoundTrip(
        SecretSplitter<SecureBigInteger> secretSplitter,
        SecretReconstructor<SecureBigInteger> secretReconstructor,
        Secret<SecureBigInteger> s,
        int expectedSecurityLevel,
        Action<Secret<SecureBigInteger>> typeAssert)
    {
        using var shares = secretSplitter.MakeShares(3, 7, s);
        Assert.NotNull(shares);
        var subSet1 = shares.Where(p => p.IsIndexOdd).ToArray();
        using var recoveredSecret1 = secretReconstructor.Reconstruction(subSet1);
        var subSet2 = shares.Where(p => p.IsIndexEven).ToArray();
        using var recoveredSecret2 = secretReconstructor.Reconstruction(subSet2);

        typeAssert(recoveredSecret1);
        Assert.Equal(s, recoveredSecret1);
        Assert.Equal(s, recoveredSecret2);
        Assert.Equal(expectedSecurityLevel, secretSplitter.SecurityLevel);
    }

    /// <summary>
    /// Tests <see cref="SecretSplitter{TNumber}"/> with <see cref="string"/> as secret.
    /// </summary>
    /// <param name="splitSecurityLevel">Initial security level for secret split phase</param>
    /// <param name="expectedSecurityLevel">Expected security level after secret reconstruction</param>
    /// <param name="password">A <see cref="string"/> as secret to test with</param>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Performance", "CA1822:MarkMembersAsStatic")]
    [Theory]
    [MemberData(nameof(TestData.TestPasswordData), MemberType = typeof(TestData))]
    public void MakeAndReconstruct_FromPassword_RestoresOriginalString(int splitSecurityLevel, int expectedSecurityLevel, string password)
    {
        // Arrange
        using var secretSplitter = new SecretSplitter<SecureBigInteger>();
        using var secretReconstructor = new SecretReconstructor<SecureBigInteger>(new MersenneSafeGcdAlgorithm<SecureBigInteger>());
        using var pinnedPassword = password.ToPinnedSecure();
        using var passwordSecret = Secret<SecureBigInteger>.FromText(pinnedPassword);

        // Act
        using var shares = secretSplitter.MakeShares(3, 7, passwordSecret, splitSecurityLevel);
        var subSet1 = shares.Where(p => p.IsIndexOdd).ToArray();
        using var recoveredSecret1 = secretReconstructor.Reconstruction(subSet1);
        var subSet2 = shares.Where(p => p.IsIndexEven).ToArray();
        using var recoveredSecret2 = secretReconstructor.Reconstruction(subSet2);

        // Assert
        SecretAssertions.AssertSecretEqualsString(password, recoveredSecret1);
        SecretAssertions.AssertSecretEqualsString(password, recoveredSecret2);
        Assert.Equal(expectedSecurityLevel, secretSplitter.SecurityLevel);
    }

    /// <summary>
    /// Tests <see cref="SecretSplitter{TNumber}"/> with <see cref="SecureBigInteger"/> as secret.
    /// </summary>
    /// <param name="splitSecurityLevel">Initial security level for secret split phase</param>
    /// <param name="expectedSecurityLevel">Expected security level after secret reconstruction</param>
    /// <param name="number">An integer number as secret to test with</param>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Performance", "CA1822:MarkMembersAsStatic")]
    [Theory]
    [MemberData(nameof(TestData.TestNumberData), MemberType = typeof(TestData))]
    public void MakeAndReconstruct_FromBigIntegerSecret_RestoresOriginalNumber(int splitSecurityLevel, int expectedSecurityLevel, BigInteger number)
    {
        // Arrange
        using var secretSplitter = new SecretSplitter<SecureBigInteger>();
        using var secretReconstructor = new SecretReconstructor<SecureBigInteger>(new MersenneSafeGcdAlgorithm<SecureBigInteger>());
        using var secretNumber = number.ToSecureBigInteger();

        // Act
        using var shares = secretSplitter.MakeShares(3, 7, secretNumber, splitSecurityLevel);
        var subSet1 = shares.Where(p => p.IsIndexOdd).ToArray();
        using var recoveredSecret1 = secretReconstructor.Reconstruction(subSet1);
        var subSet2 = shares.Where(p => p.IsIndexEven).ToArray();
        using var recoveredSecret2 = secretReconstructor.Reconstruction(subSet2);

        // Assert
        Assert.Equal(expectedSecurityLevel, secretSplitter.SecurityLevel);
    }

    /// <summary>
    /// Tests <see cref="SecretSplitter{TNumber}"/> with random <see cref="SecureBigInteger"/> value as secret.
    /// </summary>
    /// <param name="splitSecurityLevel">Initial security level for secret split phase</param>
    /// <param name="expectedSecurityLevel">Expected security level after secret reconstruction</param>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Performance", "CA1822:MarkMembersAsStatic")]
    [Theory]
    [MemberData(nameof(TestData.TestRandomSecretData), MemberType = typeof(TestData))]
    public void MakeAndReconstruct_FromRandomSecret_RestoresOriginal(int splitSecurityLevel, int expectedSecurityLevel)
    {
        // Arrange
        using var secretSplitter = new SecretSplitter<SecureBigInteger>();
        using var secretReconstructor = new SecretReconstructor<SecureBigInteger>(new MersenneSafeGcdAlgorithm<SecureBigInteger>());

        // Act
        using var shares = secretSplitter.MakeShares(3, 7, splitSecurityLevel, out var originalSecret);
        using (originalSecret)
        {
            var subSet1 = shares.Where(p => p.IsIndexOdd).ToArray();
            using var recoveredSecret1 = secretReconstructor.Reconstruction(subSet1);
            var subSet2 = shares.Where(p => p.IsIndexEven).ToArray();
            using var recoveredSecret2 = secretReconstructor.Reconstruction(subSet2);

            // Assert
            Assert.Equal(originalSecret, recoveredSecret1);
            Assert.Equal(originalSecret, recoveredSecret2);
            Assert.Equal(expectedSecurityLevel, secretSplitter.SecurityLevel);
        }
    }

    /// <summary>
    /// Tests the MakeShares method with a minimum shares number of 1 to be sure that an error occurs.
    /// Only a minimum shares number of greater or equal to 2 is valid.
    /// </summary>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Performance", "CA1822:MarkMembersAsStatic")]
    [Fact]
    public void MakeShares_MinimumThresholdBelowTwo_ThrowsArgumentOutOfRangeException()
    {
        // Arrange
        using var secretSplitter = new SecretSplitter<SecureBigInteger>();

        // Act & Assert
        Assert.Throws<ArgumentOutOfRangeException>(() => secretSplitter.MakeShares(1, 7, 5, out _));
    }

    /// <summary>
    /// Tests
    /// </summary>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Performance", "CA1822:MarkMembersAsStatic")]
    [Fact]
    public void Reconstruction_BelowMinimumThreshold_ThrowsArgumentOutOfRangeException()
    {
        // Arrange
        using var secretSplitter = new SecretSplitter<SecureBigInteger>();
        using var secretReconstructor = new SecretReconstructor<SecureBigInteger>(new MersenneSafeGcdAlgorithm<SecureBigInteger>());

        // Act & Assert
        using var shares = secretSplitter.MakeShares(2, 7, 13, out var discardedSecret);
        using (discardedSecret)
        {
            using var oneCalc = Calculator<SecureBigInteger>.One;
            var subSet = shares.Where(p => p.Index == oneCalc).ToArray();
            Assert.Throws<ArgumentOutOfRangeException>(() => secretReconstructor.Reconstruction(subSet));
        }
    }

    /// <summary>
    /// Tests
    /// </summary>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Performance", "CA1822:MarkMembersAsStatic")]
    [Fact]
    public void Reconstruction_FewerSharesThanThreshold_ProducesIncorrectSecret()
    {
        // Arrange
        using var secretSplitter = new SecretSplitter<SecureBigInteger>();
        using var secretReconstructor = new SecretReconstructor<SecureBigInteger>(new MersenneSafeGcdAlgorithm<SecureBigInteger>());

        // Act
        using var shares = secretSplitter.MakeShares(3, 7, 51, out var originalSecret);
        using (originalSecret)
        {
            var subSet = shares.Take(2).ToArray();
            using var secret = secretReconstructor.Reconstruction(subSet);

            // Assert
            Assert.NotEqual(originalSecret, secret);
        }
    }

    /// <summary>
    /// Tests whether or not bug #40 occurs [Maximum exceeded! (Parameter 'value') Actual value was 10912." #40].
    /// </summary>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Performance", "CA1822:MarkMembersAsStatic")]
    [Fact]
    public void MaximumExceeded()
    {
        // Arrange
        const string longSecret =
            "-----BEGIN EC PRIVATE KEY-----MIIBUQIBAQQgxq7AWG9L6uleuTB9q5FGqnHjXF+kD4y9154SLYYKMDqggeMwgeACAQEwLAYHKoZIzj0BAQIhAP////////////////////////////////////7///wvMEQEIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABwRBBHm+Zn753LusVaBilc6HCwcCm/zbLc4o2VnygVsW+BeYSDradyajxGVdpPv8DhEIqP0XtEimhVQZnEfQj/sQ1LgCIQD////////////////////+uq7c5q9IoDu/0l6M0DZBQQIBAaFEA0IABE0XO6I8lZYzXqRQnHP/knSwLex7q77g4J2AN0cVyrADicGlUr6QjVIlIu9NXCHxD2i++ToWjO1zLVdxgNJbUUc=-----END EC PRIVATE KEY-----";
        using var secretSplitter = new SecretSplitter<SecureBigInteger>();
        using var secretReconstructor = new SecretReconstructor<SecureBigInteger>(new MersenneSafeGcdAlgorithm<SecureBigInteger>());
        using var pinnedLong = longSecret.ToPinnedSecure();
        using var longSecretValue = Secret<SecureBigInteger>.FromText(pinnedLong);

        // Act
        using var shares = secretSplitter.MakeShares(3, 7, longSecretValue, 1024);
        var subSet1 = shares.Where(p => p.IsIndexOdd).ToArray();
        using var recoveredSecret1 = secretReconstructor.Reconstruction(subSet1);
        var subSet2 = shares.Where(p => p.IsIndexEven).ToArray();
        using var recoveredSecret2 = secretReconstructor.Reconstruction(subSet2);

        // Assert
        SecretAssertions.AssertSecretEqualsString(longSecret, recoveredSecret1);
        SecretAssertions.AssertSecretEqualsString(longSecret, recoveredSecret2);
    }

    /// <summary>
    /// Tests the secret reconstruction from an array of shares represented by strings
    /// </summary>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Performance", "CA1822:MarkMembersAsStatic")]
    [Fact]
    public void Reconstruction_FromTextLines_RestoresDefaultPassword()
    {
        // Arrange
        using var secretReconstructor = new SecretReconstructor<SecureBigInteger>(new MersenneSafeGcdAlgorithm<SecureBigInteger>());
        using var lines = TestData.GetPredefinedShares().ToPinnedSecureShareLines();

        // Act
        using Shares<SecureBigInteger> shares = Shares<SecureBigInteger>.FromTextLines(lines);
        using var secret = secretReconstructor.Reconstruction(shares);

        // Assert
        SecretAssertions.AssertSecretEqualsString(TestData.DefaultTestPassword, secret);
    }

    /// <summary>
    /// Tests the secret reconstruction from shares represented by a single string (separated by newline)
    /// </summary>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Performance", "CA1822:MarkMembersAsStatic")]
    [Fact]
    public void Reconstruction_FromConcatenatedText_RestoresDefaultPassword()
    {
        // Arrange
        var sharesChunk = new StringBuilder();
        foreach (var share in TestData.GetPredefinedShares())
        {
            sharesChunk.AppendLine(share);
        }

        using var secretReconstructor = new SecretReconstructor<SecureBigInteger>(new MersenneSafeGcdAlgorithm<SecureBigInteger>());
        using var blob = sharesChunk.ToString().ToPinnedSecure();

        // Act
        using Shares<SecureBigInteger> shares = Shares<SecureBigInteger>.FromText(blob);
        using var secret = secretReconstructor.Reconstruction(shares);

        // Assert
        SecretAssertions.AssertSecretEqualsString(TestData.DefaultTestPassword, secret);
    }

    /// <summary>
    /// Deterministic Tier-1 regression for bug #60. The original bug was that
    /// <see cref="SecureBigInteger"/>'s ctor reads the top bit of the last byte
    /// as the two's-complement sign bit, so any random message whose last byte
    /// was <c>&gt;= 0x80</c> was decoded as a negative value and broke modular
    /// reconstruction. The fix appends a random termination byte in
    /// <c>[1, 0x7F]</c> to the secret's pinned buffer; the inline data here are
    /// byte patterns that would deterministically trigger the original bug if
    /// the termination-byte invariant ever regressed, so this theory catches
    /// such a regression on every run rather than relying on Monte Carlo luck.
    /// Mirror of the BigInteger-side theory of the same name.
    /// </summary>
    /// <param name="message">Byte pattern with the top bit set in its last byte
    /// (or otherwise designed to trip the sign-bit path under the legacy code).</param>
    [Theory]
    [InlineData(new byte[] { 0xFF })]
    [InlineData(new byte[] { 0xFF, 0xFF })]
    [InlineData(new byte[] { 0x00, 0x80 })]
    [InlineData(new byte[] { 0xFF, 0xFF, 0xFF, 0xFF })]
    [InlineData(new byte[] { 0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE })]
    public void ReconstructionRoundTrip_FromTopBitSetMessage_RestoresOriginal(byte[] message)
    {
        // Arrange
        using var secretSplitter = new SecretSplitter<SecureBigInteger>();
        using var secretReconstructor = new SecretReconstructor<SecureBigInteger>(new MersenneSafeGcdAlgorithm<SecureBigInteger>());
        const int n = 5;
        var base64 = Convert.ToBase64String(message);
        using var pinnedBase64 = base64.ToPinnedSecure();

        // Act
        using var secret = Secret<SecureBigInteger>.FromBase64(pinnedBase64);
        using var shares = secretSplitter.MakeShares((n + 1) / 2, n, secret);
        using var reconstructedSecret = secretReconstructor.Reconstruction(shares.Take((n + 1) / 2).ToArray());
        using var reconstructedBase64 = reconstructedSecret.ToBase64CharArray();
        var reconstructed =
            Convert.FromBase64String(new string(reconstructedBase64.PoolArray, 0, reconstructedBase64.Length));

        // Assert
        Assert.Equal(message, reconstructed);
    }

    /// <summary>
    /// Tests whether or not bug #60 occurs [Reconstruction fails at random].
    /// Reduced Tier-2 Monte-Carlo loop (20 iters per byte size, down from the
    /// 1000 on the BigInteger backend) — the SecureBigInteger arithmetic and
    /// the constant-time Bernstein-Yang divsteps in <c>MersenneSafeGcdAlgorithm</c>
    /// are deliberately slower than the value-type backend, so the iteration
    /// budget is scaled to keep the test in a tolerable runtime. The deterministic
    /// Tier-1 vectors in <c>ReconstructionRoundTrip_FromTopBitSetMessage_RestoresOriginal</c>
    /// catch the specific #60 pattern with probability 1; this Tier-2 loop is
    /// defense-in-depth against subtler related regressions (a 10%-per-iter bug
    /// is still caught with probability 1-0.9^20 ≈ 0.88 across the 10 byte sizes).
    /// </summary>
    [Theory]
    [MemberData(nameof(TestData.ByteArraySize), MemberType = typeof(TestData))]
    public void ReconstructionFailsAtRnd(int byteArraySize)
    {
        // Arrange
        int ok = 0;
        const int total = 20;
        using var secretSplitter = new SecretSplitter<SecureBigInteger>();
        using var secretReconstructor = new SecretReconstructor<SecureBigInteger>(new MersenneSafeGcdAlgorithm<SecureBigInteger>());
        var rng = new Random();

        // Act
        for (int i = 0; i < total; i++)
        {
            var message = new byte[byteArraySize];
            rng.NextBytes(message);
            const int n = 5;
            var s = Convert.ToBase64String(message);
            using var pinnedBase64 = s.ToPinnedSecure();
            using var secret = Secret<SecureBigInteger>.FromBase64(pinnedBase64);
            using var shares = secretSplitter.MakeShares((n + 1) / 2, n, secret);
            using var reconstructedSecret = secretReconstructor.Reconstruction(shares.Take((n + 1) / 2).ToArray());
            using var reconstructedBase64 = reconstructedSecret.ToBase64CharArray();
            var reconstructed =
                Convert.FromBase64String(new string(reconstructedBase64.PoolArray, 0, reconstructedBase64.Length));
            if (message.SequenceEqual(reconstructed))
                ok++;
        }

        // Assert
        Assert.Equal(1.0, (double)ok / total);
    }

    /// <summary>
    /// Deterministic Tier-1 regression for the path on which the old heuristic refitted the level
    /// to a <em>smaller</em> Mersenne prime than the one the secret was split with. Since the share
    /// records the field it was created in, <see cref="IReconstructionUseCase{TNumber}.Reconstruction"/>
    /// reads that level instead of deriving one from the maximum share value, so the refit does
    /// not happen at all and these vectors round-trip because the field is right — not because the
    /// reduction in a smaller field happened to be a no-op.
    /// <para>
    /// <paramref name="heuristicLevel"/> is the exponent the old derivation <em>would</em> have
    /// chosen. Asserting the reconstructor does not go there is the point of these vectors: they
    /// were selected precisely because every share value falls below that smaller prime, which is
    /// what used to trigger the refit. The seeds stay pinned because reaching this shape at all is
    /// a low-probability event a Monte Carlo run may miss entirely.
    /// </para>
    /// <para>
    /// The legacy path is covered separately, by
    /// <c>Reconstruction_WhenSharesCarryNoLevel_StillRefitsDownward</c>: shares built from bare
    /// coordinates carry no level, so the derivation still runs for them and its consequences are
    /// unchanged.
    /// </para>
    /// Mirror of the BigInteger-side theory of the same name.
    /// </summary>
    /// <param name="seed">Seed driving both the secret's mark byte and the polynomial coefficients.</param>
    /// <param name="securityLevel">Mersenne exponent the secret is split with.</param>
    /// <param name="heuristicLevel">Smaller exponent the value-derived selection would have picked.</param>
    [Theory]
    [InlineData(28, 17, 13)]
    [InlineData(45, 17, 13)]
    [InlineData(62, 17, 13)]
    [InlineData(15, 19, 17)]
    [InlineData(42, 19, 17)]
    [InlineData(152, 31, 19)]
    public void ReconstructionRoundTrip_WhenSharesRecordTheirLevel_DoesNotRefitDownward(
        int seed, int securityLevel, int heuristicLevel)
    {
        // Arrange
        using var secret = new Secret<SecureBigInteger>([0x2A], 1, new DeterministicRandomSource(seed));
        using var secretSplitter = new SecretSplitter<SecureBigInteger>(new DeterministicRandomSource(seed));
        secretSplitter.SecurityLevel = securityLevel;
        using var secretReconstructor = new SecretReconstructor<SecureBigInteger>(new MersenneSafeGcdAlgorithm<SecureBigInteger>());

        // Act
        using var shares = secretSplitter.MakeShares(2, 2, secret);
        using var reconstructedSecret = secretReconstructor.Reconstruction(shares);

        // Assert
        Assert.Equal(securityLevel, secretSplitter.SecurityLevel);
        Assert.Equal(securityLevel, secretReconstructor.SecurityLevel);
        Assert.NotEqual(heuristicLevel, secretReconstructor.SecurityLevel);
        Assert.Equal(secret, reconstructedSecret);
    }

    /// <summary>
    /// Tier-2 breadth for the same concern: across a range of requested security levels and share
    /// configurations, a split followed by a reconstruction restores the original secret. Tier-1
    /// above pins the refit path deterministically; this theory covers shapes the six pinned
    /// vectors do not enumerate.
    /// <para>
    /// <b>Every input is pinned, deliberately.</b> The message stream, the secret's mark byte and
    /// the polynomial coefficients all derive from <paramref name="requestedSecurityLevel"/>
    /// through <c>DeterministicRandomSource</c>. That was originally necessary because the round
    /// trip did not hold for every input: a loop drawing from <c>CryptoRandomSource</c> would have
    /// asserted a property that was false in general and gone red at random. Shares now record
    /// their field, so the property holds for anything this theory produces — but the vectors stay
    /// pinned, because a reproducible sample is worth more than a fresh one when it does fail, and
    /// the legacy path where the property still does not hold is one
    /// <c>Share</c> constructor away.
    /// </para>
    /// <para>
    /// <paramref name="requestedSecurityLevel"/> is a floor, not the level used. <c>MakeShares</c>
    /// raises the level to the next Mersenne exponent that fits the secret including its mark byte
    /// and never lowers it, so a one-byte message already lifts a requested 13 to 17.
    /// <paramref name="expectedEffectiveLevels"/> records the levels the sweep genuinely exercises,
    /// so the coverage claim is checked rather than assumed.
    /// </para>
    /// <para>
    /// The loop runs 20 iterations per case rather than the 1000 on the BigInteger backend: the
    /// SecureBigInteger arithmetic and the constant-time Bernstein-Yang divsteps in
    /// <c>MersenneSafeGcdAlgorithm</c> are deliberately slower than the value-type backend, so the
    /// budget is scaled to keep the runtime tolerable. The refit path itself is covered with
    /// probability 1 by the pinned Tier-1 vectors above, which makes this loop defense-in-depth
    /// rather than the primary guard — and the smaller budget is why its effective-level set is
    /// narrower than the BigInteger side's.
    /// </para>
    /// Mirror of the BigInteger-side theory of the same name.
    /// </summary>
    /// <param name="requestedSecurityLevel">Mersenne exponent requested before splitting; a lower bound on the level actually used.</param>
    /// <param name="k">Reconstruction threshold.</param>
    /// <param name="n">Number of shares created.</param>
    /// <param name="expectedEffectiveLevels">Ascending, comma-separated set of the levels the sweep actually splits with.</param>
    [Theory]
    [InlineData(13, 2, 2, "17,31,61")]
    [InlineData(17, 2, 2, "17,31,61")]
    [InlineData(19, 2, 3, "19,31,61")]
    [InlineData(31, 3, 5, "31,61")]
    public void ReconstructionRoundTrip_AcrossPinnedVectorsAndSecurityLevels_RestoresOriginal(
        int requestedSecurityLevel, int k, int n, string expectedEffectiveLevels)
    {
        // Arrange
        const int total = 20;
        int ok = 0;
        var effectiveLevels = new int[total];
        var vectorSource = new Random(requestedSecurityLevel);
        using var secretReconstructor = new SecretReconstructor<SecureBigInteger>(new MersenneSafeGcdAlgorithm<SecureBigInteger>());

        // Act
        for (int i = 0; i < total; i++)
        {
            var message = new byte[vectorSource.Next(1, 5)];
            vectorSource.NextBytes(message);
            using var secret = new Secret<SecureBigInteger>(message, message.Length, new DeterministicRandomSource(vectorSource.Next()));
            using var secretSplitter = new SecretSplitter<SecureBigInteger>(new DeterministicRandomSource(vectorSource.Next()));
            secretSplitter.SecurityLevel = requestedSecurityLevel;
            using var shares = secretSplitter.MakeShares(k, n, secret);
            using var reconstructedSecret = secretReconstructor.Reconstruction(shares);
            effectiveLevels[i] = secretSplitter.SecurityLevel;
            if (secret.Equals(reconstructedSecret))
            {
                ok++;
            }
        }

        // Assert
        Assert.Equal(total, ok);
        Assert.Equal(expectedEffectiveLevels, string.Join(",", effectiveLevels.Distinct().OrderBy(level => level)));
    }

    /// <summary>
    /// The two vectors that used to lose the secret at the refit boundary now round-trip. Nothing
    /// about their arithmetic changed: the shares record the field they were created in, and
    /// reconstruction reads that level instead of deriving one from the share values, so the
    /// interpolation runs in the field the split used.
    /// <para>
    /// Vector A is the loud one — coefficient exactly <c>M13</c>, which the old derivation reduced
    /// to zero, leaving no decodable secret. Vector B is the silent one — coefficient between
    /// <c>M19</c> and twice it, which came back as a different secret with no exception. Both are
    /// simply correct now.
    /// </para>
    /// <para>
    /// The legacy behaviour these vectors used to exhibit is not gone, only out of reach for
    /// shares that carry a level; it is pinned separately by
    /// <c>Reconstruction_WhenSharesCarryNoLevel_StillRefitsDownward</c> and
    /// <c>Reconstruction_WhenSharesCarryNoLevelAndTheCoefficientCollapses_ThrowsNamingTheExponent</c>.
    /// </para>
    /// Mirror of the BigInteger-side fact of the same name.
    /// </summary>
    [Fact]
    public void Reconstruction_AtTheOldRefitBoundary_RestoresTheSecret()
    {
        // Arrange — coefficient exactly M13; every share value below it.
        using var secretAtPrime = new Secret<SecureBigInteger>(new byte[] { 0xFF }, 1, new DeterministicRandomSource(12));
        using var splitterAtPrime = new SecretSplitter<SecureBigInteger>(new DeterministicRandomSource(171));
        splitterAtPrime.SecurityLevel = 17;
        using var reconstructor = new SecretReconstructor<SecureBigInteger>(new MersenneSafeGcdAlgorithm<SecureBigInteger>());

        // Act
        using var sharesAtPrime = splitterAtPrime.MakeShares(2, 2, secretAtPrime);
        using var recoveredAtPrime = reconstructor.Reconstruction(sharesAtPrime);

        // Assert — the split level is kept and the secret survives.
        Assert.Equal(17, reconstructor.SecurityLevel);
        Assert.Equal(secretAtPrime, recoveredAtPrime);

        // Arrange — coefficient above the prime the old derivation would have picked.
        using var secretAbovePrime = new Secret<SecureBigInteger>(new byte[] { 0xFF, 0xFF }, 2, new DeterministicRandomSource(16));
        using var splitterAbovePrime = new SecretSplitter<SecureBigInteger>(new DeterministicRandomSource(3544));
        splitterAbovePrime.SecurityLevel = 31;

        // Act
        using var sharesAbovePrime = splitterAbovePrime.MakeShares(2, 2, secretAbovePrime);
        using var recoveredAbovePrime = reconstructor.Reconstruction(sharesAbovePrime);

        // Assert
        Assert.Equal(31, reconstructor.SecurityLevel);
        Assert.Equal(secretAbovePrime, recoveredAbovePrime);
    }

    /// <summary>
    /// The vector that needs no large constant term — a one-byte secret with <c>a₀ = 511</c>, lost
    /// at a refit to <c>M13 = 8191</c> because a share value had wrapped modulo the original prime
    /// — now round-trips as well. It was the sharpest counterexample against the old reasoning and
    /// is the sharpest confirmation of the fix: the trigger was never the size of the constant
    /// term, and naming the field removes the whole class of failure rather than a boundary of it.
    /// Mirror of the BigInteger-side fact of the same name.
    /// </summary>
    [Fact]
    public void Reconstruction_WhenAShareValueWrappedInTheOriginalField_RestoresTheSecret()
    {
        // Arrange — a0 = 511, far below the prime the old derivation would have landed on.
        using var secret = new Secret<SecureBigInteger>(new byte[] { 0xFF }, 1, new DeterministicRandomSource(35));
        using var secretSplitter = new SecretSplitter<SecureBigInteger>(new DeterministicRandomSource(270));
        secretSplitter.SecurityLevel = 17;
        using var secretReconstructor = new SecretReconstructor<SecureBigInteger>(new MersenneSafeGcdAlgorithm<SecureBigInteger>());

        // Act — the two shares whose values both fall below M13.
        using var shares = secretSplitter.MakeShares(2, 280, secret);
        var sharesByIndex = shares.ToArray();
        var subSet = new[] { sharesByIndex[0], sharesByIndex[279] };
        using var reconstructed = secretReconstructor.Reconstruction(subSet);

        // Assert
        Assert.Equal(17, secretReconstructor.SecurityLevel);
        Assert.Equal(secret, reconstructed);
    }

    /// <summary>
    /// Shares that record no level still go through the value-derived selection, and it still
    /// lands in the wrong field. This is the same vector as the fact above with the level stripped
    /// by rebuilding the shares from bare coordinates, which is what a share persisted before the
    /// level became part of the format amounts to. The defect is removed for shares that carry a
    /// level, not for those that do not — and that distinction is the whole substance of the fix,
    /// so it is pinned rather than described.
    /// Mirror of the BigInteger-side fact of the same name.
    /// </summary>
    [Fact]
    public void Reconstruction_WhenSharesCarryNoLevel_StillRefitsDownward()
    {
        // Arrange
        using var secret = new Secret<SecureBigInteger>(new byte[] { 0xFF }, 1, new DeterministicRandomSource(35));
        using var secretSplitter = new SecretSplitter<SecureBigInteger>(new DeterministicRandomSource(270));
        secretSplitter.SecurityLevel = 17;
        using var secretReconstructor = new SecretReconstructor<SecureBigInteger>(new MersenneSafeGcdAlgorithm<SecureBigInteger>());
        using var shares = secretSplitter.MakeShares(2, 280, secret);
        var sharesByIndex = shares.ToArray();
        using var legacy = new Shares<SecureBigInteger>(new[]
        {
            new Share<SecureBigInteger>(sharesByIndex[0].Index.Clone(), sharesByIndex[0].Value.Clone()),
            new Share<SecureBigInteger>(sharesByIndex[279].Index.Clone(), sharesByIndex[279].Value.Clone()),
        });

        // Act
        using var reconstructed = secretReconstructor.Reconstruction(legacy);

        // Assert — the derivation runs, picks M13, and the secret does not survive it.
        Assert.Equal(13, secretReconstructor.SecurityLevel);
        Assert.NotEqual(secret, reconstructed);
    }

    /// <summary>
    /// The loud legacy failure keeps its diagnosis. Vector A with the level stripped still
    /// collapses to a coefficient carrying no payload, and the reconstruction layer still rejects
    /// that itself, naming the exponent it ran under rather than letting an
    /// <c>ArgumentException</c> escape from inside the <c>Secret</c> constructor.
    /// <para>
    /// This assertion is deliberately kept out of the inversion above: shares without a level go on
    /// reaching this path after the fix, and the diagnosis is the only thing the library can offer
    /// them.
    /// </para>
    /// Mirror of the BigInteger-side fact of the same name.
    /// </summary>
    [Fact]
    public void Reconstruction_WhenSharesCarryNoLevelAndTheCoefficientCollapses_ThrowsNamingTheExponent()
    {
        // Arrange
        using var secret = new Secret<SecureBigInteger>(new byte[] { 0xFF }, 1, new DeterministicRandomSource(12));
        using var splitter = new SecretSplitter<SecureBigInteger>(new DeterministicRandomSource(171));
        splitter.SecurityLevel = 17;
        using var reconstructor = new SecretReconstructor<SecureBigInteger>(new MersenneSafeGcdAlgorithm<SecureBigInteger>());
        using var shares = splitter.MakeShares(2, 2, secret);
        var byIndex = shares.ToArray();
        using var legacy = new Shares<SecureBigInteger>(new[]
        {
            new Share<SecureBigInteger>(byIndex[0].Index.Clone(), byIndex[0].Value.Clone()),
            new Share<SecureBigInteger>(byIndex[1].Index.Clone(), byIndex[1].Value.Clone()),
        });

        // Act & Assert
        var noSecret = Assert.Throws<ReconstructionException>(() => reconstructor.Reconstruction(legacy));
        Assert.Contains("13", noSecret.Message);
    }

}
