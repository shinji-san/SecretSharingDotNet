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

namespace SecretSharingDotNetTest.Cryptography.ShamirsSecretSharing.BigInteger;

using SecretSharingDotNet.Cryptography;
using SecretSharingDotNet.Cryptography.SecureInput;
using SecretSharingDotNet.Cryptography.ShamirsSecretSharing;
using SecretSharingDotNet.Math;
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
        using var secretSplitter = new SecretSplitter<BigInteger>();
        using var secretReconstructor = new SecretReconstructor<BigInteger>(new ExtendedEuclideanAlgorithm<BigInteger>());

        // Act & Assert
        switch (secret)
        {
            case string password:
                using (var pinnedText = password.ToPinnedSecure())
                using (var s = Secret<BigInteger>.FromText(pinnedText))
                {
                    RunAutoDetectionRoundTrip(secretSplitter, secretReconstructor, s, expectedSecurityLevel,
                        recovered => SecretAssertions.AssertSecretEqualsString(password, recovered));
                }
                break;
            case BigInteger number:
                using (var s = (Secret<BigInteger>)number)
                {
                    RunAutoDetectionRoundTrip(secretSplitter, secretReconstructor, s, expectedSecurityLevel,
                        recovered => Assert.Equal(number, (BigInteger)recovered));
                }
                break;
            case null:
                return;
        }
    }

    private static void RunAutoDetectionRoundTrip(
        SecretSplitter<BigInteger> secretSplitter,
        SecretReconstructor<BigInteger> secretReconstructor,
        Secret<BigInteger> s,
        int expectedSecurityLevel,
        Action<Secret<BigInteger>> typeAssert)
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
        using var secretSplitter = new SecretSplitter<BigInteger>();
        using var secretReconstructor = new SecretReconstructor<BigInteger>(new ExtendedEuclideanAlgorithm<BigInteger>());
        using var pinnedPassword = password.ToPinnedSecure();
        using var passwordSecret = Secret<BigInteger>.FromText(pinnedPassword);

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
    /// Tests <see cref="SecretSplitter{TNumber}"/> with <see cref="BigInteger"/> as secret.
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
        using var secretSplitter = new SecretSplitter<BigInteger>();
        using var secretReconstructor = new SecretReconstructor<BigInteger>(new ExtendedEuclideanAlgorithm<BigInteger>());

        // Act
        using var shares = secretSplitter.MakeShares(3, 7, number, splitSecurityLevel);
        var subSet1 = shares.Where(p => p.IsIndexOdd).ToArray();
        using var recoveredSecret1 = secretReconstructor.Reconstruction(subSet1);
        var subSet2 = shares.Where(p => p.IsIndexEven).ToArray();
        using var recoveredSecret2 = secretReconstructor.Reconstruction(subSet2);

        // Assert
        Assert.Equal(number, (BigInteger)recoveredSecret1);
        Assert.Equal(number, (BigInteger)recoveredSecret2);
        Assert.Equal(expectedSecurityLevel, secretSplitter.SecurityLevel);
    }

    /// <summary>
    /// Tests <see cref="SecretSplitter{TNumber}"/> with random <see cref="BigInteger"/> value as secret.
    /// </summary>
    /// <param name="splitSecurityLevel">Initial security level for secret split phase</param>
    /// <param name="expectedSecurityLevel">Expected security level after secret reconstruction</param>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Performance", "CA1822:MarkMembersAsStatic")]
    [Theory]
    [MemberData(nameof(TestData.TestRandomSecretData), MemberType = typeof(TestData))]
    public void MakeAndReconstruct_FromRandomSecret_RestoresOriginal(int splitSecurityLevel, int expectedSecurityLevel)
    {
        // Arrange
        using var secretSplitter = new SecretSplitter<BigInteger>();
        using var secretReconstructor = new SecretReconstructor<BigInteger>(new ExtendedEuclideanAlgorithm<BigInteger>());

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
        using var secretSplitter = new SecretSplitter<BigInteger>();

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
        using var secretSplitter = new SecretSplitter<BigInteger>();
        using var secretReconstructor = new SecretReconstructor<BigInteger>(new ExtendedEuclideanAlgorithm<BigInteger>());

        // Act & Assert
        using var shares = secretSplitter.MakeShares(2, 7, 13, out var discardedSecret);
        using (discardedSecret)
        {
            using var oneCalc = Calculator<BigInteger>.One;
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
        using var secretSplitter = new SecretSplitter<BigInteger>();
        using var secretReconstructor = new SecretReconstructor<BigInteger>(new ExtendedEuclideanAlgorithm<BigInteger>());

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
        using var secretSplitter = new SecretSplitter<BigInteger>();
        using var secretReconstructor = new SecretReconstructor<BigInteger>(new ExtendedEuclideanAlgorithm<BigInteger>());
        using var pinnedLong = longSecret.ToPinnedSecure();
        using var longSecretValue = Secret<BigInteger>.FromText(pinnedLong);

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
        using var secretReconstructor = new SecretReconstructor<BigInteger>(new ExtendedEuclideanAlgorithm<BigInteger>());
        using var lines = TestData.GetPredefinedShares().ToPinnedSecureShareLines();

        // Act
        using Shares<BigInteger> shares = Shares<BigInteger>.FromTextLines(lines);
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

        using var secretReconstructor = new SecretReconstructor<BigInteger>(new ExtendedEuclideanAlgorithm<BigInteger>());
        using var blob = sharesChunk.ToString().ToPinnedSecure();

        // Act
        using Shares<BigInteger> shares = Shares<BigInteger>.FromText(blob);
        using var secret = secretReconstructor.Reconstruction(shares);

        // Assert
        SecretAssertions.AssertSecretEqualsString(TestData.DefaultTestPassword, secret);
    }

    /// <summary>
    /// Deterministic Tier-1 regression for bug #60. The original bug was that
    /// <see cref="System.Numerics.BigInteger"/>'s ctor reads the top bit of the
    /// last byte as the two's-complement sign bit, so any random message whose
    /// last byte was <c>&gt;= 0x80</c> was decoded as a negative value and broke
    /// modular reconstruction. The fix appends a random termination byte in
    /// <c>[1, 0x7F]</c> to the secret's pinned buffer; the inline data here are
    /// byte patterns that would deterministically trigger the original bug if
    /// the termination-byte invariant ever regressed, so this theory catches
    /// such a regression on every run rather than relying on Monte Carlo luck.
    /// Mirror of the SecureBigInteger-side theory of the same name.
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
        using var secretSplitter = new SecretSplitter<BigInteger>();
        using var secretReconstructor = new SecretReconstructor<BigInteger>(new ExtendedEuclideanAlgorithm<BigInteger>());
        const int n = 5;
        var base64 = Convert.ToBase64String(message);
        using var pinnedBase64 = base64.ToPinnedSecure();

        // Act
        using var secret = Secret<BigInteger>.FromBase64(pinnedBase64);
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
    /// </summary>
    [Theory]
    [MemberData(nameof(TestData.ByteArraySize), MemberType = typeof(TestData))]
    public void ReconstructionFailsAtRnd(int byteArraySize)
    {
        // Arrange
        int ok = 0;
        const int total = 1000;
        using var secretSplitter = new SecretSplitter<BigInteger>();
        using var secretReconstructor = new SecretReconstructor<BigInteger>(new ExtendedEuclideanAlgorithm<BigInteger>());
        var rng = new Random();

        // Act
        for (int i = 0; i < total; i++)
        {
            var message = new byte[byteArraySize];
            rng.NextBytes(message);
            const int n = 5;
            var s = Convert.ToBase64String(message);
            using var pinnedBase64 = s.ToPinnedSecure();
            using var secret = Secret<BigInteger>.FromBase64(pinnedBase64);
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
    /// Deterministic Tier-1 regression for the reconstruction path on which
    /// <see cref="SecurityLevelManager{TNumber}.AdjustSecurityLevel"/> refits the level to a
    /// <em>smaller</em> Mersenne prime than the one the secret was split with. A share carries no
    /// record of the splitting modulus, so <see cref="IReconstructionUseCase{TNumber}.Reconstruction"/>
    /// derives the level from the maximum share value alone; whenever every share value happens to
    /// fall below a smaller prime, interpolation runs in that smaller field. The integer Lagrange
    /// combination is bounded by the small share values and pinned to the constant term exactly,
    /// so the reduction modulo the smaller prime is a no-op <em>as long as the constant term is
    /// itself below that prime</em> — which is the case for the vectors below, and is why they
    /// round-trip. It does <b>not</b> hold in general: see
    /// <c>Reconstruction_WhenConstantTermReachesTheRefittedPrime_LosesTheSecret</c> for the
    /// boundary where it fails. The seeds are pinned because reaching this path at all is a
    /// low-probability event a Monte Carlo run may miss entirely.
    /// Mirror of the SecureBigInteger-side theory of the same name.
    /// </summary>
    /// <param name="seed">Seed driving both the secret's mark byte and the polynomial coefficients.</param>
    /// <param name="securityLevel">Mersenne exponent the secret is split with.</param>
    /// <param name="expectedAdjustedLevel">Smaller exponent the reconstruction is expected to refit to.</param>
    [Theory]
    [InlineData(28, 17, 13)]
    [InlineData(45, 17, 13)]
    [InlineData(62, 17, 13)]
    [InlineData(15, 19, 17)]
    [InlineData(42, 19, 17)]
    [InlineData(152, 31, 19)]
    public void ReconstructionRoundTrip_WhenSecurityLevelRefitsToSmallerPrime_RestoresOriginal(
        int seed, int securityLevel, int expectedAdjustedLevel)
    {
        // Arrange
        using var secret = new Secret<BigInteger>([0x2A], 1, new DeterministicRandomSource(seed));
        using var secretSplitter = new SecretSplitter<BigInteger>(new DeterministicRandomSource(seed));
        secretSplitter.SecurityLevel = securityLevel;
        using var secretReconstructor = new SecretReconstructor<BigInteger>(new ExtendedEuclideanAlgorithm<BigInteger>());

        // Act
        using var shares = secretSplitter.MakeShares(2, 2, secret);
        using var reconstructedSecret = secretReconstructor.Reconstruction(shares);

        // Assert
        Assert.Equal(securityLevel, secretSplitter.SecurityLevel);
        Assert.Equal(expectedAdjustedLevel, secretReconstructor.SecurityLevel);
        Assert.Equal(secret, reconstructedSecret);
    }

    /// <summary>
    /// Tier-2 sweep for the same concern: across a range of security levels and share
    /// configurations, a split followed by a reconstruction always restores the original secret —
    /// whether or not the level is refitted downward on the way back. Tier-1 above pins the refit
    /// path deterministically; this theory covers breadth, so a regression that only shows up at a
    /// level or share shape not enumerated above still turns the suite red.
    /// Mirror of the SecureBigInteger-side theory of the same name.
    /// </summary>
    /// <param name="securityLevel">Mersenne exponent the secrets are split with.</param>
    /// <param name="k">Reconstruction threshold.</param>
    /// <param name="n">Number of shares created.</param>
    [Theory]
    [InlineData(13, 2, 2)]
    [InlineData(17, 2, 2)]
    [InlineData(19, 2, 3)]
    [InlineData(31, 3, 5)]
    public void ReconstructionRoundTrip_AcrossSecurityLevels_AlwaysRestoresOriginal(int securityLevel, int k, int n)
    {
        // Arrange
        const int total = 1000;
        int ok = 0;
        var rng = new Random(securityLevel);
        using var secretReconstructor = new SecretReconstructor<BigInteger>(new ExtendedEuclideanAlgorithm<BigInteger>());

        // Act
        for (int i = 0; i < total; i++)
        {
            var message = new byte[rng.Next(1, 5)];
            rng.NextBytes(message);
            using var secret = new Secret<BigInteger>(message);
            using var secretSplitter = new SecretSplitter<BigInteger>();
            secretSplitter.SecurityLevel = securityLevel;
            using var shares = secretSplitter.MakeShares(k, n, secret);
            using var reconstructedSecret = secretReconstructor.Reconstruction(shares);
            if (secret.Equals(reconstructedSecret))
            {
                ok++;
            }
        }

        // Assert
        Assert.Equal(total, ok);
    }

    /// <summary>
    /// Boundary case for the downward security-level refit, and a characterisation of a known
    /// defect rather than of intended behaviour. Reconstruction derives the level from the maximum
    /// share value, which cannot reveal whether the constant term exceeded the smaller prime. When
    /// it did, interpolation in the refitted field returns <c>a₀ mod P_small</c> instead of
    /// <c>a₀</c>, and the shares are untampered and individually valid throughout.
    /// <para>
    /// Seed 12 encodes the one-byte secret <c>0xFF</c> with mark byte <c>0x1F</c>, giving the
    /// coefficient 8191 — exactly <c>M13</c>. Splitter seed 171 at level 17 yields the shares
    /// 7476 and 6761, both below 8191, so the level refits to 13. The integer combination
    /// <c>2·7476 − 6761</c> is 8191, and 8191 mod 8191 is zero, which decodes to an empty secret
    /// and throws.
    /// </para>
    /// <para>
    /// The silent variant needs a coefficient strictly between the refitted prime and twice it,
    /// which a one-byte secret cannot reach: seed 16 encodes <c>0xFF 0xFF</c> as 786431, and at
    /// level 31 splitter seed 3544 yields 504116 and 221801, both below <c>M19</c>. Reconstruction
    /// refits to 19 and returns 786431 mod 524287 = 262144 — a different secret, with no exception.
    /// </para>
    /// <para>
    /// <b>These assertions pin current behaviour, not desired behaviour.</b> When the refit is
    /// fixed, both cases must round-trip and this test has to be inverted.
    /// </para>
    /// Mirror of the SecureBigInteger-side fact of the same name.
    /// </summary>
    [Fact]
    public void Reconstruction_WhenConstantTermReachesTheRefittedPrime_LosesTheSecret()
    {
        // Arrange — coefficient exactly M13; every share below it.
        using var secretAtPrime = new Secret<BigInteger>(new byte[] { 0xFF }, 1, new DeterministicRandomSource(12));
        using var splitterAtPrime = new SecretSplitter<BigInteger>(new DeterministicRandomSource(171));
        splitterAtPrime.SecurityLevel = 17;
        using var reconstructor = new SecretReconstructor<BigInteger>(new ExtendedEuclideanAlgorithm<BigInteger>());

        // Act & Assert — the refitted field maps the coefficient to zero, so no secret survives.
        using var sharesAtPrime = splitterAtPrime.MakeShares(2, 2, secretAtPrime);
        Assert.Throws<ArgumentException>(() => reconstructor.Reconstruction(sharesAtPrime));

        // Arrange — coefficient above the refitted prime but below twice it.
        using var secretAbovePrime = new Secret<BigInteger>(new byte[] { 0xFF, 0xFF }, 2, new DeterministicRandomSource(16));
        using var splitterAbovePrime = new SecretSplitter<BigInteger>(new DeterministicRandomSource(3544));
        splitterAbovePrime.SecurityLevel = 31;

        // Act
        using var sharesAbovePrime = splitterAbovePrime.MakeShares(2, 2, secretAbovePrime);
        using var reconstructed = reconstructor.Reconstruction(sharesAbovePrime);

        // Assert — reconstruction succeeds and returns the wrong secret.
        Assert.Equal(19, reconstructor.SecurityLevel);
        Assert.NotEqual(secretAbovePrime, reconstructed);
    }
}
