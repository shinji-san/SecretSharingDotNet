// ----------------------------------------------------------------------------
// <copyright file="SecurityLevelManagerTest.cs" company="Private">
// Copyright (c) 2025 All Rights Reserved
// </copyright>
// <author>Sebastian Walther</author>
// <date>10/03/2025 08:52:28 PM</date>
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


namespace SecretSharingDotNetTest.Cryptography.ShamirsSecretSharing.BigInteger;

using SecretSharingDotNet.Cryptography.ShamirsSecretSharing;
using SecretSharingDotNet.Math;
using System;
using System.Numerics;
using Xunit;
using Moq;
using SecretSharingDotNet.Math.Numerics;

/// <summary>
/// Tests for <see cref="SecurityLevelManager{TNumber}"/> on the <see cref="BigInteger"/>
/// backend — security-level → Mersenne-prime mapping, range guards, and the
/// <c>AdjustSecurityLevel</c> auto-upgrade/downgrade based on operand magnitude.
/// </summary>
public class SecurityLevelManagerTest
{
    /// <summary>
    /// Tests that the parameterless constructor wires in
    /// <see cref="MersennePrimeProvider.Instance"/> as the default provider and starts at
    /// the smallest tabulated exponent.
    /// </summary>
    [Fact]
    public void Constructor_WithoutParameter_InitializesWithDefaultMersennePrimeProvider()
    {
        // Arrange & Act
        using var securityLevelManager = new SecurityLevelManager<BigInteger>();

        // Assert
        Assert.NotNull(securityLevelManager);
        Assert.Equal(MersennePrimeProvider.Instance.MinMersennePrimeExponent, securityLevelManager.SecurityLevel);
        Assert.NotNull(securityLevelManager.MersennePrime);
    }

    /// <summary>
    /// Tests that the constructor with an injected <see cref="IMersennePrimeProvider"/> mock
    /// uses the mock's <c>MinMersennePrimeExponent</c> as the initial security level.
    /// </summary>
    [Fact]
    public void Constructor_WithMersennePrimeProvider_InitializesCorrectly()
    {
        // Arrange
        var mersennePrimeProviderMock = new Mock<IMersennePrimeProvider>();
        const int expectedSecurityLevel = 7;
        mersennePrimeProviderMock.Setup(p => p.MinMersennePrimeExponent).Returns(expectedSecurityLevel);
        mersennePrimeProviderMock.Setup(p => p.MaxMersennePrimeExponent).Returns(127);
        mersennePrimeProviderMock.Setup(p => p.IsValidMersennePrimeExponent(expectedSecurityLevel)).Returns(true);

        // Act
        using var securityLevelManager = new SecurityLevelManager<BigInteger>(mersennePrimeProviderMock.Object);

        // Assert
        Assert.NotNull(securityLevelManager);
        Assert.Equal(expectedSecurityLevel, securityLevelManager.SecurityLevel);
    }

    /// <summary>
    /// Tests that the injection constructor rejects a <see langword="null"/> provider with
    /// <see cref="ArgumentNullException"/> (<c>ParamName == "mersennePrimeProvider"</c>).
    /// </summary>
    [Fact]
    public void Constructor_WithNullProvider_ThrowsArgumentNullException()
    {
        // Arrange, Act & Assert
        var exception = Assert.Throws<ArgumentNullException>(() => new SecurityLevelManager<BigInteger>(null!));
        Assert.Equal("mersennePrimeProvider", exception.ParamName);
    }

    /// <summary>
    /// Tests that assigning a valid Mersenne exponent to
    /// <see cref="SecurityLevelManager{TNumber}.SecurityLevel"/> stores the value verbatim
    /// (no upgrade fires for an exponent that is already in the tabulated set).
    /// </summary>
    [Fact]
    public void SecurityLevel_Set_WithMersennePrimeExponent_SetsSecurityLevelCorrectly()
    {
        // Arrange
        using var securityLevelManager = new SecurityLevelManager<BigInteger>();
        const int initialSecurityLevel = 17;

        // Act
        securityLevelManager.SecurityLevel = initialSecurityLevel;

        // Assert
        Assert.Equal(initialSecurityLevel, securityLevelManager.SecurityLevel);
    }

    /// <summary>
    /// Tests that assigning a security level below the minimum tabulated Mersenne exponent
    /// throws <see cref="ArgumentOutOfRangeException"/> with the offending value attached.
    /// </summary>
    [Fact]
    public void SecurityLevel_Set_BelowMinimum_ThrowsArgumentOutOfRangeException()
    {
        // Arrange
        using var securityLevelManager = new SecurityLevelManager<BigInteger>();
        const int initialSecurityLevel = 10;

        // Act & Assert
        var exception = Assert.Throws<ArgumentOutOfRangeException>(() => 
            securityLevelManager.SecurityLevel = initialSecurityLevel);
        Assert.Equal("value", exception.ParamName);
        Assert.Equal(initialSecurityLevel, exception.ActualValue);
    }

    /// <summary>
    /// Tests that assigning a security level above the maximum tabulated Mersenne exponent
    /// (43,112,609) throws <see cref="ArgumentOutOfRangeException"/>.
    /// </summary>
    [Fact]
    public void SecurityLevel_Set_AboveMaximum_ThrowsArgumentOutOfRangeException()
    {
        // Arrange
        using var securityLevelManager = new SecurityLevelManager<BigInteger>();
        const int initialSecurityLevel = 50000000;

        // Act & Assert
        var exception = Assert.Throws<ArgumentOutOfRangeException>(() => 
            securityLevelManager.SecurityLevel = initialSecurityLevel);
        Assert.Equal("value", exception.ParamName);
        Assert.Equal(initialSecurityLevel, exception.ActualValue);
    }

    /// <summary>
    /// Tests that assigning a non-Mersenne exponent (e.g. 20) auto-upgrades to the next
    /// valid Mersenne exponent (31), driven by the injected provider's
    /// <c>GetNextMersennePrimeExponent</c> contract.
    /// </summary>
    [Fact]
    public void SecurityLevel_Set_WithNonMersennePrimeExponent_AdjustsToNextValidSecurityLevel()
    {
        // Arrange
        var mockProvider = new Mock<IMersennePrimeProvider>();
        const int initialSecurityLevel = 20;
        const int expectedAdjustedLevel = 31;
        mockProvider.Setup(p => p.MinMersennePrimeExponent).Returns(13);
        mockProvider.Setup(p => p.MaxMersennePrimeExponent).Returns(127);
        mockProvider.Setup(p => p.IsValidMersennePrimeExponent(initialSecurityLevel)).Returns(false);
        mockProvider.Setup(p => p.GetNextMersennePrimeExponent(initialSecurityLevel)).Returns(31);
        mockProvider.Setup(p => p.IsValidMersennePrimeExponent(expectedAdjustedLevel)).Returns(true);

        using var securityLevelManager = new SecurityLevelManager<BigInteger>(mockProvider.Object);

        // Act
        securityLevelManager.SecurityLevel = initialSecurityLevel;

        // Assert
        Assert.Equal(expectedAdjustedLevel, securityLevelManager.SecurityLevel);
    }

    /// <summary>
    /// Tests that <see cref="SecurityLevelManager{TNumber}.MersennePrime"/> evaluates to
    /// <c>2^p − 1</c> for the configured security level <c>p</c>.
    /// </summary>
    [Fact]
    public void MersennePrime_AfterSettingSecurityLevel_IsCalculatedCorrectly()
    {
        // Arrange
        using var securityLevelManager = new SecurityLevelManager<BigInteger>();
        const int initialSecurityLevel = 17;
        
        // Act
        securityLevelManager.SecurityLevel = initialSecurityLevel;

        // Assert
        Assert.Equal(BigInteger.Pow(2, initialSecurityLevel) - 1, securityLevelManager.MersennePrime.Value);
    }

    /// <summary>
    /// Tests that <see cref="SecurityLevelManager{TNumber}.MersennePrime"/> is non-null
    /// after a security-level assignment — the property does not silently leave a stale or
    /// unset Calculator instance behind.
    /// </summary>
    [Fact]
    public void MersennePrime_AfterSettingSecurityLevel_IsNotNull()
    {
        // Arrange
        using var securityLevelManager = new SecurityLevelManager<BigInteger>();

        // Act
        securityLevelManager.SecurityLevel = 31;

        // Assert
        Assert.NotNull(securityLevelManager.MersennePrime);
    }

    /// <summary>
    /// Tests that <see cref="SecurityLevelManager{TNumber}.AdjustSecurityLevel"/> with a
    /// <c>maximumY</c> that already fits inside the minimum Mersenne prime is a no-op — no
    /// downgrade below the floor, no upgrade.
    /// </summary>
    [Fact]
    public void AdjustSecurityLevel_WhenMaximumYCorrespondsToMinimumMersennePrimeExponent_DoesNothing()
    {
        // Arrange
        using var securityLevelManager = new SecurityLevelManager<BigInteger>();
        var initialSecurityLevel = securityLevelManager.SecurityLevel;
        byte[] byteArray = [0xFF, 0x0F];
        using var maximumY = new BigIntCalculator(byteArray, byteArray.Length);

        // Act
        securityLevelManager.AdjustSecurityLevel(maximumY);

        // Assert
        Assert.Equal(initialSecurityLevel, securityLevelManager.SecurityLevel);
    }

    /// <summary>
    /// Tests that <see cref="SecurityLevelManager{TNumber}.AdjustSecurityLevel"/> upgrades
    /// the security level when <c>maximumY</c> exceeds the current Mersenne prime — so the
    /// secret can be represented without overflow under the new prime.
    /// </summary>
    [Fact]
    public void AdjustSecurityLevel_WhenMaximumYIsLargerThanInitialSecurityLevel_IncreasesSecurityLevel()
    {
        // Arrange
        using var securityLevelManager = new SecurityLevelManager<BigInteger>();
        var initialSecurityLevel = securityLevelManager.SecurityLevel;
        byte[] byteArray = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x0F];
        using var maximumY = new BigIntCalculator(byteArray, byteArray.Length);

        // Act
        securityLevelManager.AdjustSecurityLevel(maximumY);

        // Assert
        Assert.True(securityLevelManager.SecurityLevel > initialSecurityLevel);
    }

    /// <summary>
    /// Tests that <see cref="SecurityLevelManager{TNumber}.AdjustSecurityLevel"/> can also
    /// downgrade the security level when <c>maximumY</c> fits inside a smaller prime —
    /// minimises the share size while still containing the value.
    /// </summary>
    [Fact]
    public void AdjustSecurityLevel_WhenMaximumYIsLowerThanInitialSecurityLevel_DecreasesSecurityLevel()
    {
        // Arrange
        using var securityLevelManager = new SecurityLevelManager<BigInteger>();
        const int initialSecurityLevel = 31;
        securityLevelManager.SecurityLevel = initialSecurityLevel;
        byte[] byteArray = [0x0F, 0x0F];
        using var maximumY = new BigIntCalculator(byteArray, byteArray.Length);

        // Act
        securityLevelManager.AdjustSecurityLevel(maximumY);

        // Assert
        Assert.True(securityLevelManager.SecurityLevel < initialSecurityLevel);
    }

    /// <summary>
    /// Tests that assigning any of the tabulated Mersenne exponents to
    /// <see cref="SecurityLevelManager{TNumber}.SecurityLevel"/> stores the value verbatim
    /// — no spurious upgrade is triggered for already-valid inputs.
    /// </summary>
    /// <param name="exponent">A known-valid Mersenne exponent.</param>
    [Theory]
    [InlineData(13)]
    [InlineData(17)]
    [InlineData(19)]
    [InlineData(31)]
    [InlineData(61)]
    [InlineData(89)]
    [InlineData(107)]
    [InlineData(127)]
    [InlineData(521)]
    [InlineData(607)]
    public void SecurityLevel_Set_WithValidMersennePrimeExponents_SetsCorrectly(int exponent)
    {
        // Arrange
        using var securityLevelManager = new SecurityLevelManager<BigInteger>();

        // Act
        securityLevelManager.SecurityLevel = exponent;

        // Assert
        Assert.Equal(exponent, securityLevelManager.SecurityLevel);
    }

    /// <summary>
    /// Tests that successive <see cref="SecurityLevelManager{TNumber}.SecurityLevel"/>
    /// assignments refresh <see cref="SecurityLevelManager{TNumber}.MersennePrime"/> to
    /// the matching new <c>2^p − 1</c> each time — no stale prime sticks around.
    /// </summary>
    [Fact]
    public void SecurityLevel_MultipleSet_UpdatesMersennePrimeEachTime()
    {
        // Arrange
        using var securityLevelManager = new SecurityLevelManager<BigInteger>();

        // Act & Assert
        securityLevelManager.SecurityLevel = 13;
        var firstPrime = securityLevelManager.MersennePrime.Value;

        securityLevelManager.SecurityLevel = 17;
        var secondPrime = securityLevelManager.MersennePrime.Value;

        Assert.NotEqual(firstPrime, secondPrime);
        Assert.Equal(BigInteger.Pow(2, 13) - 1, firstPrime);
        Assert.Equal(BigInteger.Pow(2, 17) - 1, secondPrime);
    }

    /// <summary>
    /// Tests that <see cref="SecurityLevelManager{TNumber}.SecurityLevel"/>'s getter returns
    /// the most recently assigned value.
    /// </summary>
    [Fact]
    public void SecurityLevel_Get_ReturnsCurrentSecurityLevel()
    {
        // Arrange
        using var securityLevelManager = new SecurityLevelManager<BigInteger>();
        const int initialSecurityLevel = 31;
        securityLevelManager.SecurityLevel = initialSecurityLevel;

        // Act
        var securityLevel = securityLevelManager.SecurityLevel;

        // Assert
        Assert.Equal(initialSecurityLevel, securityLevel);
    }

    /// <summary>
    /// Tests that <see cref="SecurityLevelManager{TNumber}.MersennePrime"/>'s getter returns
    /// the Calculator wrapping <c>2^p − 1</c> for the current security level.
    /// </summary>
    [Fact]
    public void MersennePrime_Get_ReturnsCurrentMersennePrime()
    {
        // Arrange
        using var securityLevelManager = new SecurityLevelManager<BigInteger>();
        const int initialSecurityLevel = 31;
        securityLevelManager.SecurityLevel = initialSecurityLevel;

        // Act
        var mersennePrime = securityLevelManager.MersennePrime;

        // Assert
        Assert.NotNull(mersennePrime);
        Assert.Equal(BigInteger.Pow(2, initialSecurityLevel) - 1, mersennePrime.Value);
    }
}