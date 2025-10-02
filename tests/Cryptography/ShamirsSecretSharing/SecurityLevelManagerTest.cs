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


using SecretSharingDotNet.Cryptography.ShamirsSecretSharing;
using SecretSharingDotNet.Math;
using System;
using System.Numerics;
using Xunit;
using Moq;

namespace SecretSharingDotNetTest.Cryptography.ShamirsSecretSharing;

public class SecurityLevelManagerTest
{
    [Fact]
    public void Constructor_WithoutParameter_InitializesWithDefaultMersennePrimeProvider()
    {
        // Arrange & Act
        var securityLevelManager = new SecurityLevelManager<BigInteger>();

        // Assert
        Assert.NotNull(securityLevelManager);
        Assert.Equal(MersennePrimeProvider.Instance.MinMersennePrimeExponent, securityLevelManager.SecurityLevel);
        Assert.NotNull(securityLevelManager.MersennePrime);
    }

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
        var securityLevelManager = new SecurityLevelManager<BigInteger>(mersennePrimeProviderMock.Object);

        // Assert
        Assert.NotNull(securityLevelManager);
        Assert.Equal(expectedSecurityLevel, securityLevelManager.SecurityLevel);
    }

    [Fact]
    public void Constructor_WithNullProvider_ThrowsArgumentNullException()
    {
        // Arrange, Act & Assert
        var exception = Assert.Throws<ArgumentNullException>(() => new SecurityLevelManager<BigInteger>(null!));
        Assert.Equal("mersennePrimeProvider", exception.ParamName);
    }

    [Fact]
    public void SecurityLevel_Set_WithMersennePrimeExponent_SetsSecurityLevelCorrectly()
    {
        // Arrange
        var securityLevelManager = new SecurityLevelManager<BigInteger>();
        const int initialSecurityLevel = 17;

        // Act
        securityLevelManager.SecurityLevel = initialSecurityLevel;

        // Assert
        Assert.Equal(initialSecurityLevel, securityLevelManager.SecurityLevel);
    }

    [Fact]
    public void SecurityLevel_Set_BelowMinimum_ThrowsArgumentOutOfRangeException()
    {
        // Arrange
        var securityLevelManager = new SecurityLevelManager<BigInteger>();
        const int initialSecurityLevel = 10;

        // Act & Assert
        var exception = Assert.Throws<ArgumentOutOfRangeException>(() => 
            securityLevelManager.SecurityLevel = initialSecurityLevel);
        Assert.Equal("value", exception.ParamName);
        Assert.Equal(initialSecurityLevel, exception.ActualValue);
    }

    [Fact]
    public void SecurityLevel_Set_AboveMaximum_ThrowsArgumentOutOfRangeException()
    {
        // Arrange
        var securityLevelManager = new SecurityLevelManager<BigInteger>();
        const int initialSecurityLevel = 50000000;

        // Act & Assert
        var exception = Assert.Throws<ArgumentOutOfRangeException>(() => 
            securityLevelManager.SecurityLevel = initialSecurityLevel);
        Assert.Equal("value", exception.ParamName);
        Assert.Equal(initialSecurityLevel, exception.ActualValue);
    }

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

        var securityLevelManager = new SecurityLevelManager<BigInteger>(mockProvider.Object);

        // Act
        securityLevelManager.SecurityLevel = initialSecurityLevel;

        // Assert
        Assert.Equal(expectedAdjustedLevel, securityLevelManager.SecurityLevel);
    }

    [Fact]
    public void MersennePrime_AfterSettingSecurityLevel_IsCalculatedCorrectly()
    {
        // Arrange
        var securityLevelManager = new SecurityLevelManager<BigInteger>();
        const int initialSecurityLevel = 17;
        
        // Act
        securityLevelManager.SecurityLevel = initialSecurityLevel;

        // Assert
        Assert.Equal(BigInteger.Pow(2, initialSecurityLevel) - 1, securityLevelManager.MersennePrime.Value);
    }

    [Fact]
    public void MersennePrime_AfterSettingSecurityLevel_IsNotNull()
    {
        // Arrange
        var securityLevelManager = new SecurityLevelManager<BigInteger>();

        // Act
        securityLevelManager.SecurityLevel = 31;

        // Assert
        Assert.NotNull(securityLevelManager.MersennePrime);
    }

    [Fact]
    public void AdjustSecurityLevel_WhenMaximumYCorrespondsToMinimumMersennePrimeExponent_DoesNothing()
    {
        // Arrange
        var securityLevelManager = new SecurityLevelManager<BigInteger>();
        var initialSecurityLevel = securityLevelManager.SecurityLevel;
        var maximumY = new BigIntCalculator([0xFF, 0x0F]);

        // Act
        securityLevelManager.AdjustSecurityLevel(maximumY);

        // Assert
        Assert.Equal(initialSecurityLevel, securityLevelManager.SecurityLevel);
    }

    [Fact]
    public void AdjustSecurityLevel_WhenMaximumYIsLargerThanInitialSecurityLevel_IncreasesSecurityLevel()
    {
        // Arrange
        var securityLevelManager = new SecurityLevelManager<BigInteger>();
        var initialSecurityLevel = securityLevelManager.SecurityLevel;
        var maximumY = new BigIntCalculator([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x0F]);

        // Act
        securityLevelManager.AdjustSecurityLevel(maximumY);

        // Assert
        Assert.True(securityLevelManager.SecurityLevel > initialSecurityLevel);
    }

    [Fact]
    public void AdjustSecurityLevel_WhenMaximumYIsLowerThanInitialSecurityLevel_DecreasesSecurityLevel()
    {
        // Arrange
        var securityLevelManager = new SecurityLevelManager<BigInteger>();
        const int initialSecurityLevel = 31;
        securityLevelManager.SecurityLevel = initialSecurityLevel;
        var maximumY = new BigIntCalculator([0x0F, 0x0F]);

        // Act
        securityLevelManager.AdjustSecurityLevel(maximumY);

        // Assert
        Assert.True(securityLevelManager.SecurityLevel < initialSecurityLevel);
    }

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
        var securityLevelManager = new SecurityLevelManager<BigInteger>();

        // Act
        securityLevelManager.SecurityLevel = exponent;

        // Assert
        Assert.Equal(exponent, securityLevelManager.SecurityLevel);
    }

    [Fact]
    public void SecurityLevel_MultipleSet_UpdatesMersennePrimeEachTime()
    {
        // Arrange
        var securityLevelManager = new SecurityLevelManager<BigInteger>();

        // Act & Assert
        securityLevelManager.SecurityLevel = 13;
        var firstPrime = securityLevelManager.MersennePrime.Value;

        securityLevelManager.SecurityLevel = 17;
        var secondPrime = securityLevelManager.MersennePrime.Value;

        Assert.NotEqual(firstPrime, secondPrime);
        Assert.Equal(BigInteger.Pow(2, 13) - 1, firstPrime);
        Assert.Equal(BigInteger.Pow(2, 17) - 1, secondPrime);
    }

    [Fact]
    public void SecurityLevel_Get_ReturnsCurrentSecurityLevel()
    {
        // Arrange
        var securityLevelManager = new SecurityLevelManager<BigInteger>();
        const int initialSecurityLevel = 31;
        securityLevelManager.SecurityLevel = initialSecurityLevel;

        // Act
        var securityLevel = securityLevelManager.SecurityLevel;

        // Assert
        Assert.Equal(initialSecurityLevel, securityLevel);
    }

    [Fact]
    public void MersennePrime_Get_ReturnsCurrentMersennePrime()
    {
        // Arrange
        var securityLevelManager = new SecurityLevelManager<BigInteger>();
        const int initialSecurityLevel = 31;
        securityLevelManager.SecurityLevel = initialSecurityLevel;

        // Act
        var mersennePrime = securityLevelManager.MersennePrime;

        // Assert
        Assert.NotNull(mersennePrime);
        Assert.Equal(BigInteger.Pow(2, initialSecurityLevel) - 1, mersennePrime.Value);
    }
}