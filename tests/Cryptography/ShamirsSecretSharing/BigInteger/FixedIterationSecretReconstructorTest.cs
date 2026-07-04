// ----------------------------------------------------------------------------
// <copyright file="FixedIterationSecretReconstructorTest.cs" company="Private">
// Copyright (c) 2026 All Rights Reserved
// </copyright>
// <author>Sebastian Walther</author>
// <date>07/04/2026 12:00:00 PM</date>
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
using SecretSharingDotNet.Cryptography;
using SecretSharingDotNet.Cryptography.SecureInput;
using SecretSharingDotNet.Cryptography.ShamirsSecretSharing;
using SecretSharingDotNet.Math;
using System.Linq;
using System.Numerics;
using Xunit;

/// <summary>
/// Tests for <see cref="FixedIterationSecretReconstructor{TNumber}"/> on the
/// <see cref="BigInteger"/> backend. Mirror of the SecureBigInteger-side test class, kept for
/// symmetry across the two backend hierarchies. The fixed-iteration guarantee (an
/// operand-independent GCD iteration count) is backend-independent and holds here too; what
/// <see cref="BigInteger"/> lacks is per-operation constant-time arithmetic, which this type
/// does not claim. These tests assert the wiring, the round-trip correctness, and the type /
/// marker relationships, not any timing property.
/// </summary>
public class FixedIterationSecretReconstructorTest
{
    /// <summary>
    /// Tests that the parameterless constructor — which wires the recommended fixed-iteration
    /// default (<see cref="MersenneSafeGcdAlgorithm{TNumber}"/>) — reconstructs the original
    /// secret from a K-of-N subset of shares.
    /// </summary>
    [Fact]
    public void Reconstruction_WithParameterlessCtor_RestoresSecret()
    {
        // Arrange
        using var splitter = new SecretSplitter<BigInteger>();
        using var reconstructor = new FixedIterationSecretReconstructor<BigInteger>();
        using var pinnedText = "fixed-iteration round-trip".ToPinnedSecure();
        using var secret = Secret<BigInteger>.FromText(pinnedText);

        // Act
        using var shares = splitter.MakeShares(3, 7, secret);
        var subset = shares.Where(share => share.IsIndexOdd).ToArray();
        using var recoveredSecret = reconstructor.Reconstruction(subset);

        // Assert
        Assert.Equal(secret, recoveredSecret);
    }

    /// <summary>
    /// Tests that the constructor taking an explicit fixed-iteration strategy reconstructs the
    /// original secret from a K-of-N subset of shares.
    /// </summary>
    [Fact]
    public void Reconstruction_WithExplicitConstantTimeGcd_RestoresSecret()
    {
        // Arrange
        using var splitter = new SecretSplitter<BigInteger>();
        using var reconstructor = new FixedIterationSecretReconstructor<BigInteger>(
            new MersenneSafeGcdAlgorithm<BigInteger>());
        using var pinnedText = "fixed-iteration round-trip".ToPinnedSecure();
        using var secret = Secret<BigInteger>.FromText(pinnedText);

        // Act
        using var shares = splitter.MakeShares(3, 7, secret);
        var subset = shares.Where(share => share.IsIndexOdd).ToArray();
        using var recoveredSecret = reconstructor.Reconstruction(subset);

        // Assert
        Assert.Equal(secret, recoveredSecret);
    }

    /// <summary>
    /// Tests that disposing a <see cref="FixedIterationSecretReconstructor{TNumber}"/> built
    /// around a caller-supplied <see cref="ISecurityLevelManager{TNumber}"/> does NOT cascade
    /// dispose to the injected manager — ownership stays with the caller, matching the base
    /// reconstructor contract.
    /// </summary>
    [Fact]
    public void Dispose_WithInjectedManager_DoesNotDisposeIt()
    {
        // Arrange
        var managerMock = new Mock<ISecurityLevelManager<BigInteger>>();
        var reconstructor = new FixedIterationSecretReconstructor<BigInteger>(
            new MersenneSafeGcdAlgorithm<BigInteger>(),
            managerMock.Object);

        // Act — caller-supplied manager: must NOT be disposed by the reconstructor.
        reconstructor.Dispose();
        reconstructor.Dispose();
        reconstructor.Dispose();

        // Assert
        managerMock.Verify(m => m.Dispose(), Times.Never);
    }

    /// <summary>
    /// Tests that <see cref="FixedIterationSecretReconstructor{TNumber}"/> is a
    /// <see cref="SecretReconstructor{TNumber}"/> and an <see cref="IReconstructionUseCase{TNumber}"/>,
    /// so it is a drop-in wherever the base reconstructor or the use-case interface is expected
    /// (including dependency-injection registration).
    /// </summary>
    [Fact]
    public void Instance_IsAssignableToBaseReconstructorAndUseCase()
    {
        // Arrange
        using var reconstructor = new FixedIterationSecretReconstructor<BigInteger>();

        // Act & Assert
        Assert.IsAssignableFrom<SecretReconstructor<BigInteger>>(reconstructor);
        Assert.IsAssignableFrom<IReconstructionUseCase<BigInteger>>(reconstructor);
    }

    /// <summary>
    /// Tests that <see cref="MersenneSafeGcdAlgorithm{TNumber}"/> is a member of the
    /// fixed-iteration GCD family (<see cref="IFixedIterationExtendedGcdAlgorithm{TNumber}"/>) —
    /// the property that lets it be passed to the fixed-iteration reconstructor while a
    /// variable-time strategy cannot.
    /// </summary>
    [Fact]
    public void MersenneSafeGcdAlgorithm_IsMemberOfFixedIterationGcdFamily()
    {
        // Arrange
        var algorithm = new MersenneSafeGcdAlgorithm<BigInteger>();

        // Act & Assert
        Assert.IsAssignableFrom<IFixedIterationExtendedGcdAlgorithm<BigInteger>>(algorithm);
    }
}
