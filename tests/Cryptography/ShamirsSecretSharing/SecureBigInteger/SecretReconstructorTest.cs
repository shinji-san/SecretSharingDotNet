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
using SecretSharingDotNet.Cryptography;
using SecretSharingDotNet.Cryptography.ShamirsSecretSharing;
using SecretSharingDotNet.Math;
using SecretSharingDotNet.Math.Numerics;
using System;
using Xunit;

public class SecretReconstructorTest
{
    private static SecretReconstructor<SecureBigInteger> CreateWithMock(Mock<ISecurityLevelManager<SecureBigInteger>> managerMock) =>
        new(new ExtendedEuclideanAlgorithm<SecureBigInteger>(), managerMock.Object);

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

    [Fact]
    public void SecurityLevel_Get_AfterDispose_ThrowsObjectDisposedException()
    {
        // Arrange
        var reconstructor = new SecretReconstructor<SecureBigInteger>(new ExtendedEuclideanAlgorithm<SecureBigInteger>());
        reconstructor.Dispose();

        // Act & Assert
        Assert.Throws<ObjectDisposedException>(() => _ = reconstructor.SecurityLevel);
    }

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

    [Fact]
    public void DivMod_AfterDispose_ThrowsObjectDisposedException()
    {
        // Arrange
        var reconstructor = new SecretReconstructor<SecureBigInteger>(new ExtendedEuclideanAlgorithm<SecureBigInteger>());
        using var d = (Calculator<SecureBigInteger>)(SecureBigInteger)3;
        using var n = (Calculator<SecureBigInteger>)(SecureBigInteger)5;
        using var p = Calculator<SecureBigInteger>.Two.Pow(13) - Calculator<SecureBigInteger>.One;
        reconstructor.Dispose();

        // Act & Assert
        Assert.Throws<ObjectDisposedException>(() => reconstructor.DivMod(n, d, p));
    }

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

    [Fact]
    public void Reconstruction_WithDuplicateShareIndices_ThrowsArgumentException()
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
        var ex = Assert.Throws<ArgumentException>(() => reconstructor.Reconstruction(shares));
        Assert.Equal("shares", ex.ParamName);
    }

    [Fact]
    public void Reconstruction_WithDistinctIndicesAndDuplicateValues_DoesNotThrowAtValidation()
    {
        // Arrange — two shares with distinct indices but identical values. Under
        // the old Share-structural Distinct() check this would still pass; under
        // the index-only check it must continue to pass. The reconstruction
        // itself may legitimately fail later (these shares aren't on a real
        // polynomial), but never with the share-distinctness ArgumentException.
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
        if (ex is ArgumentException ae)
        {
            Assert.NotEqual("shares", ae.ParamName);
        }
    }
}