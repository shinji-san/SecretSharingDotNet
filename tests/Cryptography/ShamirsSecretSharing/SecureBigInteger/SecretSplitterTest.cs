// ----------------------------------------------------------------------------
// <copyright file="SecretSplitterTest.cs" company="Private">
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
using SecretSharingDotNet.Math.Numerics;
using System;
using Xunit;

public class SecretSplitterTest
{
    [Fact]
    public void Dispose_WithInjectedManager_DoesNotDisposeIt()
    {
        // Arrange
        var managerMock = new Mock<ISecurityLevelManager<SecureBigInteger>>();
        var splitter = new SecretSplitter<SecureBigInteger>(managerMock.Object);

        // Act — caller-supplied manager: must NOT be disposed by splitter.
        splitter.Dispose();
        splitter.Dispose();
        splitter.Dispose();

        // Assert
        managerMock.Verify(m => m.Dispose(), Times.Never);
    }

    [Fact]
    public void Dispose_CalledMultipleTimes_IsIdempotent()
    {
        // Arrange
        var splitter = new SecretSplitter<SecureBigInteger>();

        // Act & Assert — must not throw on repeated dispose.
        splitter.Dispose();
        splitter.Dispose();
        splitter.Dispose();
    }

    [Fact]
    public void SecurityLevel_Get_AfterDispose_ThrowsObjectDisposedException()
    {
        // Arrange
        var splitter = new SecretSplitter<SecureBigInteger>();
        splitter.Dispose();

        // Act & Assert
        Assert.Throws<ObjectDisposedException>(() => _ = splitter.SecurityLevel);
    }

    [Fact]
    public void SecurityLevel_Set_AfterDispose_ThrowsObjectDisposedException()
    {
        // Arrange
        var splitter = new SecretSplitter<SecureBigInteger>();
        splitter.Dispose();

        // Act & Assert
        Assert.Throws<ObjectDisposedException>(() => splitter.SecurityLevel = 31);
    }

    [Fact]
    public void MakeShares_RandomSecret_AfterDispose_ThrowsObjectDisposedException()
    {
        // Arrange
        var splitter = new SecretSplitter<SecureBigInteger>();
        splitter.Dispose();

        // Act & Assert
        Assert.Throws<ObjectDisposedException>(() => splitter.MakeShares(2, 3, 13, out _));
    }

    [Fact]
    public void MakeShares_WithSecretAndSecurityLevel_AfterDispose_ThrowsObjectDisposedException()
    {
        // Arrange
        var splitter = new SecretSplitter<SecureBigInteger>();
        using var secret = (Secret<SecureBigInteger>)(SecureBigInteger)42;
        splitter.Dispose();

        // Act & Assert
        Assert.Throws<ObjectDisposedException>(() => splitter.MakeShares(2, 3, secret, 13));
    }

    [Fact]
    public void MakeShares_WithSecret_AfterDispose_ThrowsObjectDisposedException()
    {
        // Arrange
        var splitter = new SecretSplitter<SecureBigInteger>();
        using var secret = (Secret<SecureBigInteger>)(SecureBigInteger)42;
        splitter.Dispose();

        // Act & Assert
        Assert.Throws<ObjectDisposedException>(() => splitter.MakeShares(2, 3, secret));
    }

    [Fact]
    public void UsingPattern_WithOwnedManager_DoesNotThrow()
    {
        // Arrange & Act — owned-manager round-trip via using.
        using (var splitter = new SecretSplitter<SecureBigInteger>())
        {
            Assert.True(splitter.SecurityLevel > 0);
        }

        // Assert — implicit: no exception escaped.
    }

    [Fact]
    public void MakeShares_NumberOfSharesExceedsMersennePrime_ThrowsArgumentOutOfRangeException()
    {
        // Arrange — small numeric secret. After auto-upgrade the splitter ends up at
        // SecurityLevel = 17 (next Mersenne exponent ≥ 16, since SecretByteSize = 2
        // including the termination byte), so prime = 2^17 - 1 = 131071.
        // numberOfShares = 131071 must be rejected: indices 1..131071 collapse to a
        // collision modulo prime in any subsequent reconstruction.
        using var splitter = new SecretSplitter<SecureBigInteger>();
        using var secret = (Secret<SecureBigInteger>)(SecureBigInteger)42;

        // Act & Assert
        var ex = Assert.Throws<ArgumentOutOfRangeException>(
            () => splitter.MakeShares(2, 131071, secret));
        Assert.Equal("numberOfShares", ex.ParamName);
    }

    [Fact]
    public void MakeShares_NumberOfSharesExceedsImplementationCap_ThrowsArgumentOutOfRangeException()
    {
        // Arrange — pick a secret large enough that the auto-upgraded prime is
        // astronomically larger than the implementation cap, so the H3 prime guard
        // cannot fire first; the implementation cap (M3) must still reject the request.
        using var splitter = new SecretSplitter<SecureBigInteger>();
        using var secret = new Secret<SecureBigInteger>(new byte[64]);

        // Act & Assert — exactly one above the cap.
        var ex = Assert.Throws<ArgumentOutOfRangeException>(
            () => splitter.MakeShares(2, SecretSplitter<SecureBigInteger>.MaxAllowedNumberOfShares + 1, secret));
        Assert.Equal("numberOfShares", ex.ParamName);
    }
}