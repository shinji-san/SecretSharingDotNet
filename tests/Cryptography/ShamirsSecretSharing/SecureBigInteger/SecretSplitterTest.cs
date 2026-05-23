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

/// <summary>
/// Tests for <see cref="SecretSplitter{TNumber}"/> on the <see cref="SecureBigInteger"/>
/// backend — disposal contract, share-count guards, and the LE share-index encoding
/// helper. Mirror of the BigInteger-side test class.
/// </summary>
public class SecretSplitterTest
{
    /// <summary>
    /// Tests that disposing a <see cref="SecretSplitter{TNumber}"/> built around a
    /// caller-supplied <see cref="ISecurityLevelManager{TNumber}"/> does NOT cascade dispose
    /// to the injected manager — ownership stays with the caller.
    /// </summary>
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

    /// <summary>
    /// Tests that calling <see cref="SecretSplitter{TNumber}.Dispose"/> repeatedly is
    /// idempotent — second and third calls do not throw.
    /// </summary>
    [Fact]
    public void Dispose_CalledMultipleTimes_IsIdempotent()
    {
        // Arrange
        var splitter = new SecretSplitter<SecureBigInteger>();

        // Act
        var ex = Record.Exception(() =>
        {
            splitter.Dispose();
            splitter.Dispose();
            splitter.Dispose();
        });

        // Assert
        Assert.Null(ex);
    }

    /// <summary>
    /// Tests that reading <see cref="SecretSplitter{TNumber}.SecurityLevel"/> after
    /// disposal throws <see cref="ObjectDisposedException"/>.
    /// </summary>
    [Fact]
    public void SecurityLevel_Get_AfterDispose_ThrowsObjectDisposedException()
    {
        // Arrange
        var splitter = new SecretSplitter<SecureBigInteger>();
        splitter.Dispose();

        // Act & Assert
        Assert.Throws<ObjectDisposedException>(() => _ = splitter.SecurityLevel);
    }

    /// <summary>
    /// Tests that writing <see cref="SecretSplitter{TNumber}.SecurityLevel"/> after
    /// disposal throws <see cref="ObjectDisposedException"/>.
    /// </summary>
    [Fact]
    public void SecurityLevel_Set_AfterDispose_ThrowsObjectDisposedException()
    {
        // Arrange
        var splitter = new SecretSplitter<SecureBigInteger>();
        splitter.Dispose();

        // Act & Assert
        Assert.Throws<ObjectDisposedException>(() => splitter.SecurityLevel = 31);
    }

    /// <summary>
    /// Tests that the random-secret <see cref="SecretSplitter{TNumber}.MakeShares(int, int, int, out Secret{TNumber})"/>
    /// overload rejects calls after disposal with <see cref="ObjectDisposedException"/>.
    /// </summary>
    [Fact]
    public void MakeShares_RandomSecret_AfterDispose_ThrowsObjectDisposedException()
    {
        // Arrange
        var splitter = new SecretSplitter<SecureBigInteger>();
        splitter.Dispose();

        // Act & Assert
        Assert.Throws<ObjectDisposedException>(() => splitter.MakeShares(2, 3, 13, out _));
    }

    /// <summary>
    /// Regression for PR #296 review comment <c>r3291559151</c>: when
    /// <see cref="SecretSplitter{TNumber}.MakeShares(int, int, int, out Secret{TNumber})"/>
    /// throws after the random <see cref="Secret{TNumber}"/> has already been allocated, the
    /// pinned bytes must be wiped internally and the out slot reset to <see langword="default"/>.
    /// Callers fielding the exception cannot reliably reach an out parameter from a failed
    /// call, so leaving the allocated secret in place would leak pinned memory.
    /// </summary>
    [Fact]
    public void MakeShares_RandomSecret_ThrowingAfterAllocation_ResetsOutToDefault()
    {
        // Arrange — one above the implementation cap so CreateShares throws AFTER
        // MakeShares has already allocated the random Secret via CreateRandom. The
        // implementation-cap check (M3) is evaluated before the prime guard (H3), so
        // it fires deterministically at securityLevel = 13.
        using var splitter = new SecretSplitter<SecureBigInteger>();
        Secret<SecureBigInteger> generatedSecret = default;

        // Act
        ArgumentOutOfRangeException caught = null;
        try
        {
            splitter.MakeShares(
                2,
                SecretSplitter<SecureBigInteger>.MaxAllowedNumberOfShares + 1,
                13,
                out generatedSecret);
        }
        catch (ArgumentOutOfRangeException ex)
        {
            caught = ex;
        }

        // Assert
        Assert.NotNull(caught);
        Assert.Equal("numberOfShares", caught.ParamName);
        Assert.Equal(default, generatedSecret);
    }

    /// <summary>
    /// Tests that the <c>(min, n, secret, securityLevel)</c>
    /// <see cref="SecretSplitter{TNumber}.MakeShares(int, int, Secret{TNumber}, int)"/>
    /// overload rejects calls after disposal with <see cref="ObjectDisposedException"/>.
    /// </summary>
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

    /// <summary>
    /// Tests that the <c>(min, n, secret)</c>
    /// <see cref="SecretSplitter{TNumber}.MakeShares(int, int, Secret{TNumber})"/>
    /// overload rejects calls after disposal with <see cref="ObjectDisposedException"/>.
    /// </summary>
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

    /// <summary>
    /// Tests that the <c>using</c> pattern over a default-constructed
    /// <see cref="SecretSplitter{TNumber}"/> (which internally owns its security-level
    /// manager) completes without exception.
    /// </summary>
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

    /// <summary>
    /// Tests the H3 prime guard: <see cref="SecretSplitter{TNumber}.MakeShares(int, int, Secret{TNumber})"/>
    /// rejects a share count <c>≥ M_p</c> with <see cref="ArgumentOutOfRangeException"/>
    /// before share indices collapse modulo the prime in any subsequent reconstruction.
    /// </summary>
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

    /// <summary>
    /// Tests the M3 implementation cap: even when the auto-upgraded prime is large enough
    /// that the H3 guard does not fire, <see cref="SecretSplitter{TNumber}.MakeShares(int, int, Secret{TNumber})"/>
    /// still rejects a share count above
    /// <c>SecretSplitter&lt;TNumber&gt;.MaxAllowedNumberOfShares</c> with
    /// <see cref="ArgumentOutOfRangeException"/>.
    /// </summary>
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

    /// <summary>
    /// Tests the internal <c>Int32ToLittleEndianBytes</c> helper that drives share-index
    /// encoding — produces a canonical 4-byte little-endian sequence regardless of host
    /// endianness. The helper is TNumber-independent; the
    /// <see cref="SecureBigInteger"/>-bound instantiation is kept as a mirror of the
    /// BigInteger-side test for parity with the rest of the hierarchy.
    /// </summary>
    /// <param name="value">The <see cref="int"/> value to encode.</param>
    /// <param name="expected">The expected 4-byte LE encoding.</param>
    [Theory]
    [InlineData(0,             new byte[] { 0x00, 0x00, 0x00, 0x00 })]
    [InlineData(1,             new byte[] { 0x01, 0x00, 0x00, 0x00 })]
    [InlineData(5,             new byte[] { 0x05, 0x00, 0x00, 0x00 })]
    [InlineData(255,           new byte[] { 0xFF, 0x00, 0x00, 0x00 })]
    [InlineData(256,           new byte[] { 0x00, 0x01, 0x00, 0x00 })]
    [InlineData(0x12345678,    new byte[] { 0x78, 0x56, 0x34, 0x12 })]
    [InlineData(int.MaxValue,  new byte[] { 0xFF, 0xFF, 0xFF, 0x7F })]
    public void Int32ToLittleEndianBytes_ProducesCanonicalLittleEndianEncoding(int value, byte[] expected)
    {
        // Act — the helper is TNumber-independent, so the SecureBigInteger
        // instantiation returns the same bytes as the BigInteger one. Mirror
        // is for parity with the rest of the test hierarchy.
        byte[] actual = SecretSplitter<SecureBigInteger>.Int32ToLittleEndianBytes(value);

        // Assert
        Assert.Equal(expected, actual);
    }

    /// <summary>
    /// Tests that <see cref="SecretSplitter{TNumber}.MakeShares(int, int, Secret{TNumber})"/>
    /// assigns share x-coordinates <c>1, 2, ..., n</c> in order on the
    /// <see cref="SecureBigInteger"/> backend — end-to-end counterpart to the
    /// <c>Int32ToLittleEndianBytes</c> theory.
    /// </summary>
    [Fact]
    public void MakeShares_AssignsShareIndices_AsConsecutivePositiveIntegers()
    {
        // Arrange — Secret/security-level combination is incidental; the test
        // only inspects the x-coordinates assigned by the splitter.
        using var splitter = new SecretSplitter<SecureBigInteger>();
        using var secret = (Secret<SecureBigInteger>)(SecureBigInteger)42;

        // Act — 5 shares, threshold 3.
        using var shares = splitter.MakeShares(3, 5, secret);

        // Assert — x-coordinates are 1, 2, 3, 4, 5 in order. On a big-endian
        // host with platform-endian encoding they would be 0x01000000 etc.
        // s.Index is a Calculator<SecureBigInteger>; its .Value (implicit cast)
        // is a reference into the Share's owned storage — do not dispose it.
        int expectedIndex = 1;
        foreach (var s in shares)
        {
            using var expected = new SecureBigInteger(expectedIndex);
            var actual = (SecureBigInteger)s.Index;
            Assert.Equal(expected, actual);
            expectedIndex++;
        }

        Assert.Equal(6, expectedIndex);
    }
}