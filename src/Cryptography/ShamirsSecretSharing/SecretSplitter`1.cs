// ----------------------------------------------------------------------------
// <copyright file="SecretSplitter`1.cs" company="Private">
// Copyright (c) 2025 All Rights Reserved
// </copyright>
// <author>Sebastian Walther</author>
// <date>10/03/2025 01:07:11 AM</date>
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

namespace SecretSharingDotNet.Cryptography.ShamirsSecretSharing;

using Extension;
using Math;
using SecureArray;
using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Threading;

/// <summary>
/// The <see cref="SecretSplitter{TNumber}"/> class implements Shamir's Secret Sharing algorithm to divide a secret
/// into multiple shares such that a minimum number of shares can reconstruct the original secret.
/// This class supports generic number types and allows for configuring security levels.
/// </summary>
/// <typeparam name="TNumber">
/// The numeric type used to represent shares and secret values.
/// It must support arithmetic operations and be compatible with the Shamir's Secret Sharing implementation.
/// </typeparam>
public class SecretSplitter<TNumber> : IMakeSharesUseCase<TNumber>
{
    /// <summary>
    /// Hard upper bound on the maximum number of shares (<c>numberOfShares</c>) that
    /// <see cref="MakeShares(int, int, Secret{TNumber})"/> and its overloads accept.
    /// Any realistic Shamir-secret-sharing scheme uses values in the dozens; the cap is
    /// deliberately generous so it never gets in the way of legitimate use, while still
    /// protecting against pathological / hostile callers that would otherwise drive the
    /// share-generation loop into multi-day CPU time.
    /// </summary>
    public const int MaxAllowedNumberOfShares = 1_000_000;

    /// <summary>
    /// Represents the manager for configuring and retrieving the security level
    /// settings in the context of Shamir's Secret Sharing implementation.
    /// </summary>
    private readonly ISecurityLevelManager<TNumber> securityLevelManager;

    /// <summary>
    /// Indicates whether this instance owns <see cref="securityLevelManager"/> and is therefore
    /// responsible for disposing it. <see langword="true"/> when the manager was created internally
    /// by the parameterless constructor; <see langword="false"/> when it was supplied by the caller.
    /// </summary>
    private readonly bool ownsSecurityLevelManager;

    /// <summary>
    /// Disposal flag manipulated atomically via <see cref="Interlocked.Exchange(ref int, int)"/>:
    /// 0 = alive, 1 = disposed.
    /// </summary>
    private int disposed;

    /// <summary>
    /// Initializes a new instance of the <see cref="SecretSplitter{TNumber}"/> class using a default
    /// <see cref="SecurityLevelManager{TNumber}"/>. The created manager is owned by this instance
    /// and disposed together with it.
    /// </summary>
    public SecretSplitter()
    {
        this.securityLevelManager = new SecurityLevelManager<TNumber>();
        this.ownsSecurityLevelManager = true;
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="SecretSplitter{TNumber}"/> class with a
    /// caller-supplied <see cref="ISecurityLevelManager{TNumber}"/>. Ownership of the manager
    /// remains with the caller; this instance will not dispose it.
    /// </summary>
    /// <param name="securityLevelManager">Manages security level configuration</param>
    /// <exception cref="ArgumentNullException">
    /// The <paramref name="securityLevelManager"/> parameter is <see langword="null"/>.
    /// </exception>
    public SecretSplitter(ISecurityLevelManager<TNumber> securityLevelManager)
    {
        this.securityLevelManager = securityLevelManager ?? throw new ArgumentNullException(nameof(securityLevelManager));
        this.ownsSecurityLevelManager = false;
    }

    /// <summary>
    /// Finalizes an instance of the <see cref="SecretSplitter{TNumber}"/> class.
    /// </summary>
    ~SecretSplitter()
    {
        this.Dispose(false);
    }

    /// <summary>
    /// Gets or sets the security level (in bits) of the underlying
    /// <see cref="ISecurityLevelManager{TNumber}"/>.
    /// </summary>
    /// <remarks>
    /// Acts as a lower bound on the level used by <see cref="MakeShares(int, int, Secret{TNumber})"/>
    /// and its overloads: when the secret's bit length exceeds this value, the level is
    /// automatically raised to fit the secret; it is never lowered. Valid range is the Mersenne
    /// prime exponent range exposed by <see cref="ISecurityLevelManager{TNumber}"/>
    /// (typically 13 through 43,112,609).
    /// </remarks>
    /// <exception cref="ArgumentOutOfRangeException" accessor="set">
    /// The supplied value is below the minimum or above the maximum supported Mersenne prime exponent.
    /// </exception>
    /// <exception cref="ObjectDisposedException">This instance has been disposed.</exception>
    public int SecurityLevel
    {
        get
        {
            this.ThrowIfDisposed();
            return this.securityLevelManager.SecurityLevel;
        }
        set
        {
            this.ThrowIfDisposed();
            this.securityLevelManager.SecurityLevel = value;
        }
    }

    /// <summary>
    /// Generates a random shamir pool and returns the share points.
    /// The generated random secret is provided via the <paramref name="generatedSecret"/> out parameter.
    /// </summary>
    /// <param name="numberOfMinimumShares">Minimum number of shared secrets for reconstruction.</param>
    /// <param name="numberOfShares">Maximum number of shared secrets.</param>
    /// <param name="securityLevel">Security level (in number of bits). The minimum is 13.</param>
    /// <param name="generatedSecret">
    /// Output parameter receiving the generated random <see cref="Secret{TNumber}"/>. The caller
    /// takes ownership and is responsible for disposing it when no longer needed. If the method
    /// throws after the secret has been allocated, the pinned bytes are wiped internally and
    /// <paramref name="generatedSecret"/> is reset to <see langword="default"/>; callers do not
    /// need to dispose the out value on the exception path.
    /// </param>
    /// <returns>A <see cref="Shares{TNumber}"/> collection containing the generated shares.</returns>
    /// <exception cref="ArgumentOutOfRangeException">
    /// <paramref name="securityLevel"/> is lower than 13 or greater than 43,112,609;
    /// <paramref name="numberOfMinimumShares"/> is lower than 2 or greater than <paramref name="numberOfShares"/>;
    /// <paramref name="numberOfShares"/> is greater than the implementation cap
    /// <see cref="MaxAllowedNumberOfShares"/>;
    /// or <paramref name="numberOfShares"/> is greater than or equal to the current Mersenne prime
    /// defining the finite field.
    /// </exception>
    /// <exception cref="InvalidOperationException">
    /// The configured <see cref="ISecurityLevelManager{TNumber}"/> has no Mersenne prime
    /// initialised, or the configured <typeparamref name="TNumber"/> backend's
    /// <see cref="Calculator"/> factory rejected the random byte buffer.
    /// </exception>
    /// <exception cref="ObjectDisposedException">This instance has been disposed.</exception>
    public Shares<TNumber> MakeShares(int numberOfMinimumShares, int numberOfShares, int securityLevel, out Secret<TNumber> generatedSecret)
    {
        this.ThrowIfDisposed();
        try
        {
            this.SecurityLevel = securityLevel;
        }
        catch (ArgumentOutOfRangeException e)
        {
            throw new ArgumentOutOfRangeException(nameof(securityLevel), securityLevel, e.Message);
        }

        if (numberOfMinimumShares < 2)
        {
            throw new ArgumentOutOfRangeException(nameof(numberOfMinimumShares), numberOfMinimumShares, ErrorMessages.MinNumberOfSharesLowerThanTwo);
        }

        if (numberOfMinimumShares > numberOfShares)
        {
            throw new ArgumentOutOfRangeException(nameof(numberOfShares), numberOfShares, ErrorMessages.MaxSharesLowerThanMinShares);
        }

        if (this.securityLevelManager.MersennePrime == null)
        {
            throw new InvalidOperationException(ErrorMessages.SecurityLevelNotInitialized);
        }

        generatedSecret = Secret<TNumber>.CreateRandom(this.securityLevelManager.MersennePrime);
        Calculator<TNumber>[] polynomial = null;
        try
        {
            polynomial = this.CreatePolynomial(numberOfMinimumShares, generatedSecret.ToCoefficient);
            var shares = this.CreateShares(numberOfShares, polynomial);
            return new Shares<TNumber>(shares);
        }
        catch
        {
            // CreatePolynomial / CreateShares may throw (e.g. ArgumentOutOfRangeException when
            // numberOfShares exceeds MaxAllowedNumberOfShares or the Mersenne-prime bound). The
            // out parameter is already assigned to a freshly allocated pinned-memory secret;
            // callers fielding the exception cannot reliably dispose an out value from a failed
            // call, so wipe the bytes here and reset the slot to default before rethrowing.
            generatedSecret.Dispose();
            generatedSecret = default;
            throw;
        }
        finally
        {
            polynomial?.DisposeAll();
        }
    }

    /// <summary>
    /// Generates a shamir pool using the provided <paramref name="secret"/> and returns the share points.
    /// </summary>
    /// <param name="numberOfMinimumShares">Minimum number of shared secrets for reconstruction.</param>
    /// <param name="numberOfShares">Maximum number of shared secrets.</param>
    /// <param name="secret">The secret to split, as a <see cref="Secret{TNumber}"/>.</param>
    /// <param name="securityLevel">
    /// Lower bound for the security level (in number of bits). The minimum is 13. The
    /// effective security level may be raised above this value when <paramref name="secret"/>
    /// requires more bits than <paramref name="securityLevel"/> provides.
    /// </param>
    /// <returns>A <see cref="Shares{TNumber}"/> collection containing the generated shares.</returns>
    /// <remarks>
    /// This method may raise the <see cref="SecurityLevel"/> above <paramref name="securityLevel"/>
    /// to fit the <paramref name="secret"/>'s byte length; it never lowers it.
    /// </remarks>
    /// <exception cref="ArgumentOutOfRangeException">
    /// <paramref name="securityLevel"/> is lower than 13 or greater than 43,112,609;
    /// <paramref name="numberOfMinimumShares"/> is lower than 2 or greater than <paramref name="numberOfShares"/>;
    /// <paramref name="numberOfShares"/> is greater than the implementation cap
    /// <see cref="MaxAllowedNumberOfShares"/>;
    /// or <paramref name="numberOfShares"/> is greater than or equal to the current Mersenne prime
    /// defining the finite field.
    /// </exception>
    /// <exception cref="InvalidOperationException">
    /// The configured <typeparamref name="TNumber"/> backend's <see cref="Calculator"/>
    /// factory rejected the random byte buffer.
    /// </exception>
    /// <exception cref="ObjectDisposedException">
    /// This instance has been disposed, or <paramref name="secret"/> has already been disposed.
    /// </exception>
    public Shares<TNumber> MakeShares(int numberOfMinimumShares, int numberOfShares, Secret<TNumber> secret, int securityLevel)
    {
        this.ThrowIfDisposed();
        try
        {
            this.SecurityLevel = securityLevel;
        }
        catch (ArgumentOutOfRangeException e)
        {
            throw new ArgumentOutOfRangeException(nameof(securityLevel), securityLevel, e.Message);
        }

        return this.MakeShares(numberOfMinimumShares, numberOfShares, secret);
    }

    /// <summary>
    /// Generates a shamir pool using the provided <paramref name="secret"/> and returns the share points.
    /// </summary>
    /// <param name="numberOfMinimumShares">Minimum number of shared secrets for reconstruction.</param>
    /// <param name="numberOfShares">Maximum number of shared secrets.</param>
    /// <param name="secret">The secret to split, as a <see cref="Secret{TNumber}"/>.</param>
    /// <returns>A <see cref="Shares{TNumber}"/> collection containing the generated shares.</returns>
    /// <remarks>
    /// This method may raise the <see cref="SecurityLevel"/> based on <paramref name="secret"/>'s
    /// byte length; it never lowers it.
    /// </remarks>
    /// <exception cref="ArgumentOutOfRangeException">
    /// <paramref name="numberOfMinimumShares"/> is lower than 2 or greater than <paramref name="numberOfShares"/>;
    /// <paramref name="numberOfShares"/> is greater than the implementation cap
    /// <see cref="MaxAllowedNumberOfShares"/>;
    /// or <paramref name="numberOfShares"/> is greater than or equal to the current Mersenne prime
    /// defining the finite field.
    /// </exception>
    /// <exception cref="InvalidOperationException">
    /// The configured <typeparamref name="TNumber"/> backend's <see cref="Calculator"/>
    /// factory rejected the random byte buffer.
    /// </exception>
    /// <exception cref="ObjectDisposedException">
    /// This instance has been disposed, or <paramref name="secret"/> has already been disposed.
    /// </exception>
    public Shares<TNumber> MakeShares(int numberOfMinimumShares, int numberOfShares, Secret<TNumber> secret)
    {
        this.ThrowIfDisposed();
        if (numberOfMinimumShares < 2)
        {
            throw new ArgumentOutOfRangeException(nameof(numberOfMinimumShares), numberOfMinimumShares, ErrorMessages.MinNumberOfSharesLowerThanTwo);
        }

        if (numberOfMinimumShares > numberOfShares)
        {
            throw new ArgumentOutOfRangeException(nameof(numberOfShares), numberOfShares, ErrorMessages.MaxSharesLowerThanMinShares);
        }

        int newSecurityLevel = secret.SecretByteSize * 8;
        if (this.SecurityLevel < newSecurityLevel)
        {
            this.SecurityLevel = newSecurityLevel;
        }

        var polynomial = this.CreatePolynomial(numberOfMinimumShares, secret.ToCoefficient);
        try
        {
            var shares = this.CreateShares(numberOfShares, polynomial);
            return new Shares<TNumber>(shares);
        }
        finally
        {
            polynomial.DisposeAll();
        }
    }

    /// <summary>
    /// Creates a polynomial of degree <c>numberOfMinimumShares - 1</c> whose constant term is
    /// <paramref name="a0"/> and whose remaining coefficients are independently random elements
    /// modulo the configured Mersenne prime.
    /// </summary>
    /// <param name="numberOfMinimumShares">Minimum number of shared secrets for reconstruction.</param>
    /// <param name="a0">The constant-term (a₀) coefficient. Stored at index 0 of the returned array; the caller transfers ownership.</param>
    /// <returns>A pre-populated coefficient array; element [0] is <paramref name="a0"/>, elements [1..k-1] are freshly allocated random calculators.</returns>
    private Calculator<TNumber>[] CreatePolynomial(int numberOfMinimumShares, Calculator<TNumber> a0)
    {
        var polynomial = new Calculator<TNumber>[numberOfMinimumShares];
        polynomial[0] = a0;
        try
        {
            var prime = this.securityLevelManager.MersennePrime;
            int mersennePrimeByteCount = prime.ByteCount;
            // Allocate one extra trailing byte. PinnedPoolArray's ctor zeros the buffer and
            // rng.GetBytes(buf, 0, n) only writes the prefix, so the high byte at index n
            // stays 0. Both Calculator<TNumber> backends interpret their input as signed
            // two's-complement little-endian; a 0 high byte therefore forces the value to
            // be non-negative without an Abs() correction (which would skew the
            // distribution by mapping ±x to the same magnitude).
            using var randomBytePool = new PinnedPoolArray<byte>(mersennePrimeByteCount + 1);
            // Largest multiple of `prime` that fits in [0, 2^{8 * mersennePrimeByteCount}).
            // Rejection-sample any draw that lands at or above this bound to remove the
            // residual modulo bias. The reject probability is
            // (2^{8n} mod prime) / 2^{8n}, which for every Mersenne prime in the supported
            // range is well below 0.013% — the loop is overwhelmingly single-iteration.
            using var rangeBound = ComputeRangeBound(mersennePrimeByteCount, prime);
            int topIndex = numberOfMinimumShares - 1;
            for (int i = 1; i < numberOfMinimumShares; i++)
            {
                while (true)
                {
                    SecureRandom.Fill(randomBytePool.PoolArray, 0, mersennePrimeByteCount);
                    using var randomValue = Calculator.Create<TNumber>(randomBytePool.PoolArray, randomBytePool.Length);

                    if (randomValue >= rangeBound)
                    {
                        // Bias-eliminating rejection: redraw.
                        continue;
                    }

                    var coefficient = randomValue % prime;
                    // The leading coefficient must be non-zero to keep the polynomial at the
                    // intended degree k-1. A zero leading coefficient would silently drop the
                    // effective threshold from k to k-1. Reroll on a zero draw; lower-index
                    // coefficients are accepted unconditionally.
                    if (i != topIndex || !coefficient.IsZero)
                    {
                        polynomial[i] = coefficient;
                        break;
                    }

                    coefficient.Dispose();
                }
            }
        }
        catch
        {
            polynomial.DisposeAll();
            throw;
        }

        return polynomial;
    }

    /// <summary>
    /// Computes <c>floor(2^{8 * <paramref name="byteCount"/>} / <paramref name="prime"/>) * <paramref name="prime"/></c> —
    /// the largest multiple of <paramref name="prime"/> strictly below <c>2^{8 * byteCount}</c>.
    /// Drawing uniformly in <c>[0, returnedValue)</c> and reducing modulo <paramref name="prime"/>
    /// yields a uniform sample in <c>[0, prime - 1]</c>; samples in
    /// <c>[returnedValue, 2^{8 * byteCount})</c> must be rejected.
    /// </summary>
    private static Calculator<TNumber> ComputeRangeBound(int byteCount, Calculator<TNumber> prime)
    {
        using var two = Calculator<TNumber>.Two;
        using var space = two.Pow(byteCount * 8);
        using var quotient = space / prime;
        return quotient * prime;
    }

    /// <summary>
    /// Creates shares representing points on the secret polynomial.
    /// </summary>
    /// <param name="numberOfShares">Maximum number of shares</param>
    /// <param name="polynomial">The polynomial coefficients</param>
    /// <returns>Shares representing points on the secret polynomial. The caller owns each share
    /// and is responsible for disposal (typically by handing them to a <see cref="Shares{TNumber}"/>).</returns>
    /// <exception cref="ArgumentOutOfRangeException">
    /// <paramref name="numberOfShares"/> exceeds <see cref="MaxAllowedNumberOfShares"/>; or
    /// <paramref name="numberOfShares"/> is greater than or equal to the current Mersenne prime
    /// defining the finite field. Share indices 1..<paramref name="numberOfShares"/> would
    /// otherwise collide modulo the prime, breaking Lagrange reconstruction.
    /// </exception>
    /// <exception cref="NotSupportedException">
    /// The configured <typeparamref name="TNumber"/> backend's <see cref="Calculator"/>
    /// factory has no constructor matching the share-index byte buffer.
    /// </exception>
    private Share<TNumber>[] CreateShares(int numberOfShares, ICollection<Calculator<TNumber>> polynomial)
    {
        // Hard implementation cap — protects against pathological callers driving the
        // share-generation loop into multi-day CPU time on a large finite field. Realistic
        // Shamir schemes use values in the dozens; the cap is generous enough never to
        // interfere with legitimate use.
        if (numberOfShares > MaxAllowedNumberOfShares)
        {
            throw new ArgumentOutOfRangeException(
                nameof(numberOfShares),
                numberOfShares,
                string.Format(ErrorMessages.MaxSharesExceedsImplementationLimit, MaxAllowedNumberOfShares));
        }

        var prime = this.securityLevelManager.MersennePrime;

        // Share indices 1..numberOfShares form a contiguous run of positive integers
        // and must remain distinct modulo `prime` (Lagrange reconstruction divides by
        // (x_i - x_j); a collision yields denominator = 0 and a misleading
        // "inverse of zero" deep in DivMod). Reject early with a clean
        // ArgumentOutOfRangeException naming the actual misconfigured argument.
        using var maxIndex = Calculator.Create<TNumber>(Int32ToLittleEndianBytes(numberOfShares), sizeof(int));
        if (maxIndex >= prime)
        {
            throw new ArgumentOutOfRangeException(
                nameof(numberOfShares),
                numberOfShares,
                ErrorMessages.MaxSharesExceedsMersennePrime);
        }

        var size = numberOfShares + 1;
        var shares = new Share<TNumber>[numberOfShares];

        try
        {
            for (var i = 1; i < size; i++)
            {
                var bytes = Int32ToLittleEndianBytes(i);
                Calculator<TNumber> x = null;
                Calculator<TNumber> y = null;
                try
                {
                    x = Calculator.Create<TNumber>(bytes, bytes.Length);
                    y = Polynomial.EvaluateAt(x, polynomial, this.securityLevelManager.SecurityLevel);
                    shares[i - 1] = new Share<TNumber>(x, y);
                    // Ownership transferred to Share -- null out so the catch does not double-dispose.
                    x = null;
                    y = null;
                }
                catch
                {
                    x?.Dispose();
                    y?.Dispose();
                    throw;
                }
            }
        }
        catch
        {
            shares.DisposeAll();
            throw;
        }

        return shares;
    }

    /// <summary>
    /// Encodes <paramref name="value"/> as a freshly allocated 4-byte array in
    /// little-endian order, independent of the host's native endianness.
    /// </summary>
    /// <remarks>
    /// Share x-coordinates and the <c>numberOfShares</c> validation bound are
    /// converted to <see cref="Calculator{TNumber}"/> instances via
    /// <see cref="Calculator.Create(byte[], int, Type)"/>, which forwards to
    /// <c>System.Numerics.BigInteger(ReadOnlySpan&lt;byte&gt;)</c> /
    /// <c>SecureBigInteger(byte[], int)</c>. Both ctors interpret their input as
    /// little-endian two's-complement. Using <see cref="BitConverter.GetBytes(int)"/>
    /// (platform-endian) would silently produce wrong magnitudes on big-endian
    /// hosts; <see cref="BinaryPrimitives.WriteInt32LittleEndian"/> pins the
    /// encoding to LE on every CPU.
    /// </remarks>
    internal static byte[] Int32ToLittleEndianBytes(int value)
    {
        var bytes = new byte[sizeof(int)];
        BinaryPrimitives.WriteInt32LittleEndian(bytes, value);
        return bytes;
    }

    /// <summary>
    /// Releases all resources used by the current instance of the <see cref="SecretSplitter{TNumber}"/> class.
    /// </summary>
    /// <remarks>
    /// Idempotent and safe to call from multiple threads concurrently. The owned
    /// <see cref="ISecurityLevelManager{TNumber}"/> (when present) is disposed exactly once.
    /// </remarks>
    public void Dispose()
    {
        if (Interlocked.Exchange(ref this.disposed, 1) == 1)
        {
            return;
        }

        this.Dispose(true);
        GC.SuppressFinalize(this);
    }

    /// <summary>
    /// Releases the resources used by the <see cref="SecretSplitter{TNumber}"/> instance.
    /// </summary>
    /// <param name="disposing">A boolean value indicating whether to release managed resources (<see langword="true"/>)
    /// or only unmanaged resources (<see langword="false"/>).</param>
    /// <remarks>
    /// Disposes the contained <see cref="ISecurityLevelManager{TNumber}"/> only when this instance owns it
    /// (i.e. when constructed via the parameterless-manager overload).
    /// </remarks>
    protected virtual void Dispose(bool disposing)
    {
        if (disposing && this.ownsSecurityLevelManager)
        {
            this.securityLevelManager.Dispose();
        }
    }

    /// <summary>
    /// Throws <see cref="ObjectDisposedException"/> if this instance has already been disposed.
    /// </summary>
    /// <exception cref="ObjectDisposedException">This instance has been disposed.</exception>
    private void ThrowIfDisposed()
    {
        if (Volatile.Read(ref this.disposed) == 1)
        {
            throw new ObjectDisposedException(this.GetType().FullName);
        }
    }
}
