// ----------------------------------------------------------------------------
// <copyright file="SecurityLevelManager.cs" company="Private">
// Copyright (c) 2025 All Rights Reserved
// </copyright>
// <author>Sebastian Walther</author>
// <date>10/03/2025 01:07:10 AM</date>
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

using Math;
using System;
using System.Threading;

/// <summary>
/// Default implementation of <see cref="ISecurityLevelManager{TNumber}"/>.
/// </summary>
/// <typeparam name="TNumber">Numeric data type</typeparam>
public class SecurityLevelManager<TNumber> : ISecurityLevelManager<TNumber>
{
    /// <summary>
    /// Provides access to a Mersenne prime provider implementation, enabling retrieval and validation
    /// of Mersenne prime exponents.
    /// This is used as a cornerstone for determining and managing security levels in cryptographic operations.
    /// </summary>
    private readonly IMersennePrimeProvider mersennePrimeProvider;

    /// <summary>
    /// Synchronizes mutations of <see cref="MersennePrime"/> and <see cref="currentSecurityLevel"/> in
    /// the <see cref="SecurityLevel"/> setter and final disposal, so concurrent setters and a
    /// concurrent <see cref="Dispose()"/> cannot interleave the field swap.
    /// </summary>
    private readonly object syncRoot = new();

    /// <summary>
    /// Holds the current security level (Mersenne prime exponent) backing
    /// <see cref="SecurityLevel"/>. Mutated only inside <see cref="syncRoot"/>.
    /// </summary>
    private int currentSecurityLevel;

    /// <summary>
    /// Disposal flag manipulated atomically via <see cref="Interlocked.Exchange(ref int, int)"/>:
    /// <c>0</c> = alive, <c>1</c> = disposed.
    /// </summary>
    private int disposed;

    /// <summary>
    /// Initializes a new instance of the <see cref="SecurityLevelManager{TNumber}"/> class with the
    /// default Mersenne prime provider.
    /// </summary>
    public SecurityLevelManager()
        : this(MersennePrimeProvider.Instance)
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="SecurityLevelManager{TNumber}"/> class.
    /// </summary>
    /// <param name="mersennePrimeProvider">Provider for Mersenne prime exponents</param>
    /// <exception cref="T:System.ArgumentNullException">
    /// <paramref name="mersennePrimeProvider"/> is <see langword="null"/>.
    /// </exception>
    public SecurityLevelManager(IMersennePrimeProvider mersennePrimeProvider)
    {
        this.mersennePrimeProvider = mersennePrimeProvider ?? throw new ArgumentNullException(nameof(mersennePrimeProvider));
        int initialLevel = this.mersennePrimeProvider.MinMersennePrimeExponent;
        this.currentSecurityLevel = initialLevel;
        this.mersennePrime = NewMersennePrime(initialLevel);
    }

    /// <inheritdoc/>
    public int SecurityLevel
    {
        get
        {
            this.ThrowIfDisposed();
            return this.currentSecurityLevel;
        }
        set
        {
            this.ThrowIfDisposed();
            int validSecurityLevel = this.NormalizeMersenneExponent(value);

            // Allocate the new prime outside the lock — Pow/Subtract may be costly,
            // and we want to keep the critical section short.
            var newPrime = NewMersennePrime(validSecurityLevel);

            Calculator<TNumber> oldPrime;
            try
            {
                lock (this.syncRoot)
                {
                    // Re-check disposed after acquiring the lock so a racing
                    // Dispose cannot resurrect this instance with a fresh prime.
                    this.ThrowIfDisposed();
                    oldPrime = this.mersennePrime;
                    this.mersennePrime = newPrime;
                    this.currentSecurityLevel = validSecurityLevel;
                    newPrime = null; // ownership transferred to mersennePrime
                }
            }
            catch
            {
                newPrime?.Dispose();
                throw;
            }

            // Dispose outside the lock — Calculator.Dispose touches pinned-pool
            // resources and we must not hold our own monitor across that.
            oldPrime?.Dispose();
        }
    }

    /// <inheritdoc/>
    public Calculator<TNumber> MersennePrime
    {
        get
        {
            this.ThrowIfDisposed();
            return this.mersennePrime;
        }
    }

    /// <summary>
    /// Backing field for <see cref="MersennePrime"/>. Mutated only inside <see cref="syncRoot"/>
    /// (by the <see cref="SecurityLevel"/> setter and <see cref="Dispose()"/>).
    /// </summary>
    private Calculator<TNumber> mersennePrime;

    /// <inheritdoc/>
    public void AdjustSecurityLevel(Calculator<TNumber> maximumY)
    {
        this.ThrowIfDisposed();
        if (maximumY is null)
        {
            throw new ArgumentNullException(nameof(maximumY));
        }

        // Determine the starting index without mutating MersennePrime: clamp the
        // byte-count-derived bit length to a valid Mersenne exponent and resolve its index.
        int initialLevel = this.NormalizeMersenneExponent(maximumY.ByteCount * 8);
        int index = this.mersennePrimeProvider.GetIndexOfMersennePrimeExponent(initialLevel);

        // Walk the index downward as long as maximumY still fits modulo the corresponding prime.
        // Each candidate prime is allocated locally and disposed immediately; the manager's
        // MersennePrime is not touched inside the loop.
        while (index >= 0 && this.CandidatePrimeFitsMaximumY(index, maximumY))
        {
            index--;
        }

        // index is now either -1 (maximumY fits even the smallest prime) or the highest
        // exponent for which maximumY does NOT fit. The smallest fitting exponent is at index+1.
        this.SecurityLevel = this.mersennePrimeProvider.GetMersennePrimeExponentByIndex(index + 1);
    }

    /// <summary>
    /// Validates <paramref name="value"/> against the Mersenne prime exponent range and rounds
    /// non-Mersenne values up to the next valid exponent. Mirrors the input normalisation
    /// performed by the <see cref="SecurityLevel"/> setter.
    /// </summary>
    /// <exception cref="ArgumentOutOfRangeException">
    /// <paramref name="value"/> is below <see cref="IMersennePrimeProvider.MinMersennePrimeExponent"/>
    /// or above <see cref="IMersennePrimeProvider.MaxMersennePrimeExponent"/>.
    /// </exception>
    private int NormalizeMersenneExponent(int value)
    {
        if (value < this.mersennePrimeProvider.MinMersennePrimeExponent)
        {
            throw new ArgumentOutOfRangeException(nameof(value), value, ErrorMessages.MinimumSecurityLevelExceeded);
        }

        if (value > this.mersennePrimeProvider.MaxMersennePrimeExponent)
        {
            throw new ArgumentOutOfRangeException(nameof(value), value, ErrorMessages.MaximumSecurityLevelExceeded);
        }

        return this.mersennePrimeProvider.IsValidMersennePrimeExponent(value)
            ? value
            : this.mersennePrimeProvider.GetNextMersennePrimeExponent(value);
    }

    /// <summary>
    /// Returns whether <paramref name="maximumY"/> reduces to itself modulo the Mersenne prime
    /// at the given <paramref name="index"/> — i.e. whether <paramref name="maximumY"/> fits
    /// inside that finite field.
    /// </summary>
    private bool CandidatePrimeFitsMaximumY(int index, Calculator<TNumber> maximumY)
    {
        int exponent = this.mersennePrimeProvider.GetMersennePrimeExponentByIndex(index);
        using var prime = NewMersennePrime(exponent);
        using var reduced = maximumY % prime;
        using var shifted = reduced + prime;
        using var normalized = shifted % prime;
        return normalized == maximumY;
    }

    /// <summary>
    /// Allocates a freshly computed Mersenne prime <c>2^<paramref name="exponent"/> − 1</c>
    /// as a <see cref="Calculator{TNumber}"/>. Caller takes ownership.
    /// </summary>
    private static Calculator<TNumber> NewMersennePrime(int exponent)
    {
        using var one = Calculator<TNumber>.One;
        using var two = Calculator<TNumber>.Two;
        using var power = two.Pow(exponent);
        return power - one;
    }

    /// <summary>
    /// Releases all resources used by the current instance of the <see cref="SecurityLevelManager{TNumber}"/> class.
    /// </summary>
    /// <remarks>
    /// Idempotent and safe to call from multiple threads concurrently. The owned
    /// <see cref="MersennePrime"/> Calculator is disposed exactly once.
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
    /// Releases the resources used by the <see cref="SecurityLevelManager{TNumber}"/> instance.
    /// </summary>
    /// <param name="disposing">A boolean value indicating whether to release managed resources
    /// (<see langword="true"/>) or only unmanaged resources (<see langword="false"/>).</param>
    protected virtual void Dispose(bool disposing)
    {
        if (!disposing)
        {
            return;
        }

        Calculator<TNumber> primeToDispose;
        lock (this.syncRoot)
        {
            primeToDispose = this.mersennePrime;
            this.mersennePrime = null;
        }

        primeToDispose?.Dispose();
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
