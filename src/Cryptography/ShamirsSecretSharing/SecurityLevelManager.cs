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
    /// Synchronizes mutations of <see cref="MersennePrime"/> and <see cref="fixedSecurityLevel"/> in
    /// the <see cref="SecurityLevel"/> setter and final disposal, so concurrent setters and a
    /// concurrent <see cref="Dispose"/> cannot interleave the field swap.
    /// </summary>
    private readonly object syncRoot = new();

    /// <summary>
    /// Holds the current security level (Mersenne prime exponent) backing
    /// <see cref="SecurityLevel"/>. Mutated only inside <see cref="syncRoot"/>.
    /// </summary>
    private int fixedSecurityLevel;

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
        this.SecurityLevel = this.mersennePrimeProvider.MinMersennePrimeExponent;
    }

    /// <inheritdoc/>
    public int SecurityLevel
    {
        get
        {
            this.ThrowIfDisposed();
            return this.fixedSecurityLevel;
        }
        set
        {
            this.ThrowIfDisposed();
            if (value < this.mersennePrimeProvider.MinMersennePrimeExponent)
            {
                throw new ArgumentOutOfRangeException(nameof(value), value, ErrorMessages.MinimumSecurityLevelExceeded);
            }

            if (value > this.mersennePrimeProvider.MaxMersennePrimeExponent)
            {
                throw new ArgumentOutOfRangeException(nameof(value), value, ErrorMessages.MaximumSecurityLevelExceeded);
            }

            int validSecurityLevel = !this.mersennePrimeProvider.IsValidMersennePrimeExponent(value)
                ? this.mersennePrimeProvider.GetNextMersennePrimeExponent(value)
                : value;

            // Allocate the new prime outside the lock — Pow/Subtract may be costly,
            // and we want to keep the critical section short.
            Calculator<TNumber> newPrime;
            using (var one = Calculator<TNumber>.One)
            using (var two = Calculator<TNumber>.Two)
            {
                newPrime = two.Pow(validSecurityLevel) - one;
            }

            Calculator<TNumber> oldPrime;
            try
            {
                lock (this.syncRoot)
                {
                    // Re-check disposed after acquiring the lock so a racing
                    // Dispose cannot resurrect this instance with a fresh prime.
                    this.ThrowIfDisposed();
                    oldPrime = this.MersennePrime;
                    this.MersennePrime = newPrime;
                    this.fixedSecurityLevel = validSecurityLevel;
                    newPrime = null; // ownership transferred to MersennePrime
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
    public Calculator<TNumber> MersennePrime { get; private set; }

    /// <inheritdoc/>
    public void AdjustSecurityLevel(Calculator<TNumber> maximumY)
    {
        this.SecurityLevel = maximumY.ByteCount * 8;
        int index = this.mersennePrimeProvider.GetIndexOfMersennePrimeExponent(this.SecurityLevel);
        while ((maximumY % this.MersennePrime + this.MersennePrime) % this.MersennePrime == maximumY && index >= 0)
        {
            index--;
            if (index >= 0)
            {
                this.SecurityLevel = this.mersennePrimeProvider.GetMersennePrimeExponentByIndex(index);
            }
        }

        this.SecurityLevel = this.mersennePrimeProvider.GetMersennePrimeExponentByIndex(index + 1);
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
            primeToDispose = this.MersennePrime;
            this.MersennePrime = null;
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
