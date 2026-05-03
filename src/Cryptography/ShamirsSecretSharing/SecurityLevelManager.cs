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
    /// Represents the fixed security level used within the implementation of <see cref="SecurityLevelManager{TNumber}"/>.
    /// This value determines the security level as a Mersenne prime exponent, ensuring constraints
    /// are met based on the limits provided by the <see cref="IMersennePrimeProvider"/>.
    /// </summary>
    private int fixedSecurityLevel;

    /// <summary>
    /// Indicates whether the instance has been disposed.
    /// </summary>
    private bool disposed;

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

    /// <summary>
    /// Finalizes an instance of the <see cref="SecurityLevelManager{TNumber}"/> class.
    /// </summary>
    ~SecurityLevelManager()
    {
        this.Dispose(false);
    }

    /// <inheritdoc/>
    public int SecurityLevel
    {
        get => this.fixedSecurityLevel;
        set
        {
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

            using var one = Calculator<TNumber>.One;
            using var two = Calculator<TNumber>.Two;
            var newPrime = two.Pow(validSecurityLevel) - one;
            this.MersennePrime?.Dispose();
            this.MersennePrime = newPrime;
            this.fixedSecurityLevel = validSecurityLevel;
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
    public void Dispose()
    {
        this.Dispose(true);
        GC.SuppressFinalize(this);
    }

    /// <summary>
    /// Releases the resources used by the <see cref="SecurityLevelManager{TNumber}"/> instance.
    /// </summary>
    /// <param name="disposing">A boolean value indicating whether to release managed resources (true) or
    /// only unmanaged resources (false).</param>
    protected virtual void Dispose(bool disposing)
    {
        if (this.disposed)
        {
            return;
        }

        if (disposing)
        {
            this.MersennePrime.Dispose();
        }

        // Dispose unmanaged resources here if any

        this.disposed = true;
    }
}
