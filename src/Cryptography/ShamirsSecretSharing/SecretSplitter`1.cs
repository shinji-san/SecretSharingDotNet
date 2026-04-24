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
using System.Collections.Generic;
using System.Security.Cryptography;

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
    /// Represents the manager for configuring and retrieving the security level
    /// settings in the context of Shamir's Secret Sharing implementation.
    /// </summary>
    private readonly ISecurityLevelManager<TNumber> securityLevelManager;

    /// <summary>
    /// Initializes a new instance of the <see cref="SecretSplitter{TNumber}"/> class.
    /// </summary>
    public SecretSplitter()
    {
        this.securityLevelManager = new SecurityLevelManager<TNumber>();
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="SecretSplitter{TNumber}"/> class.
    /// </summary>
    public SecretSplitter(ISecurityLevelManager<TNumber> securityLevelManager)
    {
        this.securityLevelManager = securityLevelManager ?? throw new ArgumentNullException(nameof(securityLevelManager));
    }
    
    /// <summary>
    /// Gets or sets the security level
    /// </summary>
    /// <remarks>The value is lower than 13 or greater than 43.112.609.</remarks>
    /// <exception cref="T:System.ArgumentOutOfRangeException" accessor="set">The value is lower than 13 or greater than 43.112.609.</exception>
    public int SecurityLevel
    {
        get => this.securityLevelManager.SecurityLevel;
        set => this.securityLevelManager.SecurityLevel = value;
    }

    /// <summary>
    /// Generates a random shamir pool and returns the share points.
    /// The generated random secret is provided via the <paramref name="generatedSecret"/> out parameter.
    /// </summary>
    /// <param name="numberOfMinimumShares">Minimum number of shared secrets for reconstruction</param>
    /// <param name="numberOfShares">Maximum number of shared secrets</param>
    /// <param name="securityLevel">Security level (in number of bits). The minimum is 13.</param>
    /// <param name="generatedSecret">output parameter returning the generated secret as <see cref="Secret{TNumber}"/></param>
    /// <returns>A <see cref="Shares{TNumber}"/> collection containing the generated shares.</returns>
    /// <exception cref="T:System.ArgumentOutOfRangeException">
    /// The <paramref name="securityLevel"/> parameter is lower than 13 or greater than 43.112.609. OR The <paramref name="numberOfMinimumShares"/> parameter is lower than 2 or greater than <paramref name="numberOfShares"/>.
    /// </exception>
    public Shares<TNumber> MakeShares(int numberOfMinimumShares, int numberOfShares, int securityLevel, out Secret<TNumber> generatedSecret)
    {
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
            throw new InvalidOperationException("Security Level is not initialized!");
        }

        generatedSecret = Secret<TNumber>.CreateRandom(this.securityLevelManager.MersennePrime);
        var polynomial = this.CreatePolynomial(numberOfMinimumShares);
        polynomial[0] = generatedSecret.ToCoefficient;
        var shares = this.CreateShares(numberOfShares, polynomial);
        polynomial.DisposeAll();
        return new Shares<TNumber>(shares);
    }

    /// <summary>
    /// Generates a shamir pool using the provided <paramref name="secret"/> and returns the share points.
    /// </summary>
    /// <param name="numberOfMinimumShares">Minimum number of shared secrets for reconstruction</param>
    /// <param name="numberOfShares">Maximum number of shared secrets</param>
    /// <param name="secret">secret text as <see cref="Secret{TNumber}"/> or see cref="string"/></param>
    /// <param name="securityLevel">Security level (in number of bits). The minimum is 13.</param>
    /// <returns>A <see cref="Shares{TNumber}"/> collection containing the generated shares.</returns>
    /// <remarks>This method can modify the <see cref="SecurityLevel"/> based on the <paramref name="secret"/> length.</remarks>
    /// <exception cref="T:System.ArgumentOutOfRangeException">
    /// The <paramref name="securityLevel"/> is lower than 13 or greater than 43.112.609. OR <paramref name="numberOfMinimumShares"/> is lower than 2 or greater than <paramref name="numberOfShares"/>.
    /// </exception>
    public Shares<TNumber> MakeShares(int numberOfMinimumShares, int numberOfShares, Secret<TNumber> secret, int securityLevel)
    {
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
    /// <param name="numberOfMinimumShares">Minimum number of shared secrets for reconstruction</param>
    /// <param name="numberOfShares">Maximum number of shared secrets</param>
    /// <param name="secret">secret text as <see cref="Secret{TNumber}"/> or see cref="string"/></param>
    /// <returns>A <see cref="Shares{TNumber}"/> collection containing the generated shares.</returns>
    /// <remarks>This method modifies the <see cref="SecurityLevel"/> based on the <paramref name="secret"/> length</remarks>
    /// <exception cref="T:System.ArgumentOutOfRangeException"><paramref name="numberOfMinimumShares"/> is lower than 2 or greater than <paramref name="numberOfShares"/>.</exception>
    public Shares<TNumber> MakeShares(int numberOfMinimumShares, int numberOfShares, Secret<TNumber> secret)
    {
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

        var polynomial = this.CreatePolynomial(numberOfMinimumShares);
        polynomial[0] = secret.ToCoefficient;
        var shares = this.CreateShares(numberOfShares, polynomial);
        polynomial.DisposeAll();
        return new Shares<TNumber>(shares);
    }

    /// <summary>
    /// Creates a polynomial
    /// </summary>
    /// <param name="numberOfMinimumShares">Minimum number of shared secrets for reconstruction</param>
    /// <returns></returns>
    private Calculator<TNumber>[] CreatePolynomial(int numberOfMinimumShares)
    {
        var polynomial = new Calculator<TNumber>[numberOfMinimumShares];
        polynomial[0] = Calculator<TNumber>.Zero;
        var mersennePrimeByteCount = this.securityLevelManager.MersennePrime.ByteCount;
        using var randomBytePool = new PinnedPoolArray<byte>(mersennePrimeByteCount);
        using var rng = RandomNumberGenerator.Create();
        for (int i = 1; i < numberOfMinimumShares; i++)
        {
            rng.GetBytes(randomBytePool.PoolArray, 0, mersennePrimeByteCount);
            using var randomValue = Calculator.Create(randomBytePool.PoolArray, randomBytePool.Length, typeof(TNumber)) as Calculator<TNumber>;
            if (randomValue == null)
            {
                throw new InvalidOperationException("Random value generation failed!");
            }

            using var abs = randomValue.Abs();
            polynomial[i] = abs % this.securityLevelManager.MersennePrime;
        }

        return polynomial;
    }

    /// <summary>
    /// Creates shares representing points on the secret polynomial.
    /// </summary>
    /// <param name="numberOfShares">Maximum number of shares</param>
    /// <param name="polynomial">The polynomial coefficients</param>
    /// <returns>Shares representing points on the secret polynomial. The caller owns each share
    /// and is responsible for disposal (typically by handing them to a <see cref="Shares{TNumber}"/>).</returns>
    private Share<TNumber>[] CreateShares(int numberOfShares, ICollection<Calculator<TNumber>> polynomial)
    {
        var size = numberOfShares + 1;
        var shares = new Share<TNumber>[numberOfShares];
        var prime = this.securityLevelManager.MersennePrime;

        for (var i = 1; i < size; i++)
        {
            var bytes = BitConverter.GetBytes(i);
            var x = Calculator.Create(bytes, bytes.Length, typeof(TNumber)) as Calculator<TNumber>
                    ?? throw new NotSupportedException(string.Format(ErrorMessages.DataTypeNotSupported, typeof(TNumber).Name));
            var y = Polynomial.EvaluateAt(x, polynomial, prime);
            shares[i - 1] = new Share<TNumber>(x, y);
        }

        return shares;
    }
}
