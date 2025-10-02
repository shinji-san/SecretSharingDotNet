// ----------------------------------------------------------------------------
// <copyright file="ShamirsSecretSharing.cs" company="Private">
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

using Math;
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
    /// Generates a random shamir pool, returns the random secret and the share points.
    /// </summary>
    /// <param name="numberOfMinimumShares">Minimum number of shared secrets for reconstruction</param>
    /// <param name="numberOfShares">Maximum number of shared secrets</param>
    /// <param name="securityLevel">Security level (in number of bits). The minimum is 13.</param>
    /// <returns></returns>
    /// <exception cref="T:System.ArgumentOutOfRangeException">
    /// The <paramref name="securityLevel"/> parameter is lower than 13 or greater than 43.112.609. OR The <paramref name="numberOfMinimumShares"/> parameter is lower than 2 or greater than <paramref name="numberOfShares"/>.
    /// </exception>
    public Shares<TNumber> MakeShares(TNumber numberOfMinimumShares, TNumber numberOfShares, int securityLevel)
    {
        try
        {
            this.SecurityLevel = securityLevel;
        }
        catch (ArgumentOutOfRangeException e)
        {
            throw new ArgumentOutOfRangeException(nameof(securityLevel), securityLevel, e.Message);
        }

        int min = ((Calculator<TNumber>)numberOfMinimumShares).ToInt32();
        int max = ((Calculator<TNumber>)numberOfShares).ToInt32();
        if (min < 2)
        {
            throw new ArgumentOutOfRangeException(nameof(numberOfMinimumShares), numberOfMinimumShares, ErrorMessages.MinNumberOfSharesLowerThanTwo);
        }

        if (min > max)
        {
            throw new ArgumentOutOfRangeException(nameof(numberOfShares), numberOfShares, ErrorMessages.MaxSharesLowerThanMinShares);
        }

        if (this.securityLevelManager.MersennePrime == null)
        {
            throw new InvalidOperationException("Security Level is not initialized!");
        }

        var secret = Secret<TNumber>.CreateRandom(this.securityLevelManager.MersennePrime);
        var polynomial = this.CreatePolynomial(min);
        polynomial[0] = secret.ToCoefficient;
        var points = this.CreateSharedSecrets(max, polynomial);
        return new Shares<TNumber>(secret, points);
    }

    /// <summary>
    /// Generates a random shamir pool, returns the specified <paramref name="secret"/> and the share points.
    /// </summary>
    /// <param name="numberOfMinimumShares">Minimum number of shared secrets for reconstruction</param>
    /// <param name="numberOfShares">Maximum number of shared secrets</param>
    /// <param name="secret">secret text as <see cref="Secret{TNumber}"/> or see cref="string"/></param>
    /// <param name="securityLevel">Security level (in number of bits). The minimum is 13.</param>
    /// <returns></returns>
    /// <remarks>This method can modify the <see cref="SecurityLevel"/> based on the <paramref name="secret"/> length.</remarks>
    /// <exception cref="T:System.ArgumentOutOfRangeException">
    /// The <paramref name="securityLevel"/> is lower than 13 or greater than 43.112.609. OR <paramref name="numberOfMinimumShares"/> is lower than 2 or greater than <paramref name="numberOfShares"/>.
    /// </exception>
    public Shares<TNumber> MakeShares(TNumber numberOfMinimumShares, TNumber numberOfShares, Secret<TNumber> secret, int securityLevel)
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
    /// Generates a random shamir pool, returns the specified <paramref name="secret"/> and the share points.
    /// </summary>
    /// <param name="numberOfMinimumShares">Minimum number of shared secrets for reconstruction</param>
    /// <param name="numberOfShares">Maximum number of shared secrets</param>
    /// <param name="secret">secret text as <see cref="Secret{TNumber}"/> or see cref="string"/></param>
    /// <returns></returns>
    /// <remarks>This method modifies the <see cref="SecurityLevel"/> based on the <paramref name="secret"/> length</remarks>
    /// <exception cref="T:System.ArgumentOutOfRangeException"><paramref name="numberOfMinimumShares"/> is lower than 2 or greater than <paramref name="numberOfShares"/>.</exception>
    public Shares<TNumber> MakeShares(TNumber numberOfMinimumShares, TNumber numberOfShares, Secret<TNumber> secret)
    {
        int min = ((Calculator<TNumber>)numberOfMinimumShares).ToInt32();
        int max = ((Calculator<TNumber>)numberOfShares).ToInt32();
        if (min < 2)
        {
            throw new ArgumentOutOfRangeException(nameof(numberOfMinimumShares), numberOfMinimumShares, ErrorMessages.MinNumberOfSharesLowerThanTwo);
        }

        if (min > max)
        {
            throw new ArgumentOutOfRangeException(nameof(numberOfShares), numberOfShares, ErrorMessages.MaxSharesLowerThanMinShares);
        }

        int newSecurityLevel = secret.SecretByteSize * 8;
        if (this.SecurityLevel < newSecurityLevel)
        {
            this.SecurityLevel = newSecurityLevel;
        }

        var polynomial = this.CreatePolynomial(min);
        polynomial[0] = secret.ToCoefficient;
        var points = this.CreateSharedSecrets(max, polynomial);

        return new Shares<TNumber>(secret, points);
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
        byte[] randomNumber = new byte[this.securityLevelManager.MersennePrime.ByteCount];
        using var rng = RandomNumberGenerator.Create();
        for (int i = 1; i < numberOfMinimumShares; i++)
        {
            rng.GetBytes(randomNumber);
            polynomial[i] = (Calculator.Create(randomNumber, typeof(TNumber)) as Calculator<TNumber>)?.Abs() % this.securityLevelManager.MersennePrime;
        }

        return polynomial;
    }

    /// <summary>
    /// Creates shared Secrets
    /// </summary>
    /// <param name="numberOfShares">Maximum number of shared secrets</param>
    /// <param name="polynomial"></param>
    /// <returns>Finite points representing the shared secrets</returns>
    private FinitePoint<TNumber>[] CreateSharedSecrets(int numberOfShares, ICollection<Calculator<TNumber>> polynomial)
    {
        int size = numberOfShares + 1;
        var points = new FinitePoint<TNumber>[numberOfShares];

        for (int i = 1; i < size; i++)
        {
            var x = Calculator.Create(BitConverter.GetBytes(i), typeof(TNumber)) as Calculator<TNumber>;
            points[i - 1] = new FinitePoint<TNumber>(x, polynomial, this.securityLevelManager.MersennePrime);
        }

        return points;
    }
}