// ----------------------------------------------------------------------------
// <copyright file="ShamirsSecretSharing`3.cs" company="Private">
// Copyright (c) 2022 All Rights Reserved
// </copyright>
// <author>Sebastian Walther</author>
// <date>08/20/2022 02:37:59 PM</date>
// ----------------------------------------------------------------------------

#region License
// ----------------------------------------------------------------------------
// Copyright 2022 Sebastian Walther
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

namespace SecretSharingDotNet.Cryptography;

using Math;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;

/// <summary>
/// Shamir's secret sharing algorithm
/// </summary>
/// <typeparam name="TNumber">Numeric data type</typeparam>
/// <typeparam name="TExtendedGcdAlgorithm"></typeparam>
/// <typeparam name="TExtendedGcdResult"></typeparam>
public class ShamirsSecretSharing<TNumber, TExtendedGcdAlgorithm, TExtendedGcdResult> : ShamirsSecretSharing
    where TExtendedGcdAlgorithm : class, IExtendedGcdAlgorithm<TNumber, TExtendedGcdResult>
    where TExtendedGcdResult : struct, IExtendedGcdResult<TNumber>
{
    /// <summary>
    /// Saves the fixed security level
    /// </summary>
    private int fixedSecurityLevel;

    /// <summary>
    /// Saves the calculated mersenne prime
    /// </summary>
    private Calculator<TNumber> mersennePrime;

    /// <summary>
    /// Saves the extended greatest common divisor algorithm
    /// </summary>
    private readonly TExtendedGcdAlgorithm extendedGcd;

    /// <summary>
    /// Initializes a new instance of the <see cref="ShamirsSecretSharing{TNumber, TExtendedGcdResult, TExtendedGcdResult}"/> class.
    /// </summary>
    /// <param name="extendedGcd">Extended greatest common divisor algorithm</param>
    /// <exception cref="T:System.ArgumentNullException">The <paramref name="extendedGcd"/> parameter is <see langword="null"/>.</exception>
    public ShamirsSecretSharing(TExtendedGcdAlgorithm extendedGcd)
    {
        this.extendedGcd = extendedGcd ?? throw new ArgumentNullException(nameof(extendedGcd));
        this.SecurityLevel = SecurityLevels[0];
    }

    /// <summary>
    /// Gets or sets the security level
    /// </summary>
    /// <remarks>Value is lower than 13 or greater than 43112609.</remarks>
    /// <exception cref="T:System.ArgumentOutOfRangeException" accessor="set">Value is lower than 13 or greater than 43112609.</exception>
    public int SecurityLevel
    {
        get => this.fixedSecurityLevel;

        set
        {
            if (value < SecurityLevels[0])
            {
                throw new ArgumentOutOfRangeException(nameof(value), value, ErrorMessages.MinimumSecurityLevelExceeded);
            }

            int index = Array.BinarySearch(SecurityLevels, value);
            if (index < 0)
            {
                try
                {
                    value = SecurityLevels[~index];
                }
                catch (ArgumentOutOfRangeException)
                {
                    throw new ArgumentOutOfRangeException(nameof(value), value, ErrorMessages.MaximumSecurityLevelExceeded);
                }
            }

            this.mersennePrime = Calculator<TNumber>.Two.Pow(value) - Calculator<TNumber>.One;
            this.fixedSecurityLevel = value;
        }
    }

    /// <summary>
    /// Generates a random shamir pool, returns the random secret and the share points.
    /// </summary>
    /// <param name="numberOfMinimumShares">Minimum number of shared secrets for reconstruction</param>
    /// <param name="numberOfShares">Maximum number of shared secrets</param>
    /// <param name="securityLevel">Security level (in number of bits). Minimum is 13.</param>
    /// <returns></returns>
    /// <exception cref="T:System.ArgumentOutOfRangeException">The <paramref name="securityLevel"/> parameter is lower than 13 or greater than 43112609. OR The <paramref name="numberOfMinimumShares"/> parameter is lower than 2 or greater than <paramref name="numberOfShares"/>.</exception>
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
        if (min < MinimumShareLimit)
        {
            throw new ArgumentOutOfRangeException(nameof(numberOfMinimumShares), numberOfMinimumShares, ErrorMessages.MinNumberOfSharesLowerThanTwo);
        }

        if (min > max)
        {
            throw new ArgumentOutOfRangeException(nameof(numberOfShares), numberOfShares, ErrorMessages.MaxSharesLowerThanMinShares);
        }

        if (this.mersennePrime == null)
        {
            throw new InvalidOperationException("Security Level is not initialized!");
        }

        var secret = Secret<TNumber>.CreateRandom(this.mersennePrime);
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
    /// <param name="securityLevel">Security level (in number of bits). Minimum is 13.</param>
    /// <returns></returns>
    /// <remarks>This method can modify the <see cref="SecurityLevel"/> based on the <paramref name="secret"/> length.</remarks>
    /// <exception cref="T:System.ArgumentOutOfRangeException">The <paramref name="securityLevel"/> is lower than 13 or greater than 43112609. OR <paramref name="numberOfMinimumShares"/> is lower than 2 or greater than <paramref name="numberOfShares"/>.</exception>
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
        if (min < MinimumShareLimit)
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
#if NET6_0_OR_GREATER
    private unsafe Calculator<TNumber>[] CreatePolynomial(int numberOfMinimumShares)
#else
    private Calculator<TNumber>[] CreatePolynomial(int numberOfMinimumShares)
#endif
    {
        var polynomial = new Calculator<TNumber>[numberOfMinimumShares];
        polynomial[0] = Calculator<TNumber>.Zero;
        byte[] randomNumber = new byte[this.mersennePrime.ByteCount];
#if NET6_0_OR_GREATER
        fixed (byte* pointer = randomNumber)
        {
            var span = new Span<byte>(pointer, this.mersennePrime.ByteCount);
            using var rng = RandomNumberGenerator.Create();
            for (int i = 1; i < numberOfMinimumShares; i++)
            {
                rng.GetBytes(span);
                polynomial[i] = (Calculator.Create(randomNumber, typeof(TNumber)) as Calculator<TNumber>)?.Abs() %
                                this.mersennePrime;
            }

            span.Clear();
        }
#else
         using var rng = RandomNumberGenerator.Create();
         for (int i = 1; i < numberOfMinimumShares; i++)
         {
             rng.GetBytes(randomNumber);
             polynomial[i] = (Calculator.Create(randomNumber, typeof(TNumber)) as Calculator<TNumber>)?.Abs() %
                             this.mersennePrime;
         }

         Array.Clear(randomNumber, 0, randomNumber.Length);
#endif
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
            points[i - 1] = new FinitePoint<TNumber>(x, polynomial, this.mersennePrime);
        }

        return points;
    }

    /// <summary>
    /// Computes numerator / denominator modulo prime.
    /// This means that the return value will be such that
    /// the following is true:
    /// denominator * DivMod(numerator, denominator, prime) % prime == numerator
    /// </summary>
    /// <param name="numerator"></param>
    /// <param name="denominator"></param>
    /// <param name="prime"></param>
    /// <returns></returns>
    private Calculator<TNumber> DivMod(
        Calculator<TNumber> numerator,
        Calculator<TNumber> denominator,
        Calculator<TNumber> prime)
    {
        var result = this.extendedGcd.Compute(denominator, prime);
        return numerator * result.BezoutCoefficients[0] * result.GreatestCommonDivisor;
    }

    /// <summary>
    /// Computes the mathematical product of a series of <paramref name="values"/>
    /// </summary>
    /// <param name="values"></param>
    /// <returns></returns>
    /// <remarks>Helper method for LagrangeInterpolate</remarks>
    private static Calculator<TNumber> Product(IReadOnlyList<Calculator<TNumber>> values)
    {
        var result = Calculator<TNumber>.One;
        for (int i = 0; i < values.Count; i++)
        {
            result *= values[i];
        }

        return result;
    }

    /// <summary>
    /// Find the y-value for the given x, given n (x, y) points;
    /// k points will define a polynomial of up to kth order
    /// </summary>
    /// <param name="finitePoints">The shares represented by a set of <see cref="FinitePoint{TNumber}"/>.</param>
    /// <param name="prime">A prime number must be defined to avoid computation with real numbers. In fact it is finite field arithmetic.
    /// The prime number must be the same as used for the construction of shares.</param>
    /// <exception cref="ArgumentException"></exception>
    /// <returns>The re-constructed secret.</returns>
    private Secret<TNumber> LagrangeInterpolate(FinitePoint<TNumber>[] finitePoints, Calculator<TNumber> prime)
    {
        if (finitePoints == null)
        {
            throw new ArgumentNullException(nameof(finitePoints));
        }

        if (prime == null)
        {
            throw new ArgumentNullException(nameof(prime));
        }

        int numberOfPoints = finitePoints.Length;
        if (finitePoints.Distinct().Count() != numberOfPoints)
        {
            throw new ArgumentException(ErrorMessages.FinitePointsNotDistinct, nameof(finitePoints));
        }

        var numeratorProducts = new Calculator<TNumber>[numberOfPoints];
        var denominatorProducts = new Calculator<TNumber>[numberOfPoints];
        var numeratorTerms = new Calculator<TNumber>[numberOfPoints];
        var denominatorTerms = new Calculator<TNumber>[numberOfPoints];
        var denominator = Calculator<TNumber>.One;
        for (int i = 0; i < numberOfPoints; i++)
        {
            for (int j = 0; j < numberOfPoints; j++)
            {
                if (finitePoints[i] != finitePoints[j])
                {
                    numeratorTerms[j] = Calculator<TNumber>.Zero - finitePoints[j].X;
                    denominatorTerms[j] = finitePoints[i].X - finitePoints[j].X;
                }
                else
                {
                    numeratorTerms[j] = denominatorTerms[j] = Calculator<TNumber>.One;
                }
            }

            numeratorProducts[i] = Product(numeratorTerms);
            denominatorProducts[i] = Product(denominatorTerms);
            denominator *= denominatorProducts[i];
        }

        var numerator = Calculator<TNumber>.Zero;
        for (int i = 0; i < numberOfPoints; i++)
        {
            numerator += this.DivMod(numeratorProducts[i] * denominator * ((finitePoints[i].Y % prime + prime) % prime), denominatorProducts[i], prime);
        }

        var a = this.DivMod(numerator, denominator, prime) + prime;
        a = (a % prime + prime) % prime; //// mathematical modulo
        return Secret<TNumber>.FromCoefficient(a);
    }

    /// <summary>
    /// Recovers the secret from the given <paramref name="shares"/> (points with x and y on the polynomial)
    /// </summary>
    /// <param name="shares">Shares represented by <see cref="string"/> and separated by newline.</param>
    /// <returns>Re-constructed secret</returns>
    public Secret<TNumber> Reconstruction(string shares)
    {
        if (string.IsNullOrWhiteSpace(shares))
        {
            throw new ArgumentNullException(nameof(shares));
        }

        Shares<TNumber> castShares = shares;
        return this.Reconstruction(castShares);
    }

    /// <summary>
    /// Recovers the secret from the given <paramref name="shares"/> (points with x and y on the polynomial)
    /// </summary>
    /// <param name="shares">Shares represented by <see cref="string"/> array.</param>
    /// <returns>Re-constructed secret</returns>
    public Secret<TNumber> Reconstruction(string[] shares)
    {
        if (shares == null)
        {
            throw new ArgumentNullException(nameof(shares));
        }

        if (shares.Length < 2)
        {
            throw new ArgumentOutOfRangeException(nameof(shares), ErrorMessages.MinNumberOfSharesLowerThanTwo);
        }

        Shares<TNumber> castShares = shares;
        return this.Reconstruction(castShares);
    }

    /// <summary>
    /// Recovers the secret from the given <paramref name="shares"/> (points with x and y on the polynomial)
    /// </summary>
    /// <param name="shares">For details <see cref="Shares{TNumber}"/></param>
    /// <returns>Re-constructed secret</returns>
    public Secret<TNumber> Reconstruction(Shares<TNumber> shares)
    {
        return this.Reconstruction((FinitePoint<TNumber>[])shares);
    }

    /// <summary>
    /// Recovers the secret from the given <paramref name="shares"/> (points with x and y on the polynomial)
    /// </summary>
    /// <param name="shares">Two or more shares represented by a set of <see cref="FinitePoint{TNumber}"/></param>
    /// <returns>Re-constructed secret</returns>
    /// <exception cref="T:System.ArgumentNullException"><paramref name="shares"/> is <see langword="null"/>.</exception>
    /// <exception cref="T:System.ArgumentOutOfRangeException">The length of <paramref name="shares"/> is lower than 2.</exception>
    public Secret<TNumber> Reconstruction(FinitePoint<TNumber>[] shares)
    {
        if (shares == null)
        {
            throw new ArgumentNullException(nameof(shares));
        }

        if (shares.Length < 2)
        {
            throw new ArgumentOutOfRangeException(nameof(shares), ErrorMessages.MinNumberOfSharesLowerThanTwo);
        }

        var maximumY = shares.Select(point => point.Y).Max();
        if (maximumY == null)
        {
            throw new ArgumentException(ErrorMessages.NoMaximumY, nameof(shares));
        }

        this.SecurityLevel = maximumY.ByteCount * 8;
        int index = Array.IndexOf(SecurityLevels, this.SecurityLevel);
        while ((maximumY % this.mersennePrime + this.mersennePrime) % this.mersennePrime == maximumY && index >= 0)
        {
            index--;
            if (index >= 0)
            {
                this.SecurityLevel = SecurityLevels[index];
            }
        }

        this.SecurityLevel = SecurityLevels[index + 1];

        return this.LagrangeInterpolate(shares, this.mersennePrime);
    }
}