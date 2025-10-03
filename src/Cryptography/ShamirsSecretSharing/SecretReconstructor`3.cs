// ----------------------------------------------------------------------------
// <copyright file="ShamirsSecretSharing`3.cs" company="Private">
// Copyright (c) 2025 All Rights Reserved
// </copyright>
// <author>Sebastian Walther</author>
// <date>10/03/2025 01:42:17 AM</date>
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
using System.Linq;

/// <summary>
/// Represents a class used for reconstructing secrets using Shamir's Secret Sharing scheme.
/// </summary>
/// <typeparam name="TNumber">The numeric type used in the calculations, typically an integer or big integer.</typeparam>
/// <typeparam name="TExtendedGcdAlgorithm">The type of the implementation for the extended greatest common divisor (GCD) algorithm.</typeparam>
/// <typeparam name="TExtendedGcdResult">The result type returned by the specified extended GCD algorithm.</typeparam>
public class SecretReconstructor<TNumber, TExtendedGcdAlgorithm, TExtendedGcdResult> : IReconstructionUseCase<TNumber>
    where TExtendedGcdAlgorithm : class, IExtendedGcdAlgorithm<TNumber, TExtendedGcdResult>
    where TExtendedGcdResult : struct, IExtendedGcdResult<TNumber>
{
    /// <summary>
    /// Saves the extended greatest common divisor algorithm
    /// </summary>
    private readonly TExtendedGcdAlgorithm extendedGcd;

    /// <summary>
    /// Represents a security level manager that handles the configuration of
    /// security levels and provides the necessary Mersenne prime for secure computations.
    /// </summary>
    private readonly ISecurityLevelManager<TNumber> securityLevelManager;

    /// <summary>
    /// Initializes a new instance of the <see cref="SecretReconstructor{TNumber, TExtendedGcdAlgorithm, TExtendedGcdResult}"/> class.
    /// </summary>
    /// <param name="extendedGcd">Extended greatest common divisor algorithm</param>
    /// <exception cref="T:System.ArgumentNullException">The <paramref name="extendedGcd"/> parameter is <see langword="null"/>.</exception>
    public SecretReconstructor(TExtendedGcdAlgorithm extendedGcd)
    {
        this.extendedGcd = extendedGcd ?? throw new ArgumentNullException(nameof(extendedGcd));
        this.securityLevelManager = new SecurityLevelManager<TNumber>();
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="SecretReconstructor{TNumber, TExtendedGcdResult, TExtendedGcdResult}"/> class.
    /// </summary>
    /// <param name="extendedGcd">Extended greatest common divisor algorithm</param>
    /// <param name="securityLevelManager">Manages security level configuration</param>
    /// <exception cref="T:System.ArgumentNullException">The <paramref name="extendedGcd"/> parameter is <see langword="null"/>.</exception>
    public SecretReconstructor(TExtendedGcdAlgorithm extendedGcd, ISecurityLevelManager<TNumber> securityLevelManager)
    {
        this.extendedGcd = extendedGcd ?? throw new ArgumentNullException(nameof(extendedGcd));
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
    /// Find the y-value for the given x, given n (x, y) points;
    /// k points will define a polynomial of up to kth order
    /// </summary>
    /// <param name="finitePoints">The shares represented by a set of <see cref="FinitePoint{TNumber}"/>.</param>
    /// <param name="prime">A prime number must be defined to avoid computation with real numbers. In fact, it is finite field arithmetic.
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

        this.securityLevelManager.AdjustSecurityLevel(maximumY);
        return this.LagrangeInterpolate(shares, this.securityLevelManager.MersennePrime);
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
}