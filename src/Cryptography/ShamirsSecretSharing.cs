// ----------------------------------------------------------------------------
// <copyright file="ShamirsSecretSharing.cs" company="Private">
// Copyright (c) 2022 All Rights Reserved
// </copyright>
// <author>Sebastian Walther</author>
// <date>04/20/2019 10:52:28 PM</date>
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

namespace SecretSharingDotNet.Cryptography
{
    using Math;
    using System;
    using System.Collections.Concurrent;
    using System.Collections.Generic;
    using System.Linq;
    using System.Security.Cryptography;
    using System.Threading.Tasks;

    /// <summary>
    /// Shamir's secret sharing algorithm
    /// </summary>
    /// <typeparam name="TNumber">Numeric data type</typeparam>
    public class ShamirsSecretSharing<TNumber>
    {
        /// <summary>
        /// Saves the known security levels (Mersenne prime exponents)
        /// </summary>
        private readonly List<int> securityLevels = new List<int>(new[]
        {
            5, 7, 13, 17, 19, 31, 61, 89, 107, 127, 521, 607, 1279, 2203, 2281, 3217, 4253, 4423, 9689, 9941, 11213,
            19937, 21701, 23209, 44497, 86243, 110503, 132049, 216091, 756839, 859433, 1257787, 1398269, 2976221,
            3021377, 6972593, 13466917, 20996011, 24036583, 25964951, 30402457, 32582657, 37156667, 42643801, 43112609
        });

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
        private readonly IExtendedGcdAlgorithm<TNumber> extendedGcd;

        /// <summary>
        /// Initializes a new instance of the <see cref="ShamirsSecretSharing{TNumber}"/> class.
        /// </summary>
        /// <param name="extendedGcd">Extended greatest common divisor algorithm</param>
        /// <exception cref="T:System.ArgumentNullException">The <paramref name="extendedGcd"/> parameter is <see langword="null"/>.</exception>
        public ShamirsSecretSharing(IExtendedGcdAlgorithm<TNumber> extendedGcd)
        {
            this.extendedGcd = extendedGcd ?? throw new ArgumentNullException(nameof(extendedGcd));
            this.SecurityLevel = 13;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="ShamirsSecretSharing{TNumber}"/> class.
        /// </summary>
        /// <param name="extendedGcd">Extended greatest common divisor algorithm</param>
        /// <param name="securityLevel">Security level (in number of bits). Minimum is 5 for legacy mode and 13 for normal mode.</param>
        /// <exception cref="T:System.ArgumentOutOfRangeException">The security level is lower than 5 or greater than 43112609.</exception>
        [Obsolete("Will be removed in future versions. Please use one of the overloads of the method MakeShares.", false)]
        public ShamirsSecretSharing(IExtendedGcdAlgorithm<TNumber> extendedGcd, int securityLevel)
        {
            this.extendedGcd = extendedGcd ?? throw new ArgumentNullException(nameof(extendedGcd));
            try
            {
                this.SecurityLevel = securityLevel;
            }
            catch (ArgumentOutOfRangeException e)
            {
                throw new ArgumentOutOfRangeException(nameof(securityLevel), securityLevel, e.Message);
            }
        }

        /// <summary>
        /// Gets or sets the security level
        /// </summary>
        /// <remarks>Value is lower than 5 or greater than 43112609.</remarks>
        /// <exception cref="T:System.ArgumentOutOfRangeException" accessor="set">Value is lower than 5 or greater than 43112609.</exception>
        public int SecurityLevel
        {
            get => this.fixedSecurityLevel;

            set
            {
                if (value < 5)
                {
                    throw new ArgumentOutOfRangeException(nameof(value), value, ErrorMessages.MinimumSecurityLevelExceeded);
                }

                if (!Secret.LegacyMode.Value && value < 13)
                {
                    value = 13;
                }

                int index = this.securityLevels.BinarySearch(value);
                if (index < 0)
                {
                    try
                    {
                        value = this.securityLevels.ElementAt(~index);
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
        /// <param name="securityLevel">Security level (in number of bits). Minimum is 5 for legacy mode and 13 for normal mode.</param>
        /// <returns></returns>
        /// <exception cref="T:System.ArgumentOutOfRangeException">The <paramref name="securityLevel"/> parameter is lower than 5 or greater than 43112609. OR The <paramref name="numberOfMinimumShares"/> parameter is lower than 2 or greater than <paramref name="numberOfShares"/>.</exception>
        public Shares<TNumber> MakeShares(TNumber numberOfMinimumShares, TNumber numberOfShares, int securityLevel)
        {
            Calculator<TNumber> min = numberOfMinimumShares;
            Calculator<TNumber> max = numberOfShares;
            try
            {
                this.SecurityLevel = securityLevel;
            }
            catch (ArgumentOutOfRangeException e)
            {
                throw new ArgumentOutOfRangeException(nameof(securityLevel), securityLevel, e.Message);
            }

            return this.MakeShares(numberOfMinimumShares, numberOfShares);
        }

        /// <summary>
        /// Generates a random shamir pool, returns the random secret and the share points.
        /// </summary>
        /// <param name="numberOfMinimumShares">Minimum number of shared secrets for reconstruction</param>
        /// <param name="numberOfShares">Maximum number of shared secrets</param>
        /// <returns></returns>
        /// <exception cref="T:System.ArgumentOutOfRangeException">The <paramref name="numberOfMinimumShares"/> parameter is lower than 2 or greater than <paramref name="numberOfShares"/>.</exception>
        /// <exception cref="T:System.InvalidOperationException">Security Level is not initialized!</exception>
        [Obsolete("Will be removed in future versions. Please use the method MakeShares(TNumber numberOfMinimumShares, TNumber numberOfShares, int securityLevel).", false)]
        public Shares<TNumber> MakeShares(TNumber numberOfMinimumShares, TNumber numberOfShares)
        {
            Calculator<TNumber> min = numberOfMinimumShares;
            Calculator<TNumber> max = numberOfShares;
            if (min < Calculator<TNumber>.Two)
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

            var secret = Secret.CreateRandom(this.mersennePrime);
            var polynomial = CreatePolynomial(min);
            polynomial[0] = secret.ToCoefficient;
            var points = CreateSharedSecrets(max, polynomial);
            return new Shares<TNumber>(secret, points);
        }

        /// <summary>
        /// Generates a random shamir pool, returns the specified <paramref name="secret"/> and the share points.
        /// </summary>
        /// <param name="numberOfMinimumShares">Minimum number of shared secrets for reconstruction</param>
        /// <param name="numberOfShares">Maximum number of shared secrets</param>
        /// <param name="secret">secret text as <see cref="Secret{TNumber}"/> or see cref="string"/></param>
        /// <param name="securityLevel">Security level (in number of bits). Minimum is 5 for legacy mode and 13 for normal mode.</param>
        /// <returns></returns>
        /// <remarks>This method can modify the <see cref="SecurityLevel"/> based on the <paramref name="secret"/> length.</remarks>
        /// <exception cref="T:System.ArgumentNullException">The <paramref name="secret"/> parameter is <see langword="null"/>.</exception>
        /// <exception cref="T:System.ArgumentOutOfRangeException">The <paramref name="securityLevel"/> is lower than 5 or greater than 43112609. OR <paramref name="numberOfMinimumShares"/> is lower than 2 or greater than <paramref name="numberOfShares"/>.</exception>
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
        /// <exception cref="T:System.ArgumentNullException"><paramref name="secret"/> is <see langword="null"/>.</exception>
        /// <exception cref="T:System.ArgumentOutOfRangeException"><paramref name="numberOfMinimumShares"/> is lower than 2 or greater than <paramref name="numberOfShares"/>.</exception>
        public Shares<TNumber> MakeShares(TNumber numberOfMinimumShares, TNumber numberOfShares, Secret<TNumber> secret)
        {
            if (secret is null)
            {
                throw new ArgumentNullException(nameof(secret));
            }

            Calculator<TNumber> min = numberOfMinimumShares;
            Calculator<TNumber> max = numberOfShares;
            if (min < Calculator<TNumber>.Two)
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

            var polynomial = CreatePolynomial(min);
            polynomial[0] = secret.ToCoefficient;
            var points = CreateSharedSecrets(max, polynomial);

            return new Shares<TNumber>(secret, points);
        }

        /// <summary>
        /// Creates a polynomial
        /// </summary>
        /// <param name="numberOfMinimumShares">Minimum number of shared secrets for reconstruction</param>
        /// <returns></returns>
        private List<Calculator<TNumber>> CreatePolynomial(Calculator<TNumber> numberOfMinimumShares)
        {
            var polynomial = new List<Calculator<TNumber>>() { Calculator<TNumber>.Zero };
            var randomNumber = new byte[this.mersennePrime.ByteCount];
            using (var rng = RandomNumberGenerator.Create())
            {
                for (var i = Calculator<TNumber>.One; i < numberOfMinimumShares; i++)
                {
                    rng.GetBytes(randomNumber);
                    polynomial.Add((Calculator.Create(randomNumber, typeof(TNumber)) as Calculator<TNumber>)?.Abs() % this.mersennePrime);
                }
            }

            return polynomial;
        }

        /// <summary>
        /// Creates shared Secrets
        /// </summary>
        /// <param name="numberOfShares">Maximum number of shared secrets</param>
        /// <param name="polynomial"></param>
        /// <returns>A list of finite points representing the shared secrets</returns>
        private List<FinitePoint<TNumber>> CreateSharedSecrets(Calculator<TNumber> numberOfShares, ICollection<Calculator<TNumber>> polynomial)
        {
            var points = new List<FinitePoint<TNumber>>(); //// pre-init
            for (var i = Calculator<TNumber>.One; i < numberOfShares + Calculator<TNumber>.One; i++)
            {
                points.Add(new FinitePoint<TNumber>(i, polynomial, this.mersennePrime));
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
        private static Calculator<TNumber> Product(IEnumerable<Calculator<TNumber>> values)
        {
            return values.Aggregate(Calculator<TNumber>.One, (current, v) => current * v);
        }

        /// <summary>
        /// Find the y-value for the given x, given n (x, y) points;
        /// k points will define a polynomial of up to kth order
        /// </summary>
        /// <param name="finitePoints"></param>
        /// <param name="prime">A prime number must be defined to avoid computation with real numbers. In fact it is finite field arithmetic.
        /// The prime number must be the same as used for the construction of shares.</param>
        /// <returns>The re-constructed secret.</returns>
        private Secret<TNumber> LagrangeInterpolate(List<FinitePoint<TNumber>> finitePoints, Calculator<TNumber> prime)
        {
            if (finitePoints.Distinct().Count() != finitePoints.Count)
            {
                throw new ArgumentException(ErrorMessages.FinitePointsNotDistinct, nameof(finitePoints));
            }

            int k = finitePoints.Count;
            var numerators = new List<Calculator<TNumber>>(k - 1);
            var denominators = new List<Calculator<TNumber>>(k - 1);
            for (int i = 0; i < k; i++)
            {
                var others = new List<FinitePoint<TNumber>>(finitePoints.ToArray());
                var current = others[i];
                others.RemoveAt(i);
                var numTask = Task.Run(() =>
                {
                    return Product(others.AsParallel().Select(o => Calculator<TNumber>.Zero - o.X).ToList());
                });

                var denTask = Task.Run(() =>
                {
                    return Product(others.AsParallel().Select(o => current.X - o.X).ToList());
                });

                numerators.Add(numTask.Result);
                denominators.Add(denTask.Result);
            }

            var numerator = Calculator<TNumber>.Zero;
            var denominator = Product(denominators);

            object sync = new object();
            var rangePartitioner = Partitioner.Create(0, k);
            Parallel.ForEach(rangePartitioner, (range, _) =>
            {
                for (int i = range.Item1; i < range.Item2; i++)
                {
                    var result = this.DivMod(numerators[i] * denominator * ((finitePoints[i].Y % prime + prime) % prime), denominators[i], prime);
                    lock (sync)
                    {
                        numerator += result;
                    }
                }
            });

            var a = this.DivMod(numerator, denominator, prime) + prime;
            a = (a % prime + prime) % prime; //// mathematical modulo
            return Secret.FromCoefficient(a);
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
        /// <param name="shares">two or more shares</param>
        /// <returns>Re-constructed secret</returns>
        /// <exception cref="T:System.ArgumentNullException"><paramref name="shares"/> is <see langword="null"/>.</exception>
        /// <exception cref="T:System.ArgumentOutOfRangeException">The length of <paramref name="shares"/> is lower than 2.</exception>
        public Secret<TNumber> Reconstruction(params FinitePoint<TNumber>[] shares)
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
            this.SecurityLevel = maximumY.ByteCount * 8;
            var index = this.securityLevels.IndexOf(this.SecurityLevel);
            while ((maximumY % this.mersennePrime + this.mersennePrime) % this.mersennePrime == maximumY && index > 0 && this.SecurityLevel > 5)
            {
                this.SecurityLevel = this.securityLevels[--index];
            }

            this.SecurityLevel = this.securityLevels[this.SecurityLevel > 5 ? ++index : index];
            return this.LagrangeInterpolate(new List<FinitePoint<TNumber>>(shares), this.mersennePrime);
        }
    }
}
