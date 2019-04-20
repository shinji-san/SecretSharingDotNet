// ----------------------------------------------------------------------------
// <copyright file="ShamirsSecretSharing.cs" company="Private">
// Copyright (c) 2019 All Rights Reserved
// </copyright>
// <author>Sebastian Walther</author>
// <date>04/20/2019 10:52:28 PM</date>
// ----------------------------------------------------------------------------

#region License
// ----------------------------------------------------------------------------
// Copyright 2019 Sebastian Walther
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
    using System.Collections.Concurrent;
    using System.Collections.Generic;
    using System.Linq;
    using System.Security.Cryptography;
    using System.Threading.Tasks;
    using System;
    using Math;

    /// <summary>
    /// Shamir's secret sharing algorithm
    /// </summary>
    /// <typeparam name="TNumber">Numeric data type</typeparam>
    public class ShamirsSecretSharing<TNumber>
    {
        /// <summary>
        /// Saves the known security levels (Mersenne prime exponents)
        /// </summary>
        private readonly List<int> securityLevels = new List<int> (new int[] { 5, 7, 13, 17, 19, 31, 61, 89, 107, 127, 521, 607, 1279, 2203, 2281, 3217 });

        /// <summary>
        /// Saves security level
        /// </summary>
        private Calculator<TNumber> securityLevel;

        /// <summary>
        /// Saves the extended greatest common divisor algorithm
        /// </summary>
        private readonly IExtendedGcdAlgorithm<TNumber> extendedGcd;

        /// <summary>
        /// Initializes a new instance of the <see cref="ShamirsSecretSharing"/> class.
        /// </summary>
        /// <param name="extendedGcd">Extended greatest common divisor algorithm</param>
        /// <param name="securityLevel">Security level (in number of bits). Minimum is 5.</param>
        public ShamirsSecretSharing (IExtendedGcdAlgorithm<TNumber> extendedGcd, int securityLevel)
        {
            if (extendedGcd == null)
            {
                throw new ArgumentNullException (nameof (extendedGcd));
            }

            this.extendedGcd = extendedGcd;
            try
            {
                this.SecurityLevel = securityLevel;
            }
            catch (ArgumentOutOfRangeException e)
            {
                throw new ArgumentOutOfRangeException (nameof (securityLevel), securityLevel, e.Message);
            }
        }

        /// <summary>
        /// Sets the security level
        /// </summary>
        public int SecurityLevel
        {
            set
            {
                if (value < 5)
                {
                    throw new ArgumentOutOfRangeException (nameof (value), value, "Minimum exceeded!");
                }

                int index = this.securityLevels.BinarySearch (value);
                if (index < 0)
                {
                    try
                    {
                        value = this.securityLevels.ElementAt (~index);
                    }
                    catch (ArgumentOutOfRangeException)
                    {
                        throw new ArgumentOutOfRangeException (nameof (value), value, "Maximum exceeded!");
                    }
                }

                try
                {
                    this.securityLevel = Calculator<TNumber>.Two.Pow (value) - Calculator<TNumber>.One;
                }
                catch (NotSupportedException e)
                {
                    Console.WriteLine (e);
                    throw;
                }
            }
        }

        /// <summary>
        /// Generates a random shamir pool, returns the random secret and the share points.
        /// </summary>
        /// <param name="numberOfMinimumShares">Minimum number of shared secrets for reconstruction</param>
        /// <param name="numberOfShares">Maximum number of shared secrets</param>
        /// <returns></returns>
        public Tuple<Secret<TNumber>, ICollection<FinitePoint<TNumber>>> MakeShares (TNumber numberOfMinimumShares, TNumber numberOfShares)
        {
            Calculator<TNumber> min = numberOfMinimumShares;
            Calculator<TNumber> shrs = numberOfShares;
            if (min < Calculator<TNumber>.Two)
            {
                throw new ArgumentOutOfRangeException (nameof (numberOfMinimumShares));
            }

            if (min > shrs)
            {
                throw new ArgumentOutOfRangeException ("The pool secret would be irrecoverable.");
            }

            var polynomial = CreatePolynomial (min);
            var points = CreateSharedSecrets (shrs, polynomial);

            return new Tuple<Secret<TNumber>, ICollection<FinitePoint<TNumber>>> (polynomial[0], points);
        }

        /// <summary>
        /// Generates a random shamir pool, returns the specified <paramref name="secret"/> and the share points.
        /// </summary>
        /// <param name="numberOfMinimumShares">Minimum number of shared secrets for reconstruction</param>
        /// <param name="numberOfShares">Maximum number of shared secrets</param>
        /// <param name="secret">secret text as <see cref="Secret{TNumber}"/> or see cref="string"/></param>
        /// <returns></returns>
        /// <remarks>This method modifies the <see cref="SecurityLevel"/> based on the <paramref name="secret"/> length</remarks>
        public Tuple<Secret<TNumber>, ICollection<FinitePoint<TNumber>>> MakeShares (TNumber numberOfMinimumShares, TNumber numberOfShares, Secret<TNumber> secret)
        {
            if (ReferenceEquals(secret, null))
            {
                throw new ArgumentNullException(nameof(secret));
            }

            Calculator<TNumber> min = numberOfMinimumShares;
            Calculator<TNumber> shrs = numberOfShares;
            if (min < Calculator<TNumber>.Two)
            {
                throw new ArgumentOutOfRangeException (nameof (numberOfMinimumShares));
            }

            if (min > shrs)
            {
                throw new ArgumentOutOfRangeException ("The pool secret would be irrecoverable.");
            }

            var polynomial = CreatePolynomial (min);
            this.SecurityLevel = secret.ToString ().Length * sizeof (char) * 8;
            polynomial[0] = secret;
            var points = CreateSharedSecrets (shrs, polynomial);

            return new Tuple<Secret<TNumber>, ICollection<FinitePoint<TNumber>>> (polynomial[0], points);
        }

        /// <summary>
        /// Creates a polynomial
        /// </summary>
        /// <param name="numberOfMinimumShares">Minimum number of shared secrets for reconstruction</param>
        /// <returns></returns>
        private List<Calculator<TNumber>> CreatePolynomial (Calculator<TNumber> numberOfMinimumShares)
        {
            var polynomial = new List<Calculator<TNumber>> (); /// pre-init
            var randomNumber = new byte[this.securityLevel.ByteCount];
            using (RNGCryptoServiceProvider rngCsp = new RNGCryptoServiceProvider ())
            {
                for (var i = Calculator<TNumber>.Zero; i < numberOfMinimumShares; i++)
                {
                    rngCsp.GetBytes (randomNumber);
                    polynomial.Add (Calculator<TNumber>.Create (randomNumber).Abs () % this.securityLevel);
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
        private List<FinitePoint<TNumber>> CreateSharedSecrets (Calculator<TNumber> numberOfShares, List<Calculator<TNumber>> polynomial)
        {
            var points = new List<FinitePoint<TNumber>> (); /// pre-init
            for (var i = Calculator<TNumber>.One; i < (numberOfShares + Calculator<TNumber>.One); i++)
            {
                points.Add (new FinitePoint<TNumber> (i, polynomial, this.securityLevel));
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
        private Calculator<TNumber> DivMod (
            Calculator<TNumber> numerator,
            Calculator<TNumber> denominator,
            Calculator<TNumber> prime)
        {
            var result = this.extendedGcd.Compute (denominator, prime);
            return numerator * result.BezoutCoefficients[0] * result.GreatestCommonDivisor;
        }

        /// <summary>
        /// Computes the mathematical product of a series of <paramref name="values"/>
        /// </summary>
        /// <param name="values"></param>
        /// <returns></returns>
        /// <remarks>Helper method for LagrangeInterpolate</remarks>
        private static Calculator<TNumber> Product (IEnumerable<Calculator<TNumber>> values)
        {
            var accum = Calculator<TNumber>.One;
            foreach (var v in values)
            {
                accum *= v;
            }

            return accum;
        }

        /// <summary>
        /// Find the y-value for the given x, given n (x, y) points;
        /// k points will define a polynomial of up to kth order
        /// </summary>
        /// <param name="finitePoints"></param>
        /// <param name="prime">A prime number must be defined to avoid computation with real numbers. In fact it is finite field arithmetic.
        /// The prime number must be the same as used for the construction of shares.</param>
        /// <returns>The re-constructed secret.</returns>
        private Calculator<TNumber> LagrangeInterpolate (List<FinitePoint<TNumber>> finitePoints, Calculator<TNumber> prime)
        {
            if (finitePoints.Distinct ().Count () != finitePoints.Count)
            {
                throw new ArgumentException (nameof (finitePoints));
            }

            int k = finitePoints.Count;
            var numerators = new List<Calculator<TNumber>> (k - 1);
            var denominators = new List<Calculator<TNumber>> (k - 1);
            for (int i = 0; i < k; i++)
            {
                var others = new List<FinitePoint<TNumber>> (finitePoints.ToArray ());
                var current = others[i];
                others.RemoveAt (i);
                var numTask = Task<Calculator<TNumber>>.Run (() =>
                {
                    return Product (others.AsParallel ().Select (o => { return Calculator<TNumber>.Zero - o.X; }).ToList ());
                });

                var denTask = Task<Calculator<TNumber>>.Run (() =>
                {
                    return Product (others.AsParallel ().Select (o => { return current.X - o.X; }).ToList ());
                });

                numerators.Add (numTask.Result);
                denominators.Add (denTask.Result);
            }

            var numerator = Calculator<TNumber>.Zero;
            var denominator = Product (denominators);

            object sync = new object ();
            var rangePartitioner = Partitioner.Create (0, k);
            Parallel.ForEach (rangePartitioner, (range, loopState) =>
            {
                for (int i = range.Item1; i < range.Item2; i++)
                {
                    var result = this.DivMod (numerators[i] * denominator * (((finitePoints[i].Y % prime) + prime) % prime), denominators[i], prime);
                    lock (sync)
                    {
                        numerator += result;
                    }
                }
            });

            var a = this.DivMod (numerator, denominator, prime) + prime;
            return ((a % prime) + prime) % prime; /// mathematical modulo
        }

        /// <summary>
        /// Recovers the secret from the given <paramref name="shares"/> (points with x and y on the polynomial)
        /// </summary>
        /// <param name="shares">two or more shares</param>
        /// <returns>Re-constructed secret</returns>
        public Secret<TNumber> Reconstruction (params FinitePoint<TNumber>[] shares)
        {
            if (shares == null)
            {
                throw new ArgumentNullException (nameof (shares));
            }

            if (shares.Length < 2)
            {
                throw new ArgumentOutOfRangeException (nameof (shares));
            }

            return this.LagrangeInterpolate (new List<FinitePoint<TNumber>> (shares), this.securityLevel);
        }
    }
}