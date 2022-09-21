// ----------------------------------------------------------------------------
// <copyright file="Secret.cs" company="Private">
// Copyright (c) 2022 All Rights Reserved
// </copyright>
// <author>Sebastian Walther</author>
// <date>09/22/2022 00:34:47 AM</date>
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
    using Helper;
    using Math;
    using System;
    using System.Linq;
    using System.Security.Cryptography;
    using System.Threading;

    /// <summary>
    /// This class represents the secret including members to parse or convert it.
    /// </summary>
    public class Secret
    {
        /// <summary>
        /// Gets or sets the legacy mode on (<see langword="true"/>) or <see langword="off"/> to be compatible with
        /// v0.6.0 or older.
        /// </summary>
        public static readonly ThreadLocal<bool> LegacyMode = new ThreadLocal<bool> {Value = false};

        /// <summary>
        /// Maximum mark byte to terminate the secret array and to avoid negative secret values.
        /// </summary>
        /// <remarks>prime number greater than 2^13-1</remarks>
        protected const byte MaxMarkByte = 0x7F;

        /// <summary>
        /// Minimum mark byte to terminate the secret array and to avoid negative secret values.
        /// </summary>
        /// <remarks>prime number equal to 2^13-1</remarks>
        protected const byte MinMarkByte = 0x1F;

        /// <summary>
        /// Create <see cref="Secret{TNumber}"/> from a0 coefficient
        /// </summary>
        /// <typeparam name="TNumber"></typeparam>
        /// <param name="coefficient">a0 coefficient</param>
        /// <returns>A <see cref="Secret{TNumber}"/></returns>
        internal static Secret<TNumber> FromCoefficient<TNumber>(Calculator<TNumber> coefficient) =>
            new Secret<TNumber>(coefficient.ByteRepresentation.Take(coefficient.ByteCount - MarkByteCount).ToArray());

        /// <summary>
        /// Creates a random secret
        /// </summary>
        /// <param name="prime">mersenne prime number</param>
        /// <remarks>Use this ctor to create a random secret</remarks>
        internal static Secret<TNumber> CreateRandom<TNumber>(Calculator<TNumber> prime)
        {
            byte[] randomSecretBytes = new byte[prime.ByteCount];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(randomSecretBytes);
            }

            if (LegacyMode.Value)
            {
                return (Calculator.Create(randomSecretBytes, typeof(TNumber)) as Calculator<TNumber>)?.Abs() % prime;
            }

            int i = randomSecretBytes.Length - 1;
            while (i > 0)
            {
                randomSecretBytes[i] = i == 1 ? MinMarkByte : MaxMarkByte;
                var randomSecretNumber = Calculator.Create(randomSecretBytes, typeof(TNumber)) as Calculator<TNumber>;
                var a0 = randomSecretNumber?.Abs() % prime;
                if (a0 == randomSecretNumber)
                {
                    break;
                }

                if (a0.IsZero)
                {
                    return new Secret<TNumber>(new byte[] {0x00});
                }

                randomSecretBytes[i--] = 0x00;
            }

            return new Secret<TNumber>(randomSecretBytes.Subset(0, randomSecretBytes.Length - (randomSecretBytes.Length - i)));
        }

        /// <summary>
        /// Gets the MarkByte count in dependency of the <see cref="LegacyMode"/>.
        /// </summary>
        protected static int MarkByteCount => LegacyMode.Value ? 0 : 1;

        /// <summary>
        /// Creates an array from a base64 string as in version 0.6.0 or older
        /// </summary>
        protected static readonly Func<string, byte[]> FromBase64Legacy = base64 =>
        {
            var bytes = Convert.FromBase64String(base64).ToList();
            bytes.Insert(0, 0x00);
            bytes.Add(0x78);
            return bytes.ToArray();
        };
    }
}
