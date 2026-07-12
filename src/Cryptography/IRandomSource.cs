// ----------------------------------------------------------------------------
// <copyright file="IRandomSource.cs" company="Private">
// Copyright (c) 2026 All Rights Reserved
// </copyright>
// <author>Sebastian Walther</author>
// <date>07/10/2026 00:00:00 AM</date>
// ----------------------------------------------------------------------------

#region License
// ----------------------------------------------------------------------------
// Copyright 2026 Sebastian Walther
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

using System;

/// <summary>
/// Abstraction over the random primitives consumed by the secret-sharing pipeline
/// (random secret generation, polynomial coefficients, and the termination byte).
/// </summary>
/// <remarks>
/// <para>
/// The default implementation is <see cref="CryptoRandomSource"/>, which delegates to the
/// cryptographically secure <see cref="SecureRandom"/> helper. The seam exists so that tests
/// can substitute a deterministic source; it is deliberately <see langword="internal"/> — a
/// production <see cref="Secret{TNumber}"/> or
/// <see cref="ShamirsSecretSharing.SecretSplitter{TNumber}"/> must be backed by a
/// cryptographically secure generator, because a weak or seeded source undermines the secrecy
/// of Shamir's scheme.
/// </para>
/// <para>
/// <b>Thread safety:</b> an implementation used to back a <see cref="Secret{TNumber}"/> or
/// <see cref="ShamirsSecretSharing.SecretSplitter{TNumber}"/> instance that is shared across
/// threads must be safe for concurrent use. The default <see cref="CryptoRandomSource"/>
/// satisfies this: it is stateless and delegates to the thread-safe
/// <see cref="System.Security.Cryptography.RandomNumberGenerator"/>.
/// </para>
/// </remarks>
internal interface IRandomSource
{
    /// <summary>
    /// Fills <paramref name="count"/> bytes of <paramref name="buffer"/> starting at
    /// <paramref name="offset"/> with random data.
    /// </summary>
    /// <param name="buffer">The destination buffer.</param>
    /// <param name="offset">The offset into <paramref name="buffer"/> at which to start writing.</param>
    /// <param name="count">The number of bytes to write.</param>
    /// <exception cref="ArgumentNullException"><paramref name="buffer"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentOutOfRangeException">
    /// <paramref name="offset"/> or <paramref name="count"/> is negative, or the requested range
    /// would extend past the end of <paramref name="buffer"/>.
    /// </exception>
    void Fill(byte[] buffer, int offset, int count);

    /// <summary>
    /// Returns a uniform random integer in
    /// <c>[<paramref name="fromInclusive"/>, <paramref name="toExclusive"/>)</c>.
    /// </summary>
    /// <param name="fromInclusive">Inclusive lower bound of the result.</param>
    /// <param name="toExclusive">Exclusive upper bound of the result. Must be greater than <paramref name="fromInclusive"/>.</param>
    /// <returns>A uniformly distributed integer in the requested range.</returns>
    /// <exception cref="ArgumentOutOfRangeException">
    /// <paramref name="toExclusive"/> is not greater than <paramref name="fromInclusive"/>.
    /// </exception>
    int NextInt32(int fromInclusive, int toExclusive);
}
