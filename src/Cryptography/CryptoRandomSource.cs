// ----------------------------------------------------------------------------
// <copyright file="CryptoRandomSource.cs" company="Private">
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

/// <summary>
/// Default <see cref="IRandomSource"/> implementation. Forwards every draw to the
/// cryptographically secure <see cref="SecureRandom"/> helper.
/// </summary>
/// <remarks>
/// The type is stateless and immutable, so a single shared <see cref="Instance"/> backs every
/// production draw throughout the library (no per-consumer allocation). Being stateless, it is
/// safe for concurrent use — it delegates to the thread-safe
/// <see cref="System.Security.Cryptography.RandomNumberGenerator"/> via <see cref="SecureRandom"/>.
/// </remarks>
internal sealed class CryptoRandomSource : IRandomSource
{
    /// <summary>
    /// The shared, stateless instance used as the default random source throughout the library.
    /// </summary>
    internal static readonly IRandomSource Instance = new CryptoRandomSource();

    /// <summary>
    /// Prevents external instantiation; consumers use <see cref="Instance"/>.
    /// </summary>
    private CryptoRandomSource()
    {
    }

    /// <inheritdoc/>
    public void Fill(byte[] buffer, int offset, int count)
    {
        SecureRandom.Fill(buffer, offset, count);
    }

    /// <inheritdoc/>
    public int NextInt32(int fromInclusive, int toExclusive)
    {
        return SecureRandom.NextInt32(fromInclusive, toExclusive);
    }
}
