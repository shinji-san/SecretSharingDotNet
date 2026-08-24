// ----------------------------------------------------------------------------
// <copyright file="PublicValueEqualityComparer`1.cs" company="Private">
// Copyright (c) 2026 All Rights Reserved
// </copyright>
// <author>Sebastian Walther</author>
// <date>07/12/2026 12:00:00 PM</date>
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

namespace SecretSharingDotNet.Cryptography.ShamirsSecretSharing;

using System.Collections.Generic;
using Math;

/// <summary>
/// An <see cref="IEqualityComparer{T}"/> over <see cref="Calculator{TNumber}"/> that hashes the
/// <b>public</b> value via <see cref="Calculator.ByteRepresentation"/>. Intended for
/// de-duplicating public quantities — specifically the share indices in the reconstruction
/// distinctness check.
/// </summary>
/// <typeparam name="TNumber">The mathematical type wrapped by the compared calculators.</typeparam>
/// <remarks>
/// <para>
/// Use this comparer <b>only</b> for public keys, never for secret-bearing values.
/// <see cref="Calculator{TNumber}.GetHashCode"/> delegates to <c>TNumber.GetHashCode</c>, and the
/// <c>SecureBigInteger</c> backend deliberately hashes only public metadata (sign and limb count)
/// so that a value-derived hash of <em>secret</em> material cannot be observed. That hardening
/// makes every small positive one-limb value hash identically, which would collapse the share-index
/// distinctness <see cref="HashSet{T}"/> in <see cref="SecretReconstructor{TNumber}"/> into a single
/// bucket and turn an O(n) check into O(n²).
/// </para>
/// <para>
/// Share indices are public (the X coordinate, carried in the <c>"INDEX-VALUE"</c> wire format and
/// assigned as small positive integers by the splitter), so hashing their value discloses nothing
/// the wire format does not already expose. This comparer therefore restores an O(n) distinctness
/// check <em>without</em> weakening the secret-hash hardening on
/// <see cref="Calculator{TNumber}.GetHashCode"/> itself. The public bytes are read through
/// <see cref="Calculator.ByteRepresentation"/> — the same public-value byte access used by
/// <see cref="MersenneSafeGcdAlgorithm{TNumber}"/> — and the freshly allocated buffer is disposed.
/// Equality delegates to the fixed-time <see cref="Calculator{TNumber}.Equals(Calculator{TNumber})"/>.
/// </para>
/// </remarks>
internal sealed class PublicValueEqualityComparer<TNumber> : IEqualityComparer<Calculator<TNumber>>
{
    /// <summary>
    /// The shared, stateless comparer instance.
    /// </summary>
    internal static readonly PublicValueEqualityComparer<TNumber> Instance = new PublicValueEqualityComparer<TNumber>();

    /// <summary>
    /// Initializes a new instance of the <see cref="PublicValueEqualityComparer{TNumber}"/> class.
    /// </summary>
    private PublicValueEqualityComparer()
    {
    }

    /// <summary>
    /// Determines whether two calculators wrap the same value.
    /// </summary>
    /// <param name="x">The first calculator to compare.</param>
    /// <param name="y">The second calculator to compare.</param>
    /// <returns>
    /// <see langword="true"/> when both are the same reference, both <see langword="null"/>, or wrap
    /// equal values; otherwise <see langword="false"/>.
    /// </returns>
    public bool Equals(Calculator<TNumber> x, Calculator<TNumber> y)
    {
        if (ReferenceEquals(x, y))
        {
            return true;
        }

        if (x is null || y is null)
        {
            return false;
        }

        return x.Equals(y);
    }

    /// <summary>
    /// Computes a value-derived hash of the calculator's <b>public</b> byte representation.
    /// </summary>
    /// <param name="obj">
    /// The calculator whose public value is hashed. Must wrap a public quantity (e.g. a share index),
    /// never secret material.
    /// </param>
    /// <returns>A hash code that discriminates distinct public values.</returns>
    public int GetHashCode(Calculator<TNumber> obj)
    {
        if (obj is null)
        {
            return 0;
        }

        using var bytes = obj.ByteRepresentation;
        int length = bytes.Length;
#if NETSTANDARD2_1_OR_GREATER || NET8_0_OR_GREATER
        var hash = new System.HashCode();
        for (int i = 0; i < length; i++)
        {
            hash.Add(bytes[i]);
        }

        return hash.ToHashCode();
#else
        unchecked
        {
            int hash = 17;
            for (int i = 0; i < length; i++)
            {
                hash = (hash * 31) + bytes[i];
            }

            return hash;
        }
#endif
    }
}
