// ----------------------------------------------------------------------------
// <copyright file="BigIntegerExtensions.cs" company="Private">
// Copyright (c) 2026 All Rights Reserved
// </copyright>
// <author>Sebastian Walther</author>
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

namespace SecretSharingDotNetTest;

using System.Numerics;
using SecretSharingDotNet.Cryptography.SecureInput;
using SecretSharingDotNet.Math.Numerics;

/// <summary>
/// Test-only bridge helpers between <see cref="BigInteger"/> and
/// <see cref="SecureBigInteger"/>. Exists because the historical
/// <c>SecureBigInteger(string)</c> decimal constructor was removed in D3 of
/// the constant-time refactor. Tests that previously held large constants as
/// decimal string literals can keep those literals verbatim and route them
/// through <see cref="ToSecureBigInteger"/> instead of pre-computing hex
/// equivalents by hand.
/// </summary>
internal static class BigIntegerExtensions
{
    /// <summary>
    /// Converts a <see cref="BigInteger"/> into a <see cref="SecureBigInteger"/>
    /// via the canonical little-endian two's-complement byte bridge. Both
    /// <see cref="BigInteger.ToByteArray()"/> and
    /// <see cref="SecureBigInteger(byte[], int)"/> agree on that encoding, so
    /// sign is preserved end to end without a special case.
    /// </summary>
    public static SecureBigInteger ToSecureBigInteger(this BigInteger value)
    {
        using var pinned = value.ToPinnedSecureBytes();
        return new SecureBigInteger(pinned.PoolArray, pinned.Length);
    }

    /// <summary>
    /// Converts a <see cref="SecureBigInteger"/> back to a BCL
    /// <see cref="BigInteger"/> for cross-checking against authoritative
    /// reference computations in unit tests. Routes through
    /// <see cref="SecureBigInteger.ToByteArray"/>'s pinned LE two's-complement
    /// representation and the <c>ToBigIntegerUnprotected</c> reverse bridge,
    /// which intentionally surfaces the pinned-to-unpinned trade-off at the
    /// extension's name.
    /// </summary>
    public static BigInteger ToBigInteger(this SecureBigInteger value)
    {
        using var bytes = value.ToByteArray();
        return bytes.ToBigIntegerUnprotected();
    }
}