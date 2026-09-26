// ----------------------------------------------------------------------------
// <copyright file="ShareFormatValidation.cs" company="Private">
// Copyright (c) 2026 All Rights Reserved
// </copyright>
// <author>Sebastian Walther</author>
// <date>09/16/2026 09:00:00 AM</date>
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
/// Guards the one rule about which <see cref="ShareFormat"/> values exist.
/// </summary>
/// <remarks>
/// A single place on purpose. Every entry point that takes a format has to reject an undefined
/// one, and restating the comparison at each of them is the shape that lets one entry point drift
/// — which is exactly how an empty collection came to accept a cast integer while a populated one
/// refused it.
/// </remarks>
internal static class ShareFormatValidation
{
    /// <summary>
    /// Throws when <paramref name="format"/> is not a defined <see cref="ShareFormat"/> value.
    /// </summary>
    /// <param name="format">The value to check.</param>
    /// <param name="paramName">The parameter name to report.</param>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="format"/> is undefined.</exception>
    internal static void EnsureDefined(ShareFormat format, string paramName)
    {
        if (format != ShareFormat.Legacy && format != ShareFormat.Extended)
        {
            throw new ArgumentOutOfRangeException(paramName, format, null);
        }
    }
}
