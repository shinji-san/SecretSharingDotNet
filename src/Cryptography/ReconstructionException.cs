// ----------------------------------------------------------------------------
// <copyright file="ReconstructionException.cs" company="Private">
// Copyright (c) 2026 All Rights Reserved
// </copyright>
// <author>Sebastian Walther</author>
// <date>08/06/2026 00:00:00 AM</date>
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
#if !NET8_0_OR_GREATER
using System.Runtime.Serialization;
#endif

/// <summary>
/// The exception that is thrown when a secret cannot be reconstructed from a set of shares
/// that are individually well-formed — for example shares carrying duplicate indices, a set
/// with no usable maximum y-value, or a denominator that has no modular inverse in the
/// finite field (a zero or non-invertible denominator during Lagrange interpolation).
/// </summary>
/// <remarks>
/// Distinguishes a genuine reconstruction failure from caller misuse: passing fewer than two
/// shares or a <see langword="null"/> share collection remains an argument error and throws
/// from the <see cref="ArgumentException"/> family instead.
/// </remarks>
[Serializable]
public class ReconstructionException : SecretSharingException
{
    /// <summary>
    /// Initializes a new instance of the <see cref="ReconstructionException"/> class.
    /// </summary>
    public ReconstructionException()
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="ReconstructionException"/> class with a
    /// specified error message.
    /// </summary>
    /// <param name="message">The message that describes the error.</param>
    public ReconstructionException(string message)
        : base(message)
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="ReconstructionException"/> class with a
    /// specified error message and a reference to the inner exception that is the cause of
    /// this exception.
    /// </summary>
    /// <param name="message">The message that describes the error.</param>
    /// <param name="innerException">
    /// The exception that is the cause of the current exception, or <see langword="null"/> if
    /// no inner exception is specified.
    /// </param>
    public ReconstructionException(string message, Exception innerException)
        : base(message, innerException)
    {
    }

#if !NET8_0_OR_GREATER
    /// <summary>
    /// Initializes a new instance of the <see cref="ReconstructionException"/> class with
    /// serialized data.
    /// </summary>
    /// <param name="info">
    /// The <see cref="SerializationInfo"/> that holds the serialized object data about the
    /// exception being thrown.
    /// </param>
    /// <param name="context">
    /// The <see cref="StreamingContext"/> that contains contextual information about the
    /// source or destination.
    /// </param>
    protected ReconstructionException(SerializationInfo info, StreamingContext context)
        : base(info, context)
    {
    }
#endif
}
