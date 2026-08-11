// ----------------------------------------------------------------------------
// <copyright file="Calculator.cs" company="Private">
// Copyright (c) 2022 All Rights Reserved
// </copyright>
// <author>Sebastian Walther</author>
// <date>08/20/2022 02:34:00 PM</date>
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

namespace SecretSharingDotNet.Math;

using SecureMemory;
using Numerics;
using System;
using System.Collections.Generic;
using System.Numerics;

/// <summary>
/// Non-generic base of the calculator strategy pattern that decouples Shamir's Secret
/// Sharing from the concrete numeric data type. Subtypes wire a specific backend such as
/// <see cref="System.Numerics.BigInteger"/> or
/// <see cref="Numerics.SecureBigInteger"/> in via <see cref="Calculator{TNumber}"/>.
/// </summary>
/// <remarks>
/// The base type intentionally carries no constant-time guarantees — those are a property
/// of the chosen <c>TNumber</c> backend in <see cref="Calculator{TNumber}"/>.
/// See the threat-model paragraph in <see cref="Calculator{TNumber}"/>'s class remarks for
/// the backend-conditional contract.
/// </remarks>
public abstract class Calculator : IDisposable
{
    /// <summary>
    /// Indicates whether resources used by the current instance of the <see cref="Calculator"/> class
    /// have been released.
    /// </summary>
    private bool disposed;

    /// <summary>
    /// Explicit registry of the in-tree numeric backends, keyed by their numeric data type.
    /// Replaces the former reflection-based subtype discovery: it carries no
    /// <c>System.Reflection</c> or <c>System.Linq.Expressions</c> dependency, so it is
    /// trimming- and NativeAOT-safe and free of static-initialisation-order fragility.
    /// New in-tree backends are added here; the registry is intentionally closed to
    /// external types.
    /// </summary>
    private static readonly IReadOnlyDictionary<Type, BackendRegistration> Backends =
        new Dictionary<Type, BackendRegistration>
        {
            [typeof(BigInteger)] = new BackendRegistration(
                (data, length) => new BigIntCalculator(data, length),
                (Func<BigInteger, Calculator<BigInteger>>)(value => new BigIntCalculator(value))),
            [typeof(SecureBigInteger)] = new BackendRegistration(
                (data, length) => new SecureBigIntCalculator(data, length),
                (Func<SecureBigInteger, Calculator<SecureBigInteger>>)(value => new SecureBigIntCalculator(value))),
        };

    /// <summary>
    /// Gets the length, in bytes, of the canonical two's-complement byte representation
    /// produced by <see cref="ByteRepresentation"/> — i.e. the magnitude byte count plus
    /// a trailing <c>0x00</c> sentinel when the value is non-negative and the magnitude's
    /// most-significant byte has its high bit set.
    /// </summary>
    /// <remarks>
    /// Backend implementations must uphold the invariant
    /// <c>ByteCount == ByteRepresentation.Length</c>. Callers such as
    /// <c>Share&lt;TNumber&gt;.GetCharCount</c> rely on this to size hex output without
    /// materialising the buffer.
    /// </remarks>
    public abstract int ByteCount { get; }

    /// <summary>
    /// Gets a freshly allocated <see cref="PinnedPoolArray{T}"/> containing the canonical
    /// two's-complement byte representation of this value.
    /// </summary>
    /// <remarks>
    /// Each access allocates a new buffer. The caller takes ownership and is responsible
    /// for disposing it — failing to dispose defers the underlying pool array's return
    /// to finalisation and (on pinned-memory backends) leaves plaintext reachable longer
    /// than necessary. The returned buffer's <c>Length</c> equals <see cref="ByteCount"/>.
    /// </remarks>
    public abstract PinnedPoolArray<byte> ByteRepresentation { get; }

    /// <summary>
    /// Gets a value indicating whether or not the current <see cref="Calculator"/> object is zero.
    /// </summary>
    public abstract bool IsZero { get; }

    /// <summary>
    /// Gets a value indicating whether or not the current <see cref="Calculator"/> object is one.
    /// </summary>
    public abstract bool IsOne { get; }

    /// <summary>
    /// Gets a value indicating whether or not the current <see cref="Calculator"/> object is an even number.
    /// </summary>
    public abstract bool IsEven { get; }

    /// <summary>
    /// Gets a number that indicates the sign (negative, positive, or zero) of the current <see cref="Calculator"/> object.
    /// </summary>
    public abstract int Sign { get; }

    /// <summary>
    /// Releases the resources used by the current instance of the <see cref="Calculator"/> class.
    /// </summary>
    public void Dispose()
    {
        this.Dispose(true);
        GC.SuppressFinalize(this);
    }

    /// <summary>
    /// Creates a new instance derived from the <see cref="Calculator"/> class for the
    /// requested <paramref name="numberType"/> backend.
    /// </summary>
    /// <param name="data">byte array representation of the <paramref name="numberType"/></param>
    /// <param name="length">Length of the byte array</param>
    /// <param name="numberType">Type of number</param>
    /// <returns>A <see cref="Calculator"/> instance bound to <paramref name="numberType"/>.</returns>
    /// <exception cref="System.Collections.Generic.KeyNotFoundException">
    /// <paramref name="numberType"/> is not a registered backend in this assembly. The generic
    /// <see cref="Create{TNumber}(byte[], int)"/> overload translates this to
    /// <see cref="NotSupportedException"/>; this base-class entry point intentionally surfaces
    /// the raw lookup failure for backend-lookup diagnostics.
    /// </exception>
    public static Calculator Create(byte[] data, int length, Type numberType) => Backends[numberType].FromBytes(data, length);

    /// <summary>
    /// Strongly-typed counterpart to <see cref="Create(byte[], int, Type)"/>. Resolves the backend
    /// constructor for <typeparamref name="TNumber"/> and verifies that the produced instance is
    /// assignable to <see cref="Calculator{TNumber}"/>; otherwise the orphaned instance is disposed
    /// and a <see cref="NotSupportedException"/> is thrown.
    /// </summary>
    /// <typeparam name="TNumber">Numeric backend type.</typeparam>
    /// <param name="data">byte array representation of <typeparamref name="TNumber"/></param>
    /// <param name="length">Length of the byte array</param>
    /// <returns>A <see cref="Calculator{TNumber}"/> instance bound to <typeparamref name="TNumber"/>.</returns>
    /// <remarks>
    /// Closes the leak-on-type-mismatch window of the
    /// <c>Calculator.Create(...) as Calculator&lt;TNumber&gt;</c> idiom: if a misregistered
    /// backend produces a <see cref="Calculator"/> subtype that is not assignable to
    /// <see cref="Calculator{TNumber}"/>, the original instance — which may hold pinned, security-
    /// sensitive buffers on the <see cref="Numerics.SecureBigInteger"/> backend — is disposed
    /// before the exception escapes.
    /// </remarks>
    /// <exception cref="NotSupportedException">
    /// The registered backend for <typeparamref name="TNumber"/> is not assignable to
    /// <see cref="Calculator{TNumber}"/> — a backend-registration error rather than invalid
    /// user input.
    /// </exception>
    /// <exception cref="System.Collections.Generic.KeyNotFoundException">
    /// No backend is registered for <typeparamref name="TNumber"/>.
    /// </exception>
    public static Calculator<TNumber> Create<TNumber>(byte[] data, int length)
    {
        var raw = Create(data, length, typeof(TNumber));
        if (raw is Calculator<TNumber> typed)
        {
            return typed;
        }

        raw?.Dispose();
        throw new NotSupportedException(
            string.Format(ErrorMessages.DataTypeNotSupported, typeof(TNumber).Name));
    }

    /// <summary>
    /// Builds a <see cref="Calculator{TNumber}"/> from a strongly-typed <typeparamref name="TNumber"/>
    /// value using the registered backend factory. Backs the implicit
    /// <c>TNumber</c> → <see cref="Calculator{TNumber}"/> conversion.
    /// </summary>
    /// <typeparam name="TNumber">Numeric backend type.</typeparam>
    /// <param name="value">The numeric value to wrap.</param>
    /// <returns>A <see cref="Calculator{TNumber}"/> bound to <typeparamref name="TNumber"/>.</returns>
    /// <exception cref="System.Collections.Generic.KeyNotFoundException">
    /// No backend is registered for <typeparamref name="TNumber"/>. The calling conversion
    /// operator translates this to <see cref="NotSupportedException"/>.
    /// </exception>
    internal static Calculator<TNumber> FromValue<TNumber>(TNumber value) =>
        ((Func<TNumber, Calculator<TNumber>>)Backends[typeof(TNumber)].FromValue)(value);

    /// <summary>
    /// Returns a <see cref="System.String"/> that represents the current <see cref="Calculator"/>.
    /// </summary>
    /// <returns>The <see cref="System.String"/> representation of this <see cref="Calculator"/> object</returns>
    public abstract override string ToString();

    /// <summary>
    /// Releases the resources used by the current instance of the <see cref="Calculator"/> class.
    /// </summary>
    /// <param name="disposing">A boolean value that indicates whether the method is being called explicitly or by a finalizer.</param>
    /// <remarks>
    /// The disposed flag is a non-atomic <see cref="bool"/>. This is safe for the existing
    /// backends because their cascade-dispose targets (<see cref="PinnedPoolArray{T}"/>,
    /// <see cref="Numerics.SecureBigInteger"/>) are themselves atomic and idempotent.
    /// Subclasses that wrap non-idempotent disposable state must introduce their own
    /// <see cref="System.Threading.Interlocked.Exchange(ref int, int)"/>-backed flag
    /// (see <see cref="Numerics.SecureBigIntCalculator"/> for the established pattern).
    /// </remarks>
    protected virtual void Dispose(bool disposing)
    {
        if (this.disposed)
        {
            return;
        }

        if (disposing)
        {
            // Release managed resources here
        }

        // Release unmanaged resources here
        this.disposed = true;
    }

    /// <summary>
    /// Bundles the two construction entry points of a registered backend: the
    /// <c>(byte[], length)</c> factory used by <see cref="Create(byte[], int, Type)"/> and the
    /// strongly-typed <c>(TNumber)</c> factory used by the <c>TNumber</c> →
    /// <see cref="Calculator{TNumber}"/> conversion. The latter is stored as a
    /// <see cref="System.Delegate"/> because its type (<c>Func&lt;TNumber, Calculator&lt;TNumber&gt;&gt;</c>)
    /// is generic per backend and cannot be expressed in this non-generic dictionary.
    /// </summary>
    private sealed class BackendRegistration
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="BackendRegistration"/> class.
        /// </summary>
        /// <param name="fromBytes">Factory building a <see cref="Calculator"/> from a byte array and a length.</param>
        /// <param name="fromValue">
        /// Factory building a <c>Calculator&lt;TNumber&gt;</c> from a <c>TNumber</c> value, held as a
        /// <see cref="System.Delegate"/> (a <c>Func&lt;TNumber, Calculator&lt;TNumber&gt;&gt;</c>).
        /// </param>
        internal BackendRegistration(Func<byte[], int, Calculator> fromBytes, Delegate fromValue)
        {
            this.FromBytes = fromBytes;
            this.FromValue = fromValue;
        }

        /// <summary>
        /// Gets the factory that builds a <see cref="Calculator"/> from a byte-array representation and a length.
        /// </summary>
        internal Func<byte[], int, Calculator> FromBytes { get; }

        /// <summary>
        /// Gets the strongly-typed <c>Func&lt;TNumber, Calculator&lt;TNumber&gt;&gt;</c> factory, held as a
        /// <see cref="System.Delegate"/> and cast back by <see cref="FromValue{TNumber}"/>.
        /// </summary>
        internal Delegate FromValue { get; }
    }
}
