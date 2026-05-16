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

using Cryptography.SecureArray;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Linq.Expressions;
using System.Reflection;

/// <summary>
/// Non-generic base of the calculator strategy pattern that decouples Shamir's Secret
/// Sharing from the concrete numeric data type. Subtypes wire a specific backend such as
/// <see cref="System.Numerics.BigInteger"/> or
/// <see cref="Numerics.SecureBigInteger"/> in via <see cref="Calculator{TNumber}"/>.
/// </summary>
/// <remarks>
/// The base type intentionally carries no constant-time guarantees — those are a property
/// of the chosen <typeparamref name="TNumber"/> backend in <see cref="Calculator{TNumber}"/>.
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
    /// Saves a dictionary of number data types derived from the <see cref="Calculator{TNumber}"/> class.
    /// </summary>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Security", "CA2104:DoNotDeclareReadOnlyMutableReferenceTypes")]
    private static readonly ReadOnlyDictionary<Type, Type> ChildTypes =
        new ReadOnlyDictionary<Type, Type>(GetDerivedNumberTypes());

    /// <summary>
    /// Saves a dictionary of constructors of number data types derived from the <see cref="Calculator{TNumber}"/> class.
    /// </summary>
    private static readonly IReadOnlyDictionary<Type, Func<byte[], int, Calculator>> ChildBaseCtors =
        new ReadOnlyDictionary<Type, Func<byte[], int, Calculator>>(GetDerivedCtors<Func<byte[], int, Calculator>>());

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
    /// the raw lookup failure for plugin diagnostics.
    /// </exception>
    public static Calculator Create(byte[] data, int length, Type numberType) => ChildBaseCtors[numberType](data, length);

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
    /// <c>Calculator.Create(...) as Calculator&lt;TNumber&gt;</c> idiom: if a third-party plugin
    /// backend produces a <see cref="Calculator"/> subtype that is not assignable to
    /// <see cref="Calculator{TNumber}"/>, the original instance — which may hold pinned, security-
    /// sensitive buffers on the <see cref="Numerics.SecureBigInteger"/> backend — is disposed
    /// before the exception escapes.
    /// </remarks>
    /// <exception cref="NotSupportedException">
    /// The registered backend for <typeparamref name="TNumber"/> is not assignable to
    /// <see cref="Calculator{TNumber}"/> — a configuration error in a third-party plugin
    /// backend rather than invalid user input.
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
    /// Returns a <see cref="System.String"/> that represents the current <see cref="Calculator"/>.
    /// </summary>
    /// <returns>The <see cref="System.String"/> representation of this <see cref="Calculator"/> object</returns>
    public abstract override string ToString();

    /// <summary>
    /// Returns a dictionary of constructors of number data types derived from the <see cref="Calculator"/> class.
    /// </summary>
    /// <returns>A dictionary of constructors of number data types derived from the <see cref="Calculator"/> class.</returns>
    protected static Dictionary<Type, TDelegate> GetDerivedCtors<TDelegate>() where TDelegate : Delegate
    {
        var delegateType = typeof(TDelegate);
        var methodInfo = delegateType.GetMethod(nameof(Func<>.Invoke)) ??
                         throw new InvalidOperationException(
                             $"Delegate type '{delegateType.Name}' does not have an '{nameof(Func<>.Invoke)}' method.");
        var parameterTypes = methodInfo.GetParameters().Select(x => x.ParameterType).ToArray();
        var parameterExpressions = parameterTypes.Select(Expression.Parameter).ToArray();
        var expressions = parameterExpressions.OfType<Expression>().ToArray();

        var res = new Dictionary<Type, TDelegate>(ChildTypes.Count);
        foreach (var childType in ChildTypes)
        {
            var constructorInfos = childType.Value.GetConstructors();
            foreach (var constructorInfo in constructorInfos)
            {
                var ctorParams = constructorInfo.GetParameters();
                if (ctorParams.Length != parameterTypes.Length)
                {
                    continue;
                }

                var matches = true;
                for (int i = 0; i < ctorParams.Length; i++)
                {
                    if (ctorParams[i].ParameterType == parameterTypes[i])
                    {
                        continue;
                    }

                    matches = false;
                    break;
                }

                if (!matches)
                {
                    continue;
                }

                var ctor = Expression
                    .Lambda<TDelegate>(Expression.New(constructorInfo, expressions), parameterExpressions)
                    .Compile();
                res.Add(childType.Key, ctor);
            }
        }

        return res;
    }

    /// <summary>
    /// Returns a dictionary of number data types derived from the <see cref="Calculator"/> class.
    /// </summary>
    /// <returns></returns>
    /// <remarks>The key represents the integer data type of the derived calculator. The value represents the type of derived calculator.</remarks>
    private static Dictionary<Type, Type> GetDerivedNumberTypes()
    {
        var asm = Assembly.GetAssembly(typeof(Calculator));
        var listOfClasses = asm?.GetTypes()
            .Where(x => x.IsSubclassOf(typeof(Calculator)) && !x.IsGenericType);
        return listOfClasses?.ToDictionary(type => type.BaseType?.GetGenericArguments()[0]) ?? [];
    }

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
}