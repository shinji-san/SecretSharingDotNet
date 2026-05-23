// <copyright file="Calculator`1.cs" company="Private">
// Copyright (c) 2022 All Rights Reserved
// </copyright>
// <author>Sebastian Walther</author>
// <date>07/21/2022 05:23:42 PM</date>
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

using System;
using System.Diagnostics;
using System.Collections.Generic;
using System.Collections.ObjectModel;

/// <summary>
/// Generic strategy-pattern base that decouples Shamir's Secret Sharing from the concrete
/// numeric data type. The two in-tree backends are
/// <see cref="System.Numerics.BigInteger"/> (variable-time, BCL-backed) and
/// <see cref="Numerics.SecureBigInteger"/> (pinned-memory, constant-time arithmetic).
/// </summary>
/// <typeparam name="TNumber">Numeric data type — an integer type.</typeparam>
/// <remarks>
/// <para>
/// <b>Threat model — backend-conditional.</b> The arithmetic, comparison, and conversion
/// surface exposed here is mathematically equivalent across backends, but the constant-time
/// properties are a function of the chosen <typeparamref name="TNumber"/>. With
/// <see cref="Numerics.SecureBigInteger"/>, hot-path operations (<c>+</c>, <c>-</c>,
/// <c>*</c>, <c>Divide</c>, <c>MersenneModulo</c>, <c>Equals</c>) run constant-time on
/// public bit-length; with <see cref="System.Numerics.BigInteger"/> they are variable-time
/// on operand magnitude. Callers whose threat model includes timing side channels must
/// instantiate with <see cref="Numerics.SecureBigInteger"/>.
/// </para>
/// <para>
/// <b>Pow exponent is public.</b> <see cref="Pow"/> iterates a count derived from the
/// exponent value; on <see cref="Numerics.SecureBigInteger"/> the per-iteration arithmetic
/// is CT on the public bit-length but the iteration count itself leaks the exponent.
/// Callers must not pass secret-derived exponents through this method.
/// </para>
/// <para>
/// <b>Static constants allocate.</b> <see cref="Zero"/>, <see cref="One"/>, and
/// <see cref="Two"/> each return a freshly-allocated instance per access. On the
/// <see cref="Numerics.SecureBigInteger"/> backend each carries a pinned-limb buffer;
/// callers should wrap them in <c>using var</c> and reuse the local across hot loops
/// rather than reading the static property per iteration.
/// </para>
/// </remarks>
#if DEBUG
[DebuggerDisplay("{ToString()}")]
#else
[DebuggerDisplay("*** Secured Value ***")]
#endif
public abstract class Calculator<TNumber> :
    Calculator,
    IEquatable<Calculator<TNumber>>,
    IComparable,
    IComparable<Calculator<TNumber>>
{
    /// <summary>
    /// Indicates whether the resources used by the current instance have been released.
    /// </summary>
    private bool disposed;

    /// <summary>
    /// Saves a dictionary of constructors of number data types derived from the <see cref="Calculator{TNumber}"/> class.
    /// </summary>
    private static readonly ReadOnlyDictionary<Type, Func<TNumber, Calculator<TNumber>>> ChildCtors =
        new ReadOnlyDictionary<Type, Func<TNumber, Calculator<TNumber>>>(
            GetDerivedCtors<Func<TNumber, Calculator<TNumber>>>());

    /// <summary>
    /// Initializes a new instance of the <see cref="Calculator{TNumber}"/> class.
    /// </summary>
    /// <param name="val">Numeric value</param>
    protected Calculator(TNumber val) => this.Value = val;

    /// <summary>
    /// Adds the current <see cref="Calculator{TNumber}"/> instance with the <paramref name="right"/> 
    /// <see cref="Calculator{TNumber}"/> instance.
    /// </summary>
    /// <param name="right">Right value to add (right summand).</param>
    /// <returns>The sum of the current <see cref="Calculator{TNumber}"/> instance and the <paramref name="right"/> 
    /// <see cref="Calculator{TNumber}"/> instance.</returns>
    protected abstract Calculator<TNumber> Add(TNumber right);

    /// <summary>
    /// Subtracts the current <see cref="Calculator{TNumber}"/> instance with the <paramref name="right"/> 
    /// <see cref="Calculator{TNumber}"/> instance.
    /// </summary>
    /// <param name="right">Right value to subtract (subtrahend).</param>
    /// <returns>The difference of the current <see cref="Calculator{TNumber}"/> instance and the <paramref name="right"/> 
    /// <see cref="Calculator{TNumber}"/> instance.</returns>
    protected abstract Calculator<TNumber> Subtract(TNumber right);

    /// <summary>
    /// Multiplies the current <see cref="Calculator{TNumber}"/> instance with the <paramref name="right"/> 
    /// <see cref="Calculator{TNumber}"/> instance.
    /// </summary>
    /// <param name="right">multiplicand</param>
    /// <returns>The product of the current <see cref="Calculator{TNumber}"/> instance and the <paramref name="right"/> 
    /// <see cref="Calculator{TNumber}"/> instance.</returns>
    protected abstract Calculator<TNumber> Multiply(TNumber right);

    /// <summary>
    /// Divides the current <see cref="Calculator{TNumber}"/> instance with the <paramref name="right"/> 
    /// <see cref="Calculator{TNumber}"/> instance.
    /// </summary>
    /// <param name="right">divisor</param>
    /// <returns>The quotient of the current <see cref="Calculator{TNumber}"/> instance and the <paramref name="right"/> 
    /// <see cref="Calculator{TNumber}"/> instance.</returns>
    protected abstract Calculator<TNumber> Divide(TNumber right);

    /// <summary>
    /// The modulo operation
    /// </summary>
    /// <param name="right">divisor</param>
    /// <returns>The remainder</returns>
    protected abstract Calculator<TNumber> Modulo(TNumber right);

    /// <summary>
    /// The unary increment method increments this instance by 1.
    /// </summary>
    /// <returns>This <see cref="Calculator{TNumber}"/> instance plus <see cref="Calculator{TNumber}.One"/></returns>
    protected abstract Calculator<TNumber> Increment();

    /// <summary>
    /// The unary decrement method decrements this instance by 1.
    /// </summary>
    /// <returns>This <see cref="Calculator{TNumber}"/> instance minus <see cref="Calculator{TNumber}.One"/></returns>
    protected abstract Calculator<TNumber> Decrement();

    /// <summary>
    /// Computes the mathematical modulo operation for the current <see cref="Calculator{TNumber}"/> instance.
    /// </summary>
    /// <param name="right">The divisor used to compute the modulo.</param>
    /// <returns>
    /// A new <see cref="Calculator{TNumber}"/> instance representing the result of the modulo operation.
    /// </returns>
    public Calculator<TNumber> MathematicalModulo(TNumber right)
    {
        using var remainder = this.Modulo(right);
        using var remainderPlusRight = remainder.Add(right);
        return remainderPlusRight.Modulo(right);
    }

    /// <summary>
    /// Computes the modulo of the current value by the Mersenne prime
    /// <c>M_p = 2^<paramref name="mersenneExponent"/> - 1</c>. The exponent
    /// is treated as public information and may legitimately drive the
    /// iteration count of the underlying fold-and-add algorithm.
    /// </summary>
    /// <param name="mersenneExponent">
    /// Positive Mersenne-prime exponent. Caller is responsible for ensuring
    /// the corresponding <c>2^exp - 1</c> is actually prime; the method does
    /// not verify primality.
    /// </param>
    /// <returns>
    /// A new <see cref="Calculator{TNumber}"/> in <c>[0, M_p - 1]</c>.
    /// </returns>
    /// <exception cref="ArgumentOutOfRangeException">
    /// <paramref name="mersenneExponent"/> is not positive.
    /// </exception>
    /// <remarks>
    /// <para>
    /// Mathematical-modulo semantics: negative operands return the canonical
    /// non-negative representative in <c>[0, M_p - 1]</c>. Equivalent to
    /// <see cref="MathematicalModulo"/> with the modulus implicitly fixed at
    /// <c>2^mersenneExponent - 1</c>, but specialised to the Mersenne fold
    /// algorithm on the <see cref="Numerics.SecureBigInteger"/> backend.
    /// </para>
    /// <para>
    /// On the <see cref="Numerics.SecureBigInteger"/> backend this routes to a
    /// fold-and-conditional-subtract algorithm that exploits
    /// <c>2^p ≡ 1 (mod M_p)</c>; on the <see cref="System.Numerics.BigInteger"/>
    /// backend it lowers to BCL <c>%</c> after one shift to build the modulus.
    /// Both backends produce identical results for non-negative inputs.
    /// </para>
    /// </remarks>
    public abstract Calculator<TNumber> MersenneModulo(int mersenneExponent);

    /// <summary>
    /// Returns the absolute value of the current <see cref="Calculator{TNumber}"/> object.
    /// </summary>
    /// <returns>The absolute value of this instance.</returns>
    public abstract Calculator<TNumber> Abs();

    /// <summary>
    /// Raises this <see cref="Calculator{TNumber}"/> value to the power of
    /// <paramref name="expo"/>.
    /// </summary>
    /// <param name="expo">The non-negative exponent. Must be treated as public input —
    /// <see cref="Pow"/>'s iteration count is <c>O(log₂(expo))</c>, and on the
    /// <see cref="Numerics.SecureBigInteger"/> backend that count is the only
    /// data-dependent quantity (per-iteration arithmetic on the base remains constant-time
    /// on the public bit-length). Callers must not pass secret-derived exponents.</param>
    /// <returns>The result of raising the current value to the <paramref name="expo"/> power.</returns>
    public abstract Calculator<TNumber> Pow(int expo);

    /// <summary>
    /// This method represents the Greater Than operator.
    /// </summary>
    /// <param name="right">right-hand operand</param>
    /// <returns>This method returns <see langword="true"/> if this instance is greater than the <paramref name="right"/> instance, <see langword="false"/> otherwise.</returns>
    protected abstract bool GreaterThan(TNumber right);

    /// <summary>
    /// This method represents the Greater Than Or Equal To operator.
    /// </summary>
    /// <param name="right">right-hand operand</param>
    /// <returns>This method returns <see langword="true"/> if this instance is greater than or equal to the <paramref name="right"/> instance, <see langword="false"/> otherwise.</returns>
    protected abstract bool EqualOrGreaterThan(TNumber right);

    /// <summary>
    /// This method represents the Lower Than operator.
    /// </summary>
    /// <param name="right">right-hand operand</param>
    /// <returns>This method returns <see langword="true"/> if this instance is less than the <paramref name="right"/> instance, <see langword="false"/> otherwise.</returns>
    protected abstract bool LowerThan(TNumber right);

    /// <summary>
    /// This method represents the Lower Than Or Equal To operator.
    /// </summary>
    /// <param name="right">right-hand operand</param>
    /// <returns>This method returns <see langword="true"/> if this instance is less than or equal to the <paramref name="right"/> instance, <see langword="false"/> otherwise.</returns>
    protected abstract bool EqualOrLowerThan(TNumber right);

    /// <summary>
    /// Greater than operator
    /// </summary>
    /// <param name="left">The 1st operand</param>
    /// <param name="right">The 2nd operand</param>
    /// <returns>Returns <see langword="true"/> if its 1st operand is greater than its 2nd operand, otherwise <see langword="false"/>.</returns>
    public static bool operator >(Calculator<TNumber> left, Calculator<TNumber> right) => left is not null && right is not null && left.GreaterThan(right.Value);

    /// <summary>
    /// Less than operator
    /// </summary>
    /// <param name="left">The 1st operand</param>
    /// <param name="right">The 2nd operand</param>
    /// <returns>Returns <see langword="true"/> if its 1st operand is less than its 2nd operand, otherwise <see langword="false"/>.</returns>
    public static bool operator <(Calculator<TNumber> left, Calculator<TNumber> right) => left is not null && right is not null && left.LowerThan(right.Value);

    /// <summary>
    /// Greater than or equal operator
    /// </summary>
    /// <param name="left">The 1st operand</param>
    /// <param name="right">The 2nd operand</param>
    /// <returns>Returns <see langword="true"/> if its 1st operand is greater than or equal to its 2nd operand, otherwise <see langword="false"/>.</returns>
    public static bool operator >=(Calculator<TNumber> left, Calculator<TNumber> right) => left is not null && right is not null && left.EqualOrGreaterThan(right.Value);

    /// <summary>
    /// Less than or equal operator
    /// </summary>
    /// <param name="left">The 1st operand</param>
    /// <param name="right">The 2nd operand</param>
    /// <returns>Returns <see langword="true"/> if its 1st operand is less than or equal to its 2nd operand, otherwise <see langword="false"/>.</returns>
    public static bool operator <=(Calculator<TNumber> left, Calculator<TNumber> right) => left is not null && right is not null && left.EqualOrLowerThan(right.Value);

    /// <summary>
    /// Addition operation
    /// </summary>
    /// <param name="left">The 1st summand</param>
    /// <param name="right">The 2nd summand</param>
    /// <returns>The sum</returns>
    /// <exception cref="ArgumentNullException">
    /// <paramref name="left"/> or <paramref name="right"/> is <see langword="null"/>.
    /// </exception>
    public static Calculator<TNumber> operator +(Calculator<TNumber> left, Calculator<TNumber> right) => right is not null ? left?.Add(right.Value) ?? throw new ArgumentNullException(nameof(left)) : throw new ArgumentNullException(nameof(right));

    /// <summary>
    /// Subtraction operation
    /// </summary>
    /// <param name="left">The minuend</param>
    /// <param name="right">The subtrahend</param>
    /// <returns>The difference</returns>
    /// <exception cref="ArgumentNullException">
    /// <paramref name="left"/> or <paramref name="right"/> is <see langword="null"/>.
    /// </exception>
    public static Calculator<TNumber> operator -(Calculator<TNumber> left, Calculator<TNumber> right) => right is not null ? left?.Subtract(right.Value) ?? throw new ArgumentNullException(nameof(left)) : throw new ArgumentNullException(nameof(right));

    /// <summary>
    /// Multiplication operation
    /// </summary>
    /// <param name="left">multiplier</param>
    /// <param name="right">multiplicand</param>
    /// <returns>The product</returns>
    /// <exception cref="ArgumentNullException">
    /// <paramref name="left"/> or <paramref name="right"/> is <see langword="null"/>.
    /// </exception>
    public static Calculator<TNumber> operator *(Calculator<TNumber> left, Calculator<TNumber> right) => right is not null ? left?.Multiply(right.Value) ?? throw new ArgumentNullException(nameof(left)) : throw new ArgumentNullException(nameof(right));

    /// <summary>
    /// Divide operation
    /// </summary>
    /// <param name="left">dividend</param>
    /// <param name="right">divisor</param>
    /// <returns>The quotient</returns>
    /// <exception cref="ArgumentNullException">
    /// <paramref name="left"/> or <paramref name="right"/> is <see langword="null"/>.
    /// </exception>
    public static Calculator<TNumber> operator /(Calculator<TNumber> left, Calculator<TNumber> right) => right is not null ? left?.Divide(right.Value) ?? throw new ArgumentNullException(nameof(left)) : throw new ArgumentNullException(nameof(right));

    /// <summary>
    /// Modulo operation
    /// </summary>
    /// <param name="left">dividend</param>
    /// <param name="right">divisor</param>
    /// <returns>The remainder</returns>
    /// <exception cref="ArgumentNullException">
    /// <paramref name="left"/> or <paramref name="right"/> is <see langword="null"/>.
    /// </exception>
    public static Calculator<TNumber> operator %(Calculator<TNumber> left, Calculator<TNumber> right) => right is not null ? left?.Modulo(right.Value) ?? throw new ArgumentNullException(nameof(left)) : throw new ArgumentNullException(nameof(right));

    /// <summary>
    /// Increment operator
    /// </summary>
    /// <param name="number">The operand</param>
    /// <returns>The unary increment operator increments the operand <paramref name="number"/> by 1</returns>
    public static Calculator<TNumber> operator ++(Calculator<TNumber> number) => number?.Increment();

    /// <summary>
    /// Decrement operator
    /// </summary>
    /// <param name="number">The operand</param>
    /// <returns>The unary decrement operator decrements the operand <paramref name="number"/> by 1.</returns>
    public static Calculator<TNumber> operator --(Calculator<TNumber> number) => number?.Decrement();

    /// <summary>
    /// Equality operator
    /// </summary>
    /// <param name="left">The left operand</param>
    /// <param name="right">The right operand</param>
    /// <returns>Returns <see langword="true"/> if its operands are equal, otherwise <see langword="false"/>.</returns>
    public static bool operator ==(Calculator<TNumber> left, Calculator<TNumber> right)
    {
        if ((object)left == null || (object)right == null)
        {
            return Equals(left, right);
        }

        return left.Equals(right);
    }

    /// <summary>
    /// Inequality operator
    /// </summary>
    /// <param name="left">The left operand</param>
    /// <param name="right">The right operand</param>
    /// <returns>Returns <see langword="true"/> if its operands are not equal, otherwise <see langword="false"/>.</returns>
    public static bool operator !=(Calculator<TNumber> left, Calculator<TNumber> right)
    {
        if ((object)left == null || (object)right == null)
        {
            return !Equals(left, right);
        }

        return !left.Equals(right);
    }

    /// <summary>
    /// Casts the <see cref="Calculator{TNumber}"/> instance to an <typeparamref name="TNumber"/> instance.
    /// </summary>
    /// <param name="calculatorInstance">A data type from basic class <see cref="Calculator{TNumber}"/>.</param>
    public static implicit operator TNumber(Calculator<TNumber> calculatorInstance) => calculatorInstance is not null ? calculatorInstance.Value : default;

    /// <summary>
    /// Casts the <typeparamref name="TNumber"/> instance to an <see cref="Calculator{TNumber}"/> instance.
    /// </summary>
    /// <param name="number">Numeric data type (An integer data type).</param>
    public static implicit operator Calculator<TNumber>(TNumber number)
    {
        try
        {
            return ChildCtors[typeof(TNumber)](number);
        }
        catch (KeyNotFoundException)
        {
            throw new NotSupportedException(string.Format(ErrorMessages.DataTypeNotSupported, typeof(TNumber).Name));
        }
    }

    /// <summary>
    /// Determines whether this instance and an<paramref name="other"/> specified <see cref="Calculator{TNumber}"/> instance are equal.
    /// </summary>
    /// <param name="other">The <see cref="Calculator{TNumber}"/> instance to compare</param>
    /// <returns><see langword="true"/> if the value of the <paramref name="other"/> parameter is the same as the value of this instance; otherwise <see langword="false"/>.
    /// If <paramref name="other"/> is <see langword="null"/>, the method returns <see langword="false"/>.</returns>
    public virtual bool Equals(Calculator<TNumber> other)
    {
        return other != null && this.Value.Equals(other.Value);
    }

    /// <summary>
    /// Returns a value that indicates whether the current instance and a specified object have the same value.
    /// </summary>
    /// <param name="obj">The object to compare.</param>
    /// <returns><see langword="true"/> if the <paramref name="obj"/> argument is a <see cref="Calculator{TNumber}"/> object,
    /// and its value is equal to the value of the current <see cref="Calculator{TNumber}"/> instance; otherwise, <see langword="false"/>.</returns>
    public override bool Equals(object obj)
    {
        if (obj == null)
        {
            return false;
        }

        var calculator = obj as Calculator<TNumber>;
        return calculator != null && this.Equals(calculator);
    }

    /// <summary>
    /// Returns the hash code for the current <see cref="Calculator{TNumber}"/> object.
    /// </summary>
    /// <returns>A 32-bit signed integer hash code.</returns>
    public override int GetHashCode() => this.Value.GetHashCode();

    /// <summary>
    /// Compares this instance to a specified object and returns an integer that
    /// indicates whether the value of this instance is less than, equal to, or greater than the value of the specified object.
    /// </summary>
    /// <param name="obj">The object to compare</param>
    /// <exception cref="ArgumentException"><paramref name="obj"/> has a unknown data type</exception>
    /// <returns>A signed integer that indicates the relationship of the current instance to the <paramref name="obj"/> parameter</returns>
    public virtual int CompareTo(object obj)
    {
        return obj switch
        {
            null => 1,
            TNumber number => this.CompareTo(number),
            _ => throw new ArgumentException()
        };
    }

    /// <summary>
    /// Gets or sets the numeric value
    /// </summary>
    public TNumber Value { get; set; }

    /// <summary>
    /// Returns a caller-owned snapshot of <see cref="Value"/> that survives this
    /// <see cref="Calculator{TNumber}"/>'s <see cref="IDisposable.Dispose"/>.
    /// </summary>
    /// <returns>A <typeparamref name="TNumber"/> instance independent of this
    /// calculator's lifetime.</returns>
    /// <remarks>
    /// The default implementation is a plain field read, which is correct for
    /// value-type backends (e.g. <see cref="System.Numerics.BigInteger"/>).
    /// Reference-type backends that wrap disposable state (e.g.
    /// <c>SecureBigInteger</c>) <b>must</b> override this method to return a
    /// deep copy — otherwise the caller receives a reference to storage that
    /// is wiped and/or recycled the moment this calculator is disposed.
    /// </remarks>
    protected internal virtual TNumber ExtractValue() => this.Value;

    /// <summary>
    /// Gets a freshly allocated <see cref="Calculator{TNumber}"/> representing zero (0).
    /// </summary>
    /// <remarks>
    /// Every access allocates a new instance via the implicit
    /// <typeparamref name="TNumber"/>-to-<see cref="Calculator{TNumber}"/> conversion. On
    /// the <see cref="Numerics.SecureBigInteger"/> backend the returned instance owns a
    /// fresh pinned-limb buffer; the caller takes ownership and is responsible for
    /// disposing. Hot loops should hoist a single <c>using var zero = Calculator&lt;TNumber&gt;.Zero;</c>
    /// rather than read the property per iteration.
    /// </remarks>
    public static Calculator<TNumber> Zero  => default(TNumber);

    /// <summary>
    /// Gets a freshly allocated <see cref="Calculator{TNumber}"/> representing one (1).
    /// </summary>
    /// <remarks>
    /// Computed as <c>Zero.Increment()</c>. The transient <see cref="Zero"/> instance
    /// allocated on entry is deterministically disposed inside this getter before
    /// <see cref="One"/> is returned, so on the <see cref="Numerics.SecureBigInteger"/>
    /// backend no undisposed pinned-limb buffer escapes to the caller's GC. The caller
    /// owns the single returned instance and is responsible for disposing it. Hot loops
    /// should still hoist a single <c>using var one = Calculator&lt;TNumber&gt;.One;</c>
    /// rather than re-read the property per iteration to avoid the per-call allocation
    /// pair entirely.
    /// </remarks>
    public static Calculator<TNumber> One
    {
        get
        {
            using var zero = Zero;
            return zero.Increment();
        }
    }

    /// <summary>
    /// Gets a freshly allocated <see cref="Calculator{TNumber}"/> representing two (2).
    /// </summary>
    /// <remarks>
    /// Computed as <c>One.Increment()</c>. The transient <see cref="One"/> instance
    /// allocated on entry is deterministically disposed inside this getter before
    /// <see cref="Two"/> is returned (and the inner <see cref="One"/> getter in turn
    /// disposes its own transient <see cref="Zero"/>), so on the
    /// <see cref="Numerics.SecureBigInteger"/> backend no undisposed pinned-limb buffer
    /// escapes to the caller's GC. The caller owns the single returned instance and is
    /// responsible for disposing it. Hot loops should still hoist a single
    /// <c>using var two = Calculator&lt;TNumber&gt;.Two;</c> rather than re-read the
    /// property per iteration to avoid the per-call allocation cascade entirely.
    /// </remarks>
    public static Calculator<TNumber> Two
    {
        get
        {
            using var one = One;
            return one.Increment();
        }
    }

    /// <summary>
    /// Returns a deep, independent copy of the current <see cref="Calculator{TNumber}"/> instance.
    /// </summary>
    /// <returns>A new <see cref="Calculator{TNumber}"/> whose state — including any
    /// <typeparamref name="TNumber"/> backing instance and any reference-type fields — is independent
    /// of this instance, so mutating one does not affect the other.</returns>
    /// <remarks>
    /// Subtypes are responsible for producing a true deep copy. <see cref="object.MemberwiseClone"/>
    /// is not safe as a default implementation when <typeparamref name="TNumber"/> is a reference
    /// type or when the subtype carries reference-type fields.
    /// </remarks>
    public abstract Calculator<TNumber> Clone();

    /// <summary>
    /// Compares this instance to a second <see cref="Calculator{TNumber}"/> and returns an integer that indicates whether the value of this instance is less than, equal to, or greater than the value of the specified object.
    /// </summary>
    /// <param name="other">The object to compare.</param>
    /// <returns>A signed integer that indicates the relationship of the current instance to the <paramref name="other"/> parameter</returns>
    public abstract int CompareTo(Calculator<TNumber> other);

    /// <summary>
    /// Converts the numeric value of the current <see cref="Calculator{TNumber}"/> instance to its equivalent <see cref="System.String"/> representation.
    /// </summary>
    /// <returns>The <see cref="System.String"/> representation of the current <see cref="Calculator{TNumber}"/> value.</returns>
    public override string ToString()
    {
#if DEBUG
        return $"{this.GetType().Name}({this.Value})";
#else
        return "*** Secured Value ***";
#endif
    }

    /// <summary>
    /// Releases the resources used by the <see cref="Calculator{TNumber}"/> instance.
    /// </summary>
    /// <param name="disposing">A boolean value indicating whether the method is being called explicitly or by a finalizer.</param>
    /// <remarks>
    /// Like the non-generic <see cref="Calculator.Dispose(bool)"/> base, the disposed flag
    /// is a non-atomic <see cref="bool"/>. Subtypes that wrap non-idempotent disposable
    /// state (e.g. pinned-memory backends) must introduce their own
    /// <see cref="System.Threading.Interlocked.Exchange(ref int, int)"/>-backed flag —
    /// see <see cref="Numerics.SecureBigIntCalculator"/> for the established pattern.
    /// </remarks>
    protected override void Dispose(bool disposing)
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
        base.Dispose(disposing);
    }
}
