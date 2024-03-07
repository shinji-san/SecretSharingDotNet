#if NET6_0_OR_GREATER
namespace SecretSharingDotNet.Math;

using System.Collections.Generic;
using System.Linq;

/// <summary>
/// <see cref="Calculator"/> implementation of <see cref="SecureBigInteger"/>
/// </summary>
public sealed class SecureBigIntCalculator : Calculator<SecureBigInteger>
{
    /// <summary>
    /// Initializes a new instance of the <see cref="SecureBigIntCalculator"/> class.
    /// </summary>
    /// <param name="val">The value of the <see cref="SecureBigInteger"/> object.</param>
    public SecureBigIntCalculator(SecureBigInteger val) : base(val ?? new SecureBigInteger(0))
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="Calculator{SecureBigInteger}"/> class.
    /// </summary>
    /// <param name="data">The byte array to initialize the <see cref="Calculator{SecureBigInteger}"/> object.</param>
    public SecureBigIntCalculator(byte[] data) : base(new SecureBigInteger(data))
    {
    }

    /// <summary>
    /// Gets the number of bytes in the byte representation of the <see cref="Calculator{SecureBigInteger}"/> object.
    /// </summary>
    public override int ByteCount => this.ByteRepresentation.Count();

    /// <summary>
    /// Gets the byte representation of the <see cref="Calculator{SecureBigInteger}"/> object.
    /// </summary>
    public override IEnumerable<byte> ByteRepresentation => this.Value.ToByteSpan().ToArray();

    /// <summary>
    /// Determines whether the current value of the <see cref="Calculator{SecureBigInteger}"/> is zero.
    /// </summary>
    public override bool IsZero => this.Value.IsZero;

    /// <summary>
    /// Indicates whether the value of the current <see cref="Calculator{SecureBigInteger}"/> is one.
    /// </summary>
    public override bool IsOne => this.Value.IsOne;

    /// <summary>
    /// Indicates whether the value of the current <see cref="Calculator{SecureBigInteger}"/> object is even.
    /// </summary>
    public override bool IsEven => this.Value.IsEven;

    /// <summary>
    /// Gets the sign of the <see cref="Calculator{SecureBigInteger}"/> value.
    /// </summary>
    public override int Sign => this.Value.Sign;

    /// <summary>
    /// Converts the value of the current <see cref="Calculator{SecureBigInteger}"/> object to a 32-bit signed integer.
    /// </summary>
    /// <returns>
    /// A 32-bit signed integer equivalent to the value of the current <see cref="Calculator{SecureBigInteger}"/> object.
    /// </returns>
    public override int ToInt32() => (int)this.Value;

    /// <summary>
    /// Adds the given <see cref="Calculator{SecureBigInteger}"/> to the current value.
    /// </summary>
    /// <param name="right">The <see cref="Calculator{SecureBigInteger}"/> to add.</param>
    /// <returns>A new <see cref="Calculator{SecureBigInteger}"/> instance representing the result of the addition.</returns>
    protected override Calculator<SecureBigInteger> Add(SecureBigInteger right) => this.Value + right;

    /// <summary>
    /// Subtracts a <see cref="Calculator{SecureBigInteger}"/> from the current <see cref="Calculator{SecureBigInteger}"/> value.
    /// </summary>
    /// <param name="right">The <see cref="Calculator{SecureBigInteger}"/> to subtract.</param>
    /// <returns>A new <see cref="Calculator{SecureBigInteger}"/> instance with the result of the subtraction.</returns>
    protected override Calculator<SecureBigInteger> Subtract(SecureBigInteger right) => this.Value - right;

    /// <summary>
    /// Multiplies the current <see cref="Calculator{SecureBigInteger}"/> value by the specified <see cref="Calculator{SecureBigInteger}"/> value.
    /// </summary>
    /// <param name="right">The <see cref="Calculator{SecureBigInteger}"/> value to multiply with the current value.</param>
    /// <returns>The product of the current value and the specified <see cref="Calculator{SecureBigInteger}"/> value.</returns>
    protected override Calculator<SecureBigInteger> Multiply(SecureBigInteger right) => this.Value * right;

    /// <summary>
    /// Divides the current <see cref="Calculator{SecureBigInteger}"/> value by the specified <paramref name="right"/> value.
    /// </summary>
    /// <param name="right">The <see cref="Calculator{SecureBigInteger}"/> value to divide the current value by.</param>
    /// <returns>A new <see cref="Calculator{SecureBigInteger}"/> object representing the division result.</returns>
    protected override Calculator<SecureBigInteger> Divide(SecureBigInteger right) => this.Value / right;

    /// <summary>
    /// Computes the modulus of the current <see cref="SecureBigInteger"/> value by the specified divisor.
    /// </summary>
    /// <param name="right">The divisor of type <see cref="SecureBigInteger"/>.</param>
    /// <returns>A new <see cref="Calculator{SecureBigInteger}"/> representing the result.</returns>
    protected override Calculator<SecureBigInteger> Modulo(SecureBigInteger right) => this.Value % right;

    /// <summary>
    /// Increments the current <see cref="Calculator{SecureBigInteger}"/> value by one.
    /// </summary>
    /// <returns>A new instance of <see cref="Calculator{SecureBigInteger}"/> with the incremented value.</returns>
    protected override Calculator<SecureBigInteger> Increment() => this.Value + SecureBigInteger.One;

    /// <summary>
    /// Decrements the current <see cref="Calculator{SecureBigInteger}"/> value by one.
    /// </summary>
    /// <returns>The updated <see cref="Calculator{SecureBigInteger}"/> after decrementing.</returns>
    protected override Calculator<SecureBigInteger> Decrement() => this.Value - SecureBigInteger.One;

    /// <summary>
    /// Returns the absolute value of the current <see cref="SecureBigIntCalculator"/> instance.
    /// </summary>
    /// <returns>A new <see cref="Calculator{SecureBigInteger}"/> representing the absolute value.</returns>
    public override Calculator<SecureBigInteger> Abs() => this.Value.Abs();

    /// <summary>
    /// Returns a new <see cref="Calculator{SecureBigInteger}"/> object that is the result of raising the current value to the specified exponent.
    /// </summary>
    /// <param name="expo">The exponent to which the current value is raised.</param>
    /// <returns>A new <see cref="Calculator{SecureBigInteger}"/> object representing the result of the exponentiation operation.</returns>
    public override Calculator<SecureBigInteger> Pow(int expo) => this.Value.Pow(expo);

    /// <summary>
    /// Computes the square root of the current <see cref="Calculator{SecureBigInteger}"/> object.
    /// </summary>
    public override Calculator<SecureBigInteger> Sqrt() => this.Value.SquareRoot();

    /// <summary>
    /// Determines if the current <see cref="Calculator{SecureBigInteger}"/> is greater than the specified <paramref name="right"/> value.
    /// </summary>
    /// <param name="right">The <see cref="Calculator{SecureBigInteger}"/> value to compare with the current instance.</param>
    /// <returns><see langword="true"/> if the current instance is greater than the specified value; otherwise, <see langword="false"/>.</returns>
    protected override bool GreaterThan(SecureBigInteger right) => this.Value > right;

    /// <summary>
    /// Determines whether the value of the current instance is equal to or greater than the specified <see cref="Calculator{SecureBigInteger}"/>.
    /// </summary>
    /// <param name="right">The <see cref="Calculator{SecureBigInteger}"/> to compare with.</param>
    /// <returns>
    /// <see langword="true"/> if the value of the current instance is equal to or greater than the specified <see cref="Calculator{SecureBigInteger}"/>; otherwise, <see langword="false"/>.
    /// </returns>
    protected override bool EqualOrGreaterThan(SecureBigInteger right) => this.Value >= right;

    /// <summary>
    /// Determines whether the current <see cref="Calculator{SecureBigInteger}"/> object is less than the specified <see cref="Calculator{SecureBigInteger}"/> value.
    /// </summary>
    /// <param name="right">The <see cref="Calculator{SecureBigInteger}"/> value to compare with the current <see cref="Calculator{SecureBigInteger}"/> object.</param>
    /// <returns><see langword="true"/> if the current <see cref="Calculator{SecureBigInteger}"/> object is less than the specified <see cref="Calculator{SecureBigInteger}"/> value; otherwise, <see langword="false"/>.</returns>
    protected override bool LowerThan(SecureBigInteger right) => this.Value < right;

    /// <summary>
    /// Determines whether the stored value is equal to or less than the specified value.
    /// </summary>
    /// <param name="right">The value to compare against.</param>
    /// <returns><see langword="true"/> if the stored value is equal to or less than the specified value; otherwise, <see langword="false"/>.</returns>
    protected override bool EqualOrLowerThan(SecureBigInteger right) => this.Value <= right;

    /// <summary>
    /// Compares the current instance with another object of the same type and returns an integer that indicates whether the current instance precedes, follows, or occurs in the same position in the sort order as the other object.
    /// </summary>
    /// <param name="other">An object to compare with this instance.</param>
    /// <returns>A value that indicates the relative order of the objects being compared. The return value has these meanings:
    /// Less than zero: This instance precedes <paramref name="other"/> in the sort order.
    /// Zero: This instance occurs in the same position in the sort order as <paramref name="other"/>.
    /// Greater than zero: This instance follows <paramref name="other"/> in the sort order.</returns>
    public override int CompareTo(Calculator<SecureBigInteger> other) => this.Value.CompareTo(other.Value);

    /// <summary>
    /// Converts the current instance to its string representation.
    /// </summary>
    /// <returns>The string representation of the current instance.</returns>
    public override string ToString() => this.Value.ToString();
}
#endif