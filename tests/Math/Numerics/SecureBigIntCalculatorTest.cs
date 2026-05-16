// ----------------------------------------------------------------------------
// <copyright file="SecureBigIntCalculatorTest.cs" company="Private">
// Copyright (c) 2025 All Rights Reserved
// </copyright>
// <author>Sebastian Walther</author>
// <date>12/22/2025 01:05:28 AM</date>
// ----------------------------------------------------------------------------

#region License
// ----------------------------------------------------------------------------
// Copyright 2025 Sebastian Walther
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

namespace SecretSharingDotNetTest.Math.Numerics;

using System;
using SecretSharingDotNet;
using SecretSharingDotNet.Math;
using SecretSharingDotNet.Math.Numerics;
using System.Linq;
using System.Threading;
using Xunit;

/// <summary>
/// Tests for <see cref="SecureBigIntCalculator"/> — the
/// <see cref="SecureBigInteger"/>-backed <see cref="Calculator{TNumber}"/> implementation.
/// Mirror of <c>BigIntCalculatorTest</c> plus reference-type-specific contract tests
/// (null-fallback, concurrent disposal, increment-loop smoke test).
/// </summary>
public class SecureBigIntCalculatorTest
{
    /// <summary>
    /// Tests that <see cref="SecureBigIntCalculator(SecureBigInteger)"/> stores the supplied
    /// value in <see cref="Calculator{TNumber}.Value"/>.
    /// </summary>
    [Fact]
    public void Constructor_WithSecureBigInteger_ShouldInitializeValue()
    {
        // Arrange
        using SecureBigInteger value = 12345;

        // Act
        using Calculator<SecureBigInteger> calculator = new SecureBigIntCalculator(value);

        // Assert
        Assert.Equal(value, calculator.Value);
    }

    /// <summary>
    /// Tests the null-fallback contract on <see cref="SecureBigIntCalculator(SecureBigInteger)"/>:
    /// a <see langword="null"/> argument is substituted by zero. This is required to support
    /// <see cref="Calculator{TNumber}.Zero"/> on the reference-type backend (where
    /// <c>default(TNumber) == null</c>).
    /// </summary>
    [Fact]
    public void Constructor_NullValue_FallsBackToZero()
    {
        // Arrange
        // The single-argument constructor accepts null and substitutes zero.
        // This contract exists to support `Calculator<SecureBigInteger>.Zero`
        // on the reference-type backend (where `default(TNumber) == null`).
        using var calculator = new SecureBigIntCalculator(null);

        // Act & Assert
        Assert.True(calculator.Value.IsZero);
    }

    /// <summary>
    /// Regression guard for <see cref="Calculator{SecureBigInteger}.Zero"/>: removing the
    /// null fallback in <see cref="SecureBigIntCalculator(SecureBigInteger)"/> would break
    /// the static <c>Zero</c> property and every chain that depends on it
    /// (<c>One</c>, <c>Two</c>, …).
    /// </summary>
    [Fact]
    public void Calculator_Zero_ReliesOnNullFallback_AndReturnsZero()
    {
        // Arrange
        // Regression guard: removing the null fallback in the SecureBigInteger
        // constructor would break Calculator<SecureBigInteger>.Zero (and every
        // dependent chain: One, Two, etc.).
        using var zero = Calculator<SecureBigInteger>.Zero;

        // Act & Assert
        Assert.True(zero.Value.IsZero);
    }

    /// <summary>
    /// Tests that the <c>(byte[], int)</c> constructor decodes a little-endian
    /// two's-complement byte array into the matching <see cref="SecureBigInteger"/> value,
    /// including the boundary case <see cref="long.MinValue"/>.
    /// </summary>
    [Fact]
    public void Constructor_WithByteArray_ShouldInitializeValue()
    {
        // Arrange
        using var expected = new SecureBigInteger(long.MinValue);
        using var data = expected.ToByteArray();

        // Act
        using Calculator<SecureBigInteger> calculator = new SecureBigIntCalculator(data.PoolArray, data.Length);

        // Assert
        Assert.Equal(expected, calculator.Value);
    }

    /// <summary>
    /// Tests that <see cref="SecureBigIntCalculator.Equals(Calculator{SecureBigInteger})"/>
    /// returns <see langword="true"/> for two calculators wrapping equal
    /// <see cref="SecureBigInteger"/> values.
    /// </summary>
    [Fact]
    public void Equals_ShouldReturnTrue_ForEqualValues()
    {
        // Arrange
        using Calculator<SecureBigInteger> calculator1 = new SecureBigIntCalculator(new SecureBigInteger(12345));
        using Calculator<SecureBigInteger> calculator2 = new SecureBigIntCalculator(new SecureBigInteger(12345));

        // Act & Assert
        Assert.True(calculator1.Equals(calculator2));
    }

    /// <summary>
    /// Tests that <see cref="SecureBigIntCalculator.Equals(Calculator{SecureBigInteger})"/>
    /// returns <see langword="false"/> for two calculators wrapping different
    /// <see cref="SecureBigInteger"/> values.
    /// </summary>
    [Fact]
    public void Equals_ShouldReturnFalse_ForDifferentValues()
    {
        // Arrange
        using Calculator<SecureBigInteger> calculator1 = new SecureBigIntCalculator(new SecureBigInteger(12345));
        using Calculator<SecureBigInteger> calculator2 = new SecureBigIntCalculator(new SecureBigInteger(67890));

        // Act & Assert
        Assert.False(calculator1.Equals(calculator2));
    }

    /// <summary>
    /// Tests the <c>&gt;</c> operator on <see cref="Calculator{SecureBigInteger}"/> against
    /// rhs values both below and above the lhs.
    /// </summary>
    [Fact]
    public void GreaterThan_ShouldReturnCorrectResult()
    {
        // Arrange
        using Calculator<SecureBigInteger> calculator = new SecureBigIntCalculator(new SecureBigInteger(10));
        using Calculator<SecureBigInteger> rhs5 = new SecureBigIntCalculator(new SecureBigInteger(5));
        using Calculator<SecureBigInteger> rhs15 = new SecureBigIntCalculator(new SecureBigInteger(15));

        // Act & Assert
        Assert.True(calculator > rhs5);
        Assert.False(calculator > rhs15);
    }

    /// <summary>
    /// Tests the <c>&lt;</c> operator on <see cref="Calculator{SecureBigInteger}"/> against
    /// rhs values both above and below the lhs.
    /// </summary>
    [Fact]
    public void LowerThan_ShouldReturnCorrectResult()
    {
        // Arrange
        using Calculator<SecureBigInteger> calculator = new SecureBigIntCalculator(new SecureBigInteger(10));
        using Calculator<SecureBigInteger> rhs5 = new SecureBigIntCalculator(new SecureBigInteger(5));
        using Calculator<SecureBigInteger> rhs15 = new SecureBigIntCalculator(new SecureBigInteger(15));

        // Act & Assert
        Assert.True(calculator < rhs15);
        Assert.False(calculator < rhs5);
    }

    /// <summary>
    /// Tests the <c>&gt;=</c> operator on <see cref="Calculator{SecureBigInteger}"/> across
    /// the equal, strictly-greater, and strictly-lower comparison cases.
    /// </summary>
    [Fact]
    public void EqualOrGreaterThan_ShouldReturnCorrectResult()
    {
        // Arrange
        using Calculator<SecureBigInteger> calculator = new SecureBigIntCalculator(new SecureBigInteger(10));
        using Calculator<SecureBigInteger> rhs5 = new SecureBigIntCalculator(new SecureBigInteger(5));
        using Calculator<SecureBigInteger> rhs10 = new SecureBigIntCalculator(new SecureBigInteger(10));
        using Calculator<SecureBigInteger> rhs11 = new SecureBigIntCalculator(new SecureBigInteger(11));

        // Act & Assert
        Assert.True(calculator >= rhs10);
        Assert.True(calculator >= rhs5);
        Assert.False(calculator >= rhs11);
    }

    /// <summary>
    /// Tests the <c>&lt;=</c> operator on <see cref="Calculator{SecureBigInteger}"/> across
    /// the equal, strictly-lower, and strictly-greater comparison cases.
    /// </summary>
    [Fact]
    public void EqualOrLowerThan_ShouldReturnCorrectResult()
    {
        // Arrange
        using Calculator<SecureBigInteger> calculator = new SecureBigIntCalculator(new SecureBigInteger(10));
        using Calculator<SecureBigInteger> rhs5 = new SecureBigIntCalculator(new SecureBigInteger(5));
        using Calculator<SecureBigInteger> rhs10 = new SecureBigIntCalculator(new SecureBigInteger(10));
        using Calculator<SecureBigInteger> rhs11 = new SecureBigIntCalculator(new SecureBigInteger(11));

        // Act & Assert
        Assert.True(calculator <= rhs10);
        Assert.True(calculator <= rhs11);
        Assert.False(calculator <= rhs5);
    }

    /// <summary>
    /// Tests <see cref="SecureBigIntCalculator.CompareTo(Calculator{SecureBigInteger})"/>:
    /// returns <c>-1</c>, <c>0</c>, or <c>+1</c> depending on whether the lhs is less than,
    /// equal to, or greater than the rhs.
    /// </summary>
    [Fact]
    public void CompareTo_ShouldReturnCorrectComparison()
    {
        // Arrange
        using var calculator1 = new SecureBigIntCalculator(new SecureBigInteger(10));
        using var calculator2 = new SecureBigIntCalculator(new SecureBigInteger(15));

        // Act & Assert
        Assert.Equal(-1, calculator1.CompareTo(calculator2));
        Assert.Equal(1, calculator2.CompareTo(calculator1));
        Assert.Equal(0, calculator1.CompareTo(calculator1));
    }

    /// <summary>
    /// Tests the inherited arithmetic operator surface on
    /// <see cref="Calculator{SecureBigInteger}"/>: <c>+</c>, <c>-</c>, <c>*</c>, <c>/</c>,
    /// <c>%</c> across operand pairs that exercise both exact-division and non-zero-remainder
    /// paths.
    /// </summary>
    [Fact]
    public void ArithmeticOperations_ShouldReturnCorrectResults()
    {
        // Arrange — operand 5 / 10 / 11 are reused; expected results are pre-allocated.
        using Calculator<SecureBigInteger> calculator = new SecureBigIntCalculator(new SecureBigInteger(10));
        using Calculator<SecureBigInteger> rhs5 = new SecureBigIntCalculator(new SecureBigInteger(5));
        using Calculator<SecureBigInteger> rhs10 = new SecureBigIntCalculator(new SecureBigInteger(10));
        using Calculator<SecureBigInteger> rhs11 = new SecureBigIntCalculator(new SecureBigInteger(11));
        using Calculator<SecureBigInteger> expected15 = new SecureBigIntCalculator(new SecureBigInteger(15));
        using Calculator<SecureBigInteger> expected50 = new SecureBigIntCalculator(new SecureBigInteger(50));
        using Calculator<SecureBigInteger> expected2 = new SecureBigIntCalculator(new SecureBigInteger(2));
        using Calculator<SecureBigInteger> expected1 = new SecureBigIntCalculator(new SecureBigInteger(1));
        using Calculator<SecureBigInteger> expected0 = new SecureBigIntCalculator(new SecureBigInteger(0));

        // Act
        using var sum = calculator + rhs5;
        using var difference = calculator - rhs5;
        using var product = calculator * rhs5;
        using var quotientBy5 = calculator / rhs5;
        using var quotientBy10 = calculator / rhs10;
        using var moduloBy5 = calculator % rhs5;
        using var moduloBy11 = calculator % rhs11;

        // Assert
        Assert.Equal(expected15, sum);
        Assert.Equal(rhs5, difference);
        Assert.Equal(expected50, product);
        Assert.Equal(expected2, quotientBy5);
        Assert.Equal(expected1, quotientBy10);
        Assert.Equal(expected0, moduloBy5);
        Assert.Equal(rhs10, moduloBy11);
    }

    /// <summary>
    /// Tests that the <c>++</c> operator on <see cref="Calculator{SecureBigInteger}"/>
    /// returns a new calculator whose value is <c>source + 1</c>, and that the original
    /// source calculator is not mutated.
    /// </summary>
    [Fact]
    public void Increment_ShouldIncreaseValueByOne()
    {
        // Arrange
        // Keep a separate reference to the source object so that we can verify it
        // remains untouched: ++ reassigns the local `working` to point at the
        // freshly-allocated incremented Calculator, but the original object that
        // `source` still references must not have been mutated.
        using var source = new SecureBigIntCalculator(new SecureBigInteger(10));
        Calculator<SecureBigInteger> working = source;

        // Act
        using var incrementedCalculator = ++working;

        // Assert
        using var expected11 = new SecureBigInteger(11);
        using var expected10 = new SecureBigInteger(10);
        Assert.Equal(expected11, incrementedCalculator.Value);
        Assert.Equal(expected10, source.Value);
    }

    /// <summary>
    /// Tests that the <c>--</c> operator on <see cref="Calculator{SecureBigInteger}"/>
    /// returns a new calculator whose value is <c>source - 1</c>, and that the original
    /// source calculator is not mutated.
    /// </summary>
    [Fact]
    public void Decrement_ShouldDecreaseValueByOne()
    {
        // Arrange
        using var source = new SecureBigIntCalculator(new SecureBigInteger(10));
        Calculator<SecureBigInteger> working = source;

        // Act
        using var decrementedCalculator = --working;

        // Assert
        using var expected9 = new SecureBigInteger(9);
        using var expected10 = new SecureBigInteger(10);
        Assert.Equal(expected9, decrementedCalculator.Value);
        Assert.Equal(expected10, source.Value);
    }

    /// <summary>
    /// Smoke test for 100 <c>++</c>/<c>--</c> iterations against a single source: the
    /// pinned-pool state must survive the churn without double-disposal or corruption,
    /// and the source's value must remain unchanged throughout.
    /// </summary>
    [Fact]
    public void IncrementDecrement_RepeatedCalls_NoCrashOrLeak()
    {
        // Arrange
        // Smoke test: 100 iterations of ++ / -- against a single source must not
        // crash, double-dispose, or otherwise corrupt pinned-pool state. Each
        // iteration aliases the source into a local and pre-increments/decrements
        // the alias — `++` reassigns the local to a fresh wrapper without
        // touching `source`, and the result is captured and disposed on the spot.
        using var source = new SecureBigIntCalculator(new SecureBigInteger(50));
        using var expected51 = new SecureBigInteger(51);
        using var expected50 = new SecureBigInteger(50);
        using var expected49 = new SecureBigInteger(49);

        // Act & Assert
        Assert.All(Enumerable.Range(0, 100), _ =>
        {
            Calculator<SecureBigInteger> working = source;
            using (var incremented = ++working)
            {
                Assert.Equal(expected51, incremented.Value);
            }

            working = source;
            using (var decremented = --working)
            {
                Assert.Equal(expected49, decremented.Value);
            }

            Assert.Equal(expected50, source.Value);
        });
    }

    /// <summary>
    /// Tests that <see cref="SecureBigIntCalculator.Abs"/> returns the absolute value for a
    /// negative source.
    /// </summary>
    [Fact]
    public void Abs_ShouldReturnAbsoluteValue()
    {
        // Arrange
        using Calculator<SecureBigInteger> calculator = new SecureBigIntCalculator(new SecureBigInteger(-10));

        // Act
        using var absCalculator = calculator.Abs();

        // Assert
        using var expected = new SecureBigInteger(10);
        Assert.Equal(expected, absCalculator.Value);
    }

    /// <summary>
    /// Tests that <see cref="SecureBigIntCalculator.Pow(int)"/> raises the base value to the
    /// supplied integer exponent (<c>2^3 = 8</c>).
    /// </summary>
    [Fact]
    public void Pow_ShouldReturnCorrectPower()
    {
        // Arrange
        using Calculator<SecureBigInteger> calculator = new SecureBigIntCalculator(new SecureBigInteger(2));

        // Act
        using var result = calculator.Pow(3);

        // Assert
        using var expected = new SecureBigInteger(8);
        Assert.Equal(expected, result.Value);
    }

    /// <summary>
    /// Tests that <see cref="SecureBigIntCalculator.IsZero"/> distinguishes zero from
    /// non-zero values.
    /// </summary>
    [Fact]
    public void IsZero_ShouldReturnCorrectResult()
    {
        // Arrange
        using Calculator<SecureBigInteger> zeroCalculator = new SecureBigIntCalculator(new SecureBigInteger(0));
        using Calculator<SecureBigInteger> nonZeroCalculator = new SecureBigIntCalculator(new SecureBigInteger(5));

        // Act & Assert
        Assert.True(zeroCalculator.IsZero);
        Assert.False(nonZeroCalculator.IsZero);
    }

    /// <summary>
    /// Tests that <see cref="SecureBigIntCalculator.IsOne"/> distinguishes one from
    /// non-one values.
    /// </summary>
    [Fact]
    public void IsOne_ShouldReturnCorrectResult()
    {
        // Arrange
        using Calculator<SecureBigInteger> oneCalculator = new SecureBigIntCalculator(new SecureBigInteger(1));
        using Calculator<SecureBigInteger> nonOneCalculator = new SecureBigIntCalculator(new SecureBigInteger(5));

        // Act & Assert
        Assert.True(oneCalculator.IsOne);
        Assert.False(nonOneCalculator.IsOne);
    }

    /// <summary>
    /// Tests that <see cref="SecureBigIntCalculator.IsEven"/> distinguishes even from odd
    /// values on small inputs.
    /// </summary>
    [Fact]
    public void IsEven_ShouldReturnCorrectResult()
    {
        // Arrange
        using Calculator<SecureBigInteger> evenCalculator = new SecureBigIntCalculator(new SecureBigInteger(6));
        using Calculator<SecureBigInteger> oddCalculator = new SecureBigIntCalculator(new SecureBigInteger(5));

        // Act & Assert
        Assert.True(evenCalculator.IsEven);
        Assert.False(oddCalculator.IsEven);
    }

    /// <summary>
    /// Tests that <see cref="SecureBigIntCalculator.IsEven"/> behaves correctly across the
    /// integer boundary values (zero, negative, <c>int.Max/MinValue</c>,
    /// <c>long.Max/MinValue</c>) — guards against sign-bit handling regressions.
    /// </summary>
    /// <param name="value">The boundary value to test.</param>
    /// <param name="expectedEven">Whether the value is mathematically even.</param>
    [Theory]
    [InlineData(0L, true)]
    [InlineData(-2L, true)]
    [InlineData(-3L, false)]
    [InlineData(int.MaxValue, false)]
    [InlineData(int.MinValue, true)]
    [InlineData(long.MaxValue, false)]
    [InlineData(long.MinValue, true)]
    public void IsEven_HandlesBoundaryValues(long value, bool expectedEven)
    {
        // Arrange
        using Calculator<SecureBigInteger> calculator = new SecureBigIntCalculator(new SecureBigInteger(value));

        // Act & Assert
        Assert.Equal(expectedEven, calculator.IsEven);
    }

    /// <summary>
    /// Tests that <see cref="SecureBigIntCalculator.ByteRepresentation"/> matches
    /// <see cref="SecureBigInteger.ToByteArray"/> byte-for-byte on the same source value.
    /// </summary>
    [Fact]
    public void ByteRepresentation_ShouldReturnCorrectBytes()
    {
        // Arrange
        using var value = new SecureBigInteger(1234567890);
        using var calculator = new SecureBigIntCalculator(value);
        using var expectedPinnedPoolArray = value.ToByteArray();

        // Act
        using var actualPinnedPoolArray = calculator.ByteRepresentation;

        // Assert
        Assert.Equal(expectedPinnedPoolArray.Length, actualPinnedPoolArray.Length);
        Assert.True(expectedPinnedPoolArray.PoolArray
            .Take(expectedPinnedPoolArray.Length)
            .SequenceEqual(actualPinnedPoolArray.PoolArray.Take(actualPinnedPoolArray.Length)));
    }

    /// <summary>
    /// Tests that <see cref="SecureBigIntCalculator.ByteCount"/> matches the serialized
    /// length produced by <see cref="SecureBigInteger.ToByteArray"/> — the contract that
    /// <c>Share&lt;TNumber&gt;.GetCharCount</c> relies on. Covers magnitude-only values
    /// (no sentinel), high-bit-set positive values (sentinel appended), and negative
    /// values (no sentinel), to ensure the Sentinel-needed rule is honoured by the
    /// pure-arithmetic <c>SerializedByteCount</c> delegation.
    /// </summary>
    /// <param name="value">A representative signed value.</param>
    [Theory]
    [InlineData(0L)]
    [InlineData(127L)]          // high-bit clear: no sentinel
    [InlineData(128L)]          // high-bit set: sentinel
    [InlineData(255L)]          // high-bit set: sentinel
    [InlineData(256L)]          // multi-byte magnitude, high byte high-bit clear
    [InlineData(32768L)]        // multi-byte magnitude, high byte high-bit set
    [InlineData(1234567890L)]
    [InlineData(-1L)]           // negative: no sentinel
    [InlineData(-128L)]         // negative two's-complement boundary
    [InlineData(long.MaxValue)]
    [InlineData(long.MinValue)]
    public void ByteCount_MatchesByteRepresentationLength(long value)
    {
        // Arrange
        using var secureBigInt = new SecureBigInteger(value);
        using var calculator = new SecureBigIntCalculator(secureBigInt);
        using var pinnedBytes = secureBigInt.ToByteArray();

        // Act & Assert
        Assert.Equal(pinnedBytes.Length, calculator.ByteCount);
    }

    /// <summary>
    /// Tests the concurrent-disposal contract: when two threads race to call
    /// <see cref="SecureBigIntCalculator.Dispose"/>, the atomic
    /// <see cref="System.Threading.Interlocked.Exchange(ref int, int)"/> guard ensures a
    /// single winner. The loser sees <c>disposed == 1</c> and returns without re-entering
    /// the underlying <c>SecureBigInteger.Dispose</c> — no double-free, no exception.
    /// </summary>
    [Fact]
    public void Dispose_TwiceFromMultipleThreads_DoesNotDoubleFree()
    {
        // Arrange
        // Concurrent Dispose calls must not let both threads reach
        // `this.Value.Dispose()`. The atomic Interlocked.Exchange guard ensures a
        // single winner; the loser observes `disposed == 1` and returns.

        // Act & Assert
        Assert.All(Enumerable.Range(0, 50), _ =>
        {
            var calculator = new SecureBigIntCalculator(new SecureBigInteger(42));

            Exception ex1 = null;
            Exception ex2 = null;
            var t1 = new Thread(() =>
            {
                try { calculator.Dispose(); }
                catch (Exception ex) { ex1 = ex; }
            });
            var t2 = new Thread(() =>
            {
                try { calculator.Dispose(); }
                catch (Exception ex) { ex2 = ex; }
            });

            t1.Start();
            t2.Start();
            t1.Join();
            t2.Join();

            Assert.Null(ex1);
            Assert.Null(ex2);
        });
    }
}
