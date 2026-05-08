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

public class SecureBigIntCalculatorTest
{
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

    [Fact]
    public void Calculator_Zero_ReliesOnNullFallback_AndReturnsZero()
    {
        // Arrange
        // Regression guard: removing the null fallback in the SecureBigInteger
        // constructor would break Calculator<SecureBigInteger>.Zero (and the
        // chains that depend on it: One, Two, every Sqrt pre-check that
        // compares against Zero).
        using var zero = Calculator<SecureBigInteger>.Zero;

        // Act & Assert
        Assert.True(zero.Value.IsZero);
    }

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

    [Fact]
    public void Equals_ShouldReturnTrue_ForEqualValues()
    {
        // Arrange
        using Calculator<SecureBigInteger> calculator1 = new SecureBigIntCalculator(new SecureBigInteger(12345));
        using Calculator<SecureBigInteger> calculator2 = new SecureBigIntCalculator(new SecureBigInteger(12345));

        // Act & Assert
        Assert.True(calculator1.Equals(calculator2));
    }

    [Fact]
    public void Equals_ShouldReturnFalse_ForDifferentValues()
    {
        // Arrange
        using Calculator<SecureBigInteger> calculator1 = new SecureBigIntCalculator(new SecureBigInteger(12345));
        using Calculator<SecureBigInteger> calculator2 = new SecureBigIntCalculator(new SecureBigInteger(67890));

        // Act & Assert
        Assert.False(calculator1.Equals(calculator2));
    }

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
        for (int i = 0; i < 100; i++)
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
        }
    }

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

    [Fact]
    public void Sqrt_ShouldReturnCorrectResultForPerfectSquare()
    {
        // Arrange
        using Calculator<SecureBigInteger> calculator = new SecureBigIntCalculator(new SecureBigInteger(16));

        // Act
        using var result = calculator.Sqrt();

        // Assert
        using var expected = new SecureBigInteger(4);
        Assert.Equal(expected, result.Value);
    }

    [Fact]
    public void Sqrt_OfZero_ReturnsZero()
    {
        // Arrange
        using Calculator<SecureBigInteger> calculator = new SecureBigIntCalculator(new SecureBigInteger(0));

        // Act
        using var result = calculator.Sqrt();

        // Assert
        Assert.True(result.Value.IsZero);
    }

    [Fact]
    public void Sqrt_ShouldThrowExceptionForNegativeValue()
    {
        // Arrange
        using Calculator<SecureBigInteger> calculator = new SecureBigIntCalculator(new SecureBigInteger(-16));

        // Act & Assert
        var arithmeticException = Assert.Throws<ArithmeticException>(() => calculator.Sqrt());
        Assert.Equal(ErrorMessages.SqrtOfNegativeIsNaN, arithmeticException.Message);
    }

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

    [Fact]
    public void ByteCount_ShouldReturnCorrectNumberOfBytes()
    {
        // Arrange
        using var value = new SecureBigInteger(1234567890);
        using var calculator = new SecureBigIntCalculator(value);

        // Act & Assert
        Assert.Equal(value.ByteCount, calculator.ByteCount);
    }

    [Fact]
    public void Dispose_TwiceFromMultipleThreads_DoesNotDoubleFree()
    {
        // Arrange
        // Concurrent Dispose calls must not let both threads reach
        // `this.Value.Dispose()`. The atomic Interlocked.Exchange guard ensures a
        // single winner; the loser observes `disposed == 1` and returns.

        // Act & Assert
        for (int iteration = 0; iteration < 50; iteration++)
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
        }
    }
}
