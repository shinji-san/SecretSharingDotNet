// ----------------------------------------------------------------------------
// <copyright file="ConsolePasswordReaderTest.cs" company="Private">
// Copyright (c) 2026 All Rights Reserved
// </copyright>
// <author>Sebastian Walther</author>
// <date>05/02/2026</date>
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

namespace SecretSharingDotNetTest.Cryptography.SecureInput;

using System;
using System.Collections.Generic;
using System.Text;
using SecretSharingDotNet.Cryptography.SecureInput;
using Xunit;

public class ConsolePasswordReaderTest
{
    [Fact]
    public void ReadPassword_NegativeMaxLength_ThrowsArgumentOutOfRangeException()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => ConsolePasswordReader.ReadPassword(-1));
    }

    [Fact]
    public void ReadPassword_ZeroMaxLength_ThrowsArgumentOutOfRangeException()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => ConsolePasswordReader.ReadPassword(0));
    }

    [Fact]
    public void ReadPassword_WhenInputIsRedirected_ThrowsInvalidOperationException()
    {
        // The xUnit test runner runs with stdin redirected, so this hits the redirect guard.
        Assert.Throws<InvalidOperationException>(() => ConsolePasswordReader.ReadPassword(8));
    }

    [Fact]
    public void ReadPasswordLoop_EnterImmediately_ReturnsEmptyBuffer()
    {
        // Arrange
        var keys = MakeKeys(Enter());

        // Act
        using var pinned = ConsolePasswordReader.ReadPasswordLoop(keys.Dequeue, 8, null, _ => { });

        // Assert
        Assert.Equal(0, pinned.Length);
        Assert.True(pinned.Capacity >= 8);
    }

    [Fact]
    public void ReadPasswordLoop_TypicalInput_AccumulatesChars()
    {
        // Arrange
        var keys = MakeKeys(Char('a'), Char('b'), Char('c'), Enter());

        // Act
        using var pinned = ConsolePasswordReader.ReadPasswordLoop(keys.Dequeue, 8, null, _ => { });

        // Assert
        Assert.Equal(3, pinned.Length);
        Assert.Equal('a', pinned[0]);
        Assert.Equal('b', pinned[1]);
        Assert.Equal('c', pinned[2]);
    }

    [Fact]
    public void ReadPasswordLoop_Backspace_RemovesLastChar()
    {
        // Arrange
        var keys = MakeKeys(Char('a'), Char('b'), Backspace(), Char('c'), Enter());

        // Act
        using var pinned = ConsolePasswordReader.ReadPasswordLoop(keys.Dequeue, 8, null, _ => { });

        // Assert
        Assert.Equal(2, pinned.Length);
        Assert.Equal('a', pinned[0]);
        Assert.Equal('c', pinned[1]);
    }

    [Fact]
    public void ReadPasswordLoop_BackspaceOnEmptyBuffer_IsNoOp()
    {
        // Arrange
        var keys = MakeKeys(Backspace(), Backspace(), Char('x'), Enter());

        // Act
        using var pinned = ConsolePasswordReader.ReadPasswordLoop(keys.Dequeue, 8, null, _ => { });

        // Assert
        Assert.Equal(1, pinned.Length);
        Assert.Equal('x', pinned[0]);
    }

    [Fact]
    public void ReadPasswordLoop_BackspaceClearsCharSlot()
    {
        // Arrange
        var keys = MakeKeys(Char('S'), Backspace(), Enter());

        // Act
        using var pinned = ConsolePasswordReader.ReadPasswordLoop(keys.Dequeue, 4, null, _ => { });

        // Assert — the slot beyond the logical length must have been wiped on backspace.
        Assert.Equal(0, pinned.Length);
        Assert.Equal('\0', pinned.PoolArray[0]);
    }

    [Fact]
    public void ReadPasswordLoop_MaxLengthReached_IgnoresFurtherChars()
    {
        // Arrange
        var keys = MakeKeys(Char('a'), Char('b'), Char('c'), Char('d'), Enter());

        // Act
        using var pinned = ConsolePasswordReader.ReadPasswordLoop(keys.Dequeue, 2, null, _ => { });

        // Assert
        Assert.Equal(2, pinned.Length);
        Assert.Equal('a', pinned[0]);
        Assert.Equal('b', pinned[1]);
    }

    [Fact]
    public void ReadPasswordLoop_AfterMaxReached_BackspaceStillWorks()
    {
        // Arrange
        var keys = MakeKeys(Char('a'), Char('b'), Char('c'), Backspace(), Char('Z'), Enter());

        // Act
        using var pinned = ConsolePasswordReader.ReadPasswordLoop(keys.Dequeue, 2, null, _ => { });

        // Assert
        Assert.Equal(2, pinned.Length);
        Assert.Equal('a', pinned[0]);
        Assert.Equal('Z', pinned[1]);
    }

    [Fact]
    public void ReadPasswordLoop_ControlKeys_AreIgnored()
    {
        // Arrange
        var keys = MakeKeys(Char('a'), Tab(), Esc(), Char('b'), Enter());

        // Act
        using var pinned = ConsolePasswordReader.ReadPasswordLoop(keys.Dequeue, 8, null, _ => { });

        // Assert
        Assert.Equal(2, pinned.Length);
        Assert.Equal('a', pinned[0]);
        Assert.Equal('b', pinned[1]);
    }

    [Fact]
    public void ReadPasswordLoop_NoEcho_DoesNotInvokeSink()
    {
        // Arrange
        var keys = MakeKeys(Char('a'), Char('b'), Backspace(), Enter());
        var sink = new StringBuilder();

        // Act
        using var pinned = ConsolePasswordReader.ReadPasswordLoop(keys.Dequeue, 8, null, s => sink.Append(s));

        // Assert
        Assert.Equal(0, sink.Length);
        Assert.Equal(1, pinned.Length);
    }

    [Fact]
    public void ReadPasswordLoop_WithEcho_EmitsMaskCharPerKey()
    {
        // Arrange
        var keys = MakeKeys(Char('a'), Char('b'), Char('c'), Enter());
        var sink = new StringBuilder();

        // Act
        using var pinned = ConsolePasswordReader.ReadPasswordLoop(keys.Dequeue, 8, '*', s => sink.Append(s));

        // Assert
        Assert.Equal("***", sink.ToString());
        Assert.Equal(3, pinned.Length);
    }

    [Fact]
    public void ReadPasswordLoop_WithEcho_BackspaceEmitsEraseSequence()
    {
        // Arrange
        var keys = MakeKeys(Char('a'), Backspace(), Enter());
        var sink = new StringBuilder();

        // Act
        using var pinned = ConsolePasswordReader.ReadPasswordLoop(keys.Dequeue, 8, '*', s => sink.Append(s));

        // Assert
        Assert.Equal("*\b \b", sink.ToString());
        Assert.Equal(0, pinned.Length);
    }

    [Fact]
    public void ReadPasswordLoop_WithEcho_BackspaceOnEmpty_NoEcho()
    {
        // Arrange
        var keys = MakeKeys(Backspace(), Char('a'), Enter());
        var sink = new StringBuilder();

        // Act
        using var pinned = ConsolePasswordReader.ReadPasswordLoop(keys.Dequeue, 8, '*', s => sink.Append(s));

        // Assert
        Assert.Equal("*", sink.ToString());
        Assert.Equal(1, pinned.Length);
    }

    private static Queue<ConsoleKeyInfo> MakeKeys(params ConsoleKeyInfo[] items)
    {
        return new Queue<ConsoleKeyInfo>(items);
    }

    private static ConsoleKeyInfo Char(char c) =>
        new ConsoleKeyInfo(c, CharToKey(c), shift: false, alt: false, control: false);

    private static ConsoleKeyInfo Enter() =>
        new ConsoleKeyInfo('\r', ConsoleKey.Enter, shift: false, alt: false, control: false);

    private static ConsoleKeyInfo Backspace() =>
        new ConsoleKeyInfo('\b', ConsoleKey.Backspace, shift: false, alt: false, control: false);

    private static ConsoleKeyInfo Tab() =>
        new ConsoleKeyInfo('\t', ConsoleKey.Tab, shift: false, alt: false, control: false);

    private static ConsoleKeyInfo Esc() =>
        new ConsoleKeyInfo('\x1B', ConsoleKey.Escape, shift: false, alt: false, control: false);

    private static ConsoleKey CharToKey(char c)
    {
        if (c >= 'a' && c <= 'z')
        {
            return (ConsoleKey)('A' + (c - 'a'));
        }
        if (c >= 'A' && c <= 'Z')
        {
            return (ConsoleKey)c;
        }
        if (c >= '0' && c <= '9')
        {
            return (ConsoleKey)c;
        }
        return ConsoleKey.Oem8;
    }
}