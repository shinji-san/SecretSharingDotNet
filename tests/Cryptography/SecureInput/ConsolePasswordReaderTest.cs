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
using System.IO;
using System.Text;
using SecretSharingDotNet.Cryptography.SecureArray;
using SecretSharingDotNet.Cryptography.SecureInput;
using Xunit;

/// <summary>
/// Tests for <see cref="ConsolePasswordReader"/> — argument validation on the public
/// <c>ReadPassword</c> wrapper and the keystroke-loop behaviour exposed through the
/// internal <c>ReadPasswordLoop</c> helper (injected key source + sink for echo).
/// </summary>
public class ConsolePasswordReaderTest
{
    /// <summary>
    /// Tests that <see cref="ConsolePasswordReader.ReadPassword"/> rejects a negative
    /// <c>maxLength</c> with <see cref="ArgumentOutOfRangeException"/>.
    /// </summary>
    [Fact]
    public void ReadPassword_NegativeMaxLength_ThrowsArgumentOutOfRangeException()
    {
        // Act & Assert
        Assert.Throws<ArgumentOutOfRangeException>(() => ConsolePasswordReader.ReadPassword(-1));
    }

    /// <summary>
    /// Tests that <see cref="ConsolePasswordReader.ReadPassword"/> rejects a zero
    /// <c>maxLength</c> with <see cref="ArgumentOutOfRangeException"/> — a buffer of length
    /// zero cannot hold any password material.
    /// </summary>
    [Fact]
    public void ReadPassword_ZeroMaxLength_ThrowsArgumentOutOfRangeException()
    {
        // Act & Assert
        Assert.Throws<ArgumentOutOfRangeException>(() => ConsolePasswordReader.ReadPassword(0));
    }

    /// <summary>
    /// Tests that <see cref="ConsolePasswordReader.ReadPassword"/> refuses to read from a
    /// redirected stdin with <see cref="InvalidOperationException"/> — interactive password
    /// entry requires a real console. xUnit's test runner runs with stdin redirected, so
    /// the guard fires here as part of normal test execution.
    /// </summary>
    [Fact]
    public void ReadPassword_WhenInputIsRedirected_ThrowsInvalidOperationException()
    {
        // Act & Assert — the xUnit test runner runs with stdin redirected, so this hits the redirect guard.
        Assert.Throws<InvalidOperationException>(() => ConsolePasswordReader.ReadPassword(8));
    }

    /// <summary>
    /// Tests that <see cref="ConsolePasswordReader.ReadPasswordLoop"/> returns a zero-length
    /// (but non-zero-capacity) pinned buffer when the very first key is <c>Enter</c>.
    /// </summary>
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

    /// <summary>
    /// Tests that <see cref="ConsolePasswordReader.ReadPasswordLoop"/> accumulates typed
    /// characters into the pinned buffer in order, terminating on <c>Enter</c>.
    /// </summary>
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

    /// <summary>
    /// Tests that <c>Backspace</c> in <see cref="ConsolePasswordReader.ReadPasswordLoop"/>
    /// removes the most recently entered character and the next typed character takes its
    /// place.
    /// </summary>
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

    /// <summary>
    /// Tests that <c>Backspace</c> on an already-empty buffer is a no-op rather than an
    /// error — the loop continues to accept further input.
    /// </summary>
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

    /// <summary>
    /// Tests that <c>Backspace</c> wipes the just-removed character slot to <c>\0</c> rather
    /// than leaving the stale character behind beyond the logical length — security-relevant
    /// because the slot would otherwise survive in pinned memory until <c>Dispose</c>.
    /// </summary>
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

    /// <summary>
    /// Tests that once the buffer fills to <c>maxLength</c>, further character keys are
    /// silently ignored (the loop stays at the cap rather than truncating or extending).
    /// </summary>
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

    /// <summary>
    /// Tests that after the buffer reached <c>maxLength</c>, <c>Backspace</c> still removes
    /// the last character and a subsequent character key can refill the freed slot.
    /// </summary>
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

    /// <summary>
    /// Tests that non-character control keys (<c>Tab</c>, <c>Esc</c>, …) inside the typing
    /// loop are ignored without breaking the read — only printable characters,
    /// <c>Backspace</c>, and <c>Enter</c> have visible effect.
    /// </summary>
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

    /// <summary>
    /// Tests that a <see langword="null"/> mask-character disables echo entirely — the sink
    /// callback never gets invoked even though the buffer still accumulates input.
    /// </summary>
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

    /// <summary>
    /// Tests that with a configured mask character, the sink receives that mask character
    /// once per accepted character key — no preview of the typed character itself.
    /// </summary>
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

    /// <summary>
    /// Tests that <c>Backspace</c> with echo enabled emits the canonical
    /// <c>\b space \b</c> erase sequence to the sink so the masked echo display stays
    /// in sync with the buffer.
    /// </summary>
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

    /// <summary>
    /// Tests that <c>Backspace</c> with echo enabled emits no erase sequence when the buffer
    /// is already empty — only real removals produce output.
    /// </summary>
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

    /// <summary>
    /// Tests that when <c>readKey</c> throws after at least one character has already been
    /// typed into the pinned buffer, <see cref="ConsolePasswordReader.ReadPasswordLoop(System.Func{System.ConsoleKeyInfo},int,char?,System.Action{string},System.Func{int,PinnedPoolArray{char}})"/>
    /// disposes that buffer before rethrowing — sensitive partial input must not survive in
    /// pinned memory until the non-deterministic finalizer runs.
    /// </summary>
    [Fact]
    public void ReadPasswordLoop_WhenReadKeyThrows_DisposesPinnedBuffer()
    {
        // Arrange
        PinnedPoolArray<char> captured = null;
        int step = 0;
        Func<ConsoleKeyInfo> readKey = () =>
        {
            if (step++ == 0)
            {
                return Char('a');
            }

            throw new IOException("simulated readKey failure");
        };
        Func<int, PinnedPoolArray<char>> factory = capacity =>
        {
            captured = new PinnedPoolArray<char>(capacity);
            return captured;
        };

        // Act
        var thrown = Assert.Throws<IOException>(() =>
            ConsolePasswordReader.ReadPasswordLoop(readKey, 8, null, _ => { }, factory));

        // Assert
        Assert.Equal("simulated readKey failure", thrown.Message);
        Assert.NotNull(captured);
        Assert.True(captured.IsDisposed);
    }

    /// <summary>
    /// Tests that when <c>echoSink</c> throws while the loop is forwarding an accepted
    /// keystroke, <see cref="ConsolePasswordReader.ReadPasswordLoop(System.Func{System.ConsoleKeyInfo},int,char?,System.Action{string},System.Func{int,PinnedPoolArray{char}})"/>
    /// disposes the pinned buffer before rethrowing — the just-accepted character is
    /// already resident in pinned memory and must be wiped on the failure path.
    /// </summary>
    [Fact]
    public void ReadPasswordLoop_WhenEchoSinkThrows_DisposesPinnedBuffer()
    {
        // Arrange
        PinnedPoolArray<char> captured = null;
        var keys = MakeKeys(Char('a'), Enter());
        Action<string> echoSink = _ => throw new IOException("simulated echoSink failure");
        Func<int, PinnedPoolArray<char>> factory = capacity =>
        {
            captured = new PinnedPoolArray<char>(capacity);
            return captured;
        };

        // Act
        var thrown = Assert.Throws<IOException>(() =>
            ConsolePasswordReader.ReadPasswordLoop(keys.Dequeue, 8, '*', echoSink, factory));

        // Assert
        Assert.Equal("simulated echoSink failure", thrown.Message);
        Assert.NotNull(captured);
        Assert.True(captured.IsDisposed);
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