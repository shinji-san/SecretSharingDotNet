// ----------------------------------------------------------------------------
// <copyright file="ConsolePasswordReader.cs" company="Private">
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

namespace SecretSharingDotNet.Cryptography.SecureInput;

using System;
using SecureArray;

/// <summary>
/// Provides interactive console-based password input that lands directly in pinned,
/// securely cleared memory.
/// </summary>
public static class ConsolePasswordReader
{
    /// <summary>
    /// Reads a line of input interactively from the standard console, character by character,
    /// into a pinned <see cref="PinnedPoolArray{T}"/> of <see cref="char"/>. No <see cref="string"/>
    /// or other unpinned heap container is created at any point.
    /// </summary>
    /// <param name="maxLength">
    /// The maximum number of characters to accept. Must be greater than zero. The returned
    /// buffer's <see cref="PinnedPoolArray{T}.Capacity"/> is <paramref name="maxLength"/>;
    /// its <see cref="PinnedPoolArray{T}.Length"/> reflects the number of characters actually entered.
    /// </param>
    /// <param name="echoChar">
    /// Optional masking character to write to the console for each accepted keystroke. Pass
    /// <see langword="null"/> (default) to suppress all echo. A typical visible mask is <c>'*'</c>.
    /// </param>
    /// <returns>
    /// A <see cref="PinnedPoolArray{T}"/> with capacity <paramref name="maxLength"/> and
    /// <see cref="PinnedPoolArray{T}.Length"/> set to the number of characters entered before
    /// the user pressed <c>Enter</c>. The caller is responsible for disposing it.
    /// </returns>
    /// <remarks>
    /// Behaviour:
    /// <list type="bullet">
    /// <item><description>Pressing <c>Enter</c> ends the input and returns the buffer.</description></item>
    /// <item><description>Pressing <c>Backspace</c> deletes the most recently accepted character
    /// (and erases the echo on the console if <paramref name="echoChar"/> is set).</description></item>
    /// <item><description>Once <paramref name="maxLength"/> characters have been entered, additional
    /// printable keystrokes are silently ignored until the user presses <c>Enter</c> or
    /// <c>Backspace</c>.</description></item>
    /// <item><description>Non-printable control keys other than <c>Enter</c> and <c>Backspace</c> are ignored.</description></item>
    /// <item><description>Ctrl+C is not intercepted — the default console behaviour applies (process termination).</description></item>
    /// </list>
    /// <para>
    /// On termination, no <see cref="string"/> is ever materialised: the entered characters
    /// exist only in the returned pinned buffer, which is securely cleared on dispose.
    /// </para>
    /// </remarks>
    /// <exception cref="ArgumentOutOfRangeException">
    /// Thrown when <paramref name="maxLength"/> is less than or equal to zero.
    /// </exception>
    /// <exception cref="InvalidOperationException">
    /// Thrown when standard input is redirected (i.e. <see cref="Console.IsInputRedirected"/>
    /// is <see langword="true"/>); interactive key-by-key reading is not available in that case.
    /// </exception>
    public static PinnedPoolArray<char> ReadPassword(int maxLength, char? echoChar = null)
    {
        if (maxLength <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(maxLength), maxLength, ErrorMessages.MaxLengthMustBePositive);
        }

        if (Console.IsInputRedirected)
        {
            throw new InvalidOperationException(ErrorMessages.ConsoleInputRedirected);
        }

        return ReadPasswordLoop(
            () => Console.ReadKey(intercept: true),
            maxLength,
            echoChar,
            Console.Write);
    }

    /// <summary>
    /// Loop body for <see cref="ReadPassword"/>, decoupled from the static
    /// <see cref="Console"/> API for unit-testing. Reads keys via <paramref name="readKey"/>
    /// and forwards echo output to <paramref name="echoSink"/>.
    /// </summary>
    /// <param name="readKey">Source of keystrokes. Invoked once per loop iteration.</param>
    /// <param name="maxLength">Maximum number of characters to accept.</param>
    /// <param name="echoChar">Mask character to emit, or <see langword="null"/> for silent input.</param>
    /// <param name="echoSink">
    /// Sink for echo output. Receives a single mask character per accepted keystroke and
    /// the literal string <c>"\b \b"</c> per accepted backspace. Only invoked when
    /// <paramref name="echoChar"/> has a value.
    /// </param>
    /// <returns>
    /// A pinned buffer with capacity <paramref name="maxLength"/> and length set to the
    /// number of characters accepted before <c>Enter</c> was pressed.
    /// </returns>
    internal static PinnedPoolArray<char> ReadPasswordLoop(
        Func<ConsoleKeyInfo> readKey,
        int maxLength,
        char? echoChar,
        Action<string> echoSink)
    {
        return ReadPasswordLoop(readKey, maxLength, echoChar, echoSink, CreatePinnedBuffer);
    }

    /// <summary>
    /// Buffer-factory-injected overload of
    /// <see cref="ReadPasswordLoop(Func{ConsoleKeyInfo},int,char?,Action{string})"/>.
    /// Exists so unit tests can capture the <see cref="PinnedPoolArray{T}"/> instance the
    /// loop allocates and assert that it is disposed on the failure path — when
    /// <paramref name="readKey"/> or <paramref name="echoSink"/> throws while
    /// partially-typed secret material is already resident in the buffer.
    /// </summary>
    /// <param name="readKey">Source of keystrokes. Invoked once per loop iteration.</param>
    /// <param name="maxLength">Maximum number of characters to accept.</param>
    /// <param name="echoChar">Mask character to emit, or <see langword="null"/> for silent input.</param>
    /// <param name="echoSink">
    /// Sink for echo output. Receives a single mask character per accepted keystroke and
    /// the literal string <c>"\b \b"</c> per accepted backspace. Only invoked when
    /// <paramref name="echoChar"/> has a value.
    /// </param>
    /// <param name="bufferFactory">
    /// Allocates the pinned receive-buffer of the requested capacity. The production path
    /// passes <see cref="CreatePinnedBuffer"/>; tests pass a capturing lambda so they can
    /// inspect the buffer's disposed state after the loop returns or throws.
    /// </param>
    /// <returns>
    /// The pinned buffer with <see cref="PinnedPoolArray{T}.Length"/> set to the number of
    /// characters accepted before <c>Enter</c> was pressed. If <paramref name="readKey"/>
    /// or <paramref name="echoSink"/> throws, the buffer is disposed and the exception is
    /// rethrown — no reference to it escapes.
    /// </returns>
    internal static PinnedPoolArray<char> ReadPasswordLoop(
        Func<ConsoleKeyInfo> readKey,
        int maxLength,
        char? echoChar,
        Action<string> echoSink,
        Func<int, PinnedPoolArray<char>> bufferFactory)
    {
        var pinned = bufferFactory(maxLength);
        try
        {
            int count = 0;

            while (true)
            {
                var key = readKey();

                if (key.Key == ConsoleKey.Enter)
                {
                    break;
                }

                if (key.Key == ConsoleKey.Backspace)
                {
                    count = HandleBackspace(pinned, count, echoChar, echoSink);
                    continue;
                }

                if (char.IsControl(key.KeyChar))
                {
                    continue;
                }

                count = HandlePrintable(pinned, count, key.KeyChar, maxLength, echoChar, echoSink);
            }

            pinned.Length = count;
            return pinned;
        }
        catch
        {
            pinned.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Default factory used by the four-parameter
    /// <see cref="ReadPasswordLoop(Func{ConsoleKeyInfo},int,char?,Action{string})"/> wrapper
    /// to allocate the pinned receive-buffer in production. Wrapped as a named method so the
    /// wrapper can pass it as a method-group reference without a per-call closure
    /// allocation.
    /// </summary>
    /// <param name="capacity">Capacity in characters of the buffer to allocate.</param>
    /// <returns>
    /// A new <see cref="PinnedPoolArray{T}"/> of <see cref="char"/> with the requested
    /// capacity and zero logical length.
    /// </returns>
    private static PinnedPoolArray<char> CreatePinnedBuffer(int capacity)
    {
        return new PinnedPoolArray<char>(capacity);
    }

    /// <summary>
    /// Handles a <c>Backspace</c> keystroke inside
    /// <see cref="ReadPasswordLoop(Func{ConsoleKeyInfo},int,char?,Action{string})"/>: removes
    /// the most recently entered character (if any), wipes the freed slot to <c>'\0'</c>
    /// so no stale character survives in pinned memory beyond the logical length, and
    /// emits the canonical <c>"\b \b"</c> erase sequence to <paramref name="echoSink"/>
    /// when echo is enabled.
    /// </summary>
    /// <param name="pinned">The pinned receive-buffer being filled.</param>
    /// <param name="count">Current logical length of <paramref name="pinned"/>.</param>
    /// <param name="echoChar">Mask character configured for echo, or <see langword="null"/> for silent input.</param>
    /// <param name="echoSink">Sink that receives the erase sequence when echo is enabled.</param>
    /// <returns>The new logical length after the backspace has been applied.</returns>
    private static int HandleBackspace(
        PinnedPoolArray<char> pinned,
        int count,
        char? echoChar,
        Action<string> echoSink)
    {
        if (count <= 0)
        {
            return count;
        }

        count--;
        pinned.PoolArray[count] = '\0';
        if (echoChar.HasValue)
        {
            echoSink("\b \b");
        }

        return count;
    }

    /// <summary>
    /// Handles a printable-character keystroke inside
    /// <see cref="ReadPasswordLoop(Func{ConsoleKeyInfo},int,char?,Action{string})"/>:
    /// appends the character to the pinned buffer if capacity remains and emits the
    /// configured mask character to <paramref name="echoSink"/> when echo is enabled.
    /// Once the buffer has reached <paramref name="maxLength"/>, additional printable
    /// keystrokes are silently dropped.
    /// </summary>
    /// <param name="pinned">The pinned receive-buffer being filled.</param>
    /// <param name="count">Current logical length of <paramref name="pinned"/>.</param>
    /// <param name="ch">The printable character to append.</param>
    /// <param name="maxLength">Maximum allowed logical length for <paramref name="pinned"/>.</param>
    /// <param name="echoChar">Mask character configured for echo, or <see langword="null"/> for silent input.</param>
    /// <param name="echoSink">Sink that receives the mask character when echo is enabled.</param>
    /// <returns>The new logical length after the character has been appended (or dropped).</returns>
    private static int HandlePrintable(
        PinnedPoolArray<char> pinned,
        int count,
        char ch,
        int maxLength,
        char? echoChar,
        Action<string> echoSink)
    {
        if (count >= maxLength)
        {
            return count;
        }

        pinned.PoolArray[count++] = ch;
        if (echoChar.HasValue)
        {
            echoSink(echoChar.Value.ToString());
        }

        return count;
    }
}