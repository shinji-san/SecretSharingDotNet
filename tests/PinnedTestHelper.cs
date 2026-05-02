// ----------------------------------------------------------------------------
// <copyright file="PinnedTestHelper.cs" company="Private">
// Copyright (c) 2026 All Rights Reserved
// </copyright>
// <author>Sebastian Walther</author>
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

namespace SecretSharingDotNetTest;

using SecretSharingDotNet.Cryptography.SecureArray;
using System;

internal static class PinnedTestHelper
{
    public static PinnedPoolArray<char> ToPinnedLines(string[] lines, string separator = "\n")
    {
        if (lines is null)
        {
            throw new ArgumentNullException(nameof(lines));
        }

        if (separator is null)
        {
            throw new ArgumentNullException(nameof(separator));
        }

        var total = 0;
        for (var i = 0; i < lines.Length; i++)
        {
            total += lines[i]?.Length ?? 0;
            if (i < lines.Length - 1)
            {
                total += separator.Length;
            }
        }

        var result = new PinnedPoolArray<char>(total);
        var pos = 0;
        for (var i = 0; i < lines.Length; i++)
        {
            if (i > 0 && separator.Length > 0)
            {
                separator.CopyTo(0, result.PoolArray, pos, separator.Length);
                pos += separator.Length;
            }

            var line = lines[i];
            if (!string.IsNullOrEmpty(line))
            {
                line.CopyTo(0, result.PoolArray, pos, line.Length);
                pos += line.Length;
            }
        }

        return result;
    }
}