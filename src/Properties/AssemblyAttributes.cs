// ----------------------------------------------------------------------------
// <copyright file="AssemblyAttributes.cs" company="Private">
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

using System;
using System.Runtime.InteropServices;

// The assembly-level attributes below have no MSBuild property counterpart, so the SDK
// cannot generate them and they stay in source. Everything the SDK does generate -
// title, company, copyright, product, versions, neutral language, InternalsVisibleTo -
// is configured in SecretSharingDotNet.csproj and Directory.Build.props instead.

// Turns on CLS compliance checking for the public API: the compiler reports CS3001 and
// its siblings when a publicly visible signature uses a type outside the Common Language
// Specification. A verification switch - it does not change what is emitted.
[assembly: CLSCompliant(true)]

// Keeps the assembly invisible to COM. This is also the default; it is spelled out
// because the type library id below is only meaningful next to an explicit decision.
[assembly: ComVisible(false)]

// Type library id used should the assembly ever be registered for COM. Carried over
// verbatim from the former AssemblyInfo.cs - generating a fresh one would change an
// identity that is already out in the wild.
[assembly: Guid("1c21b99c-2de4-4ca5-b4ce-bc95cf89369e")]
