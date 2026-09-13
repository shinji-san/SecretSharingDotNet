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
// title, company, copyright, product, versions, neutral language - is configured in
// SecretSharingDotNetTest.csproj and Directory.Build.props instead.

// The test assembly deliberately opts out of CLS compliance checking: test signatures
// use types the Common Language Specification does not cover, and flagging those would
// be noise. The library it exercises opts in.
[assembly: CLSCompliant(false)]

// Keeps the assembly invisible to COM. This is also the default; it is spelled out
// because the type library id below is only meaningful next to an explicit decision.
[assembly: ComVisible(false)]

// Type library id used should the assembly ever be registered for COM. Carried over
// verbatim from the former AssemblyInfo.cs.
[assembly: Guid("70290cc4-75a1-4609-afca-f1343d889a0e")]
