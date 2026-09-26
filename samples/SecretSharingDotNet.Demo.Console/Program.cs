// ----------------------------------------------------------------------------
// <copyright file="Program.cs" company="Private">
// Copyright (c) 2026 All Rights Reserved
// </copyright>
// <author>Sebastian Walther</author>
// <date>05/17/2026</date>
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

namespace SecretSharingDotNet.Demo.Console;

using Cryptography;
using Cryptography.ShamirsSecretSharing;
using Math.Numerics;
using Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Composition root and entry point of the SecretSharingDotNet demo. Builds the
/// <see cref="ServiceProvider"/>, opens a single scope, resolves <see cref="DemoApp"/>,
/// and forwards its exit code to the operating system.
/// </summary>
internal static class Program
{
    /// <summary>
    /// Process entry point. Constructs the DI container, runs the demo once, and returns
    /// the exit code produced by <see cref="DemoApp.Run"/>.
    /// </summary>
    /// <returns>
    /// The exit code reported by <see cref="DemoApp.Run"/>. See that method for the
    /// concrete codes.
    /// </returns>
    private static int Main()
    {
        using var serviceProvider = BuildServiceProvider();
        using var scope = serviceProvider.CreateScope();
        var demo = scope.ServiceProvider.GetRequiredService<DemoApp>();
        return demo.Run();
    }

    /// <summary>
    /// Configures and builds the DI container for the demo. Registers the two Shamir use
    /// cases as scoped (they own disposable state and are released on scope dispose) — the
    /// reconstructor is the <see cref="FixedIterationSecretReconstructor{TNumber}"/>
    /// — and <see cref="DemoApp"/> as scoped.
    /// <see cref="ServiceProviderOptions.ValidateOnBuild"/> and
    /// <see cref="ServiceProviderOptions.ValidateScopes"/> are enabled so that wiring
    /// mistakes fail fast at startup rather than mid-run.
    /// </summary>
    /// <returns>
    /// A fully configured <see cref="ServiceProvider"/>. The caller owns disposal.
    /// </returns>
    private static ServiceProvider BuildServiceProvider()
    {
        var services = new ServiceCollection();

        // SecretSplitter and FixedIterationSecretReconstructor own internal disposables
        // (SecurityLevelManager). Registered as scoped, so the DI scope tracks and disposes
        // them deterministically. FixedIterationSecretReconstructor supplies the fixed-iteration
        // MersenneSafeGcdAlgorithm inverse itself — the inverse path required for the
        // security-conscious SecureBigInteger backend — so no separate GCD registration is
        // needed; the base ExtendedEuclideanAlgorithm would be variable-time on operand values.
        services.AddScoped<IMakeSharesUseCase<SecureBigInteger>, SecretSplitter<SecureBigInteger>>();
        services.AddScoped<IReconstructionUseCase<SecureBigInteger>, FixedIterationSecretReconstructor<SecureBigInteger>>();

        services.AddScoped<DemoApp>();

        return services.BuildServiceProvider(new ServiceProviderOptions
        {
            ValidateOnBuild = true,
            ValidateScopes = true,
        });
    }
}
