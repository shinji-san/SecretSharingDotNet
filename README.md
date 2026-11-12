# SecretSharingDotNet

[![Build and test](https://github.com/shinji-san/SecretSharingDotNet/actions/workflows/dotnetall.yml/badge.svg?branch=main)](https://github.com/shinji-san/SecretSharingDotNet/actions/workflows/dotnetall.yml)
[![NuGet publishing](https://github.com/shinji-san/SecretSharingDotNet/actions/workflows/publishing.yml/badge.svg)](https://github.com/shinji-san/SecretSharingDotNet/actions/workflows/publishing.yml)
[![NuGet version](https://img.shields.io/nuget/v/SecretSharingDotNet)](https://www.nuget.org/packages/SecretSharingDotNet)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue)](https://github.com/shinji-san/SecretSharingDotNet/blob/main/LICENSE.md)

Shamir's Secret Sharing for .NET: split a secret into n shares, reconstruct it from any k of them.

## 🌟 Highlights

- Two numeric backends: `BigInteger` and `SecureBigInteger`, which keeps its limbs in pinned memory and wipes them on dispose.
- Text input and output use pinned `PinnedPoolArray<char>` buffers instead of `string`, including a console password reader.
- Best-effort timing hardening: fixed-time secret equality and a fixed-iteration modular inverse.
- Shares can record their security level (`ShareFormat.Extended`), so reconstruction does not have to derive the field.
- `ToString()` returns `*** Secured Value ***` in Release builds, so secrets do not leak into logs.

## ℹ️ Overview

The library splits a secret into n shares; any k of them reconstruct it, and fewer than k do not.
Splitting evaluates a random polynomial over a Mersenne prime field; reconstruction uses Lagrange interpolation.
The secret can be text, a byte array, a number, or a random value that the library generates.

`SecureBigInteger` reduces timing side channels on a best-effort basis; it is not audited against active co-located attackers.
Plain Shamir carries no integrity check, so a tampered share yields a wrong secret without an error.
The [threat model](https://github.com/shinji-san/SecretSharingDotNet/blob/main/docs/threat-model.md) lists what is protected and what is not.

## ⬇️ Installation

The package targets .NET Standard 2.0 and 2.1, .NET Framework 4.7.2, 4.8, and 4.8.1, and .NET 8, 9, and 10.

Install SecretSharingDotNet with:

```shell
dotnet add package SecretSharingDotNet
```

Upgrading from an earlier version? The [upgrade notes](https://github.com/shinji-san/SecretSharingDotNet/blob/main/docs/usage.md#upgrading-to-1x) summarize the breaking changes, and the [changelog](https://github.com/shinji-san/SecretSharingDotNet/blob/main/CHANGELOG.md) lists all of them.

## 🚀 Usage

The following example splits and reconstructs a text secret in a .NET 8+ console app (`dotnet new console`):

```csharp
using SecretSharingDotNet.Cryptography;
using SecretSharingDotNet.Cryptography.SecureInput;
using SecretSharingDotNet.Cryptography.ShamirsSecretSharing;
using SecretSharingDotNet.Math.Numerics;

// Split into 5 shares at security level 127; any 3 of them reconstruct it.
using var text = "Hello World!".ToPinnedSecure();
using var secret = Secret<SecureBigInteger>.FromText(text);
using var splitter = new SecretSplitter<SecureBigInteger>();
using var shares = splitter.MakeShares(3, 5, secret, 127);
// Reconstruct the secret and print it without creating a string.
using var reconstructor = new FixedIterationSecretReconstructor<SecureBigInteger>();
using var recovered = reconstructor.Reconstruction(shares);
using var chars = recovered.ToCharArray();
Console.WriteLine(chars.PoolArray, 0, chars.Length);
```

Output:

```text
Hello World!
```

To store shares, write them with `ShareFormat.Extended`.
The default format omits the security level, so shares read back from storage can silently reconstruct a different secret.
For the `BigInteger` backend, pass an `ExtendedEuclideanAlgorithm<BigInteger>` to `SecretReconstructor<BigInteger>`.
The [usage guide](https://github.com/shinji-san/SecretSharingDotNet/blob/main/docs/usage.md) covers both backends, dependency injection, [storing shares](https://github.com/shinji-san/SecretSharingDotNet/blob/main/docs/usage.md#storing-shares), and console input.
[`samples/SecretSharingDotNet.Demo.Console`](https://github.com/shinji-san/SecretSharingDotNet/tree/main/samples/SecretSharingDotNet.Demo.Console) is a runnable demo.

## 📖 Documentation

- [Usage guide](https://github.com/shinji-san/SecretSharingDotNet/blob/main/docs/usage.md): backends, dependency injection, secrets, shares, storage, console input, upgrade notes.
- [Threat model](https://github.com/shinji-san/SecretSharingDotNet/blob/main/docs/threat-model.md): what `SecureBigInteger` and reconstruction protect against, and what they do not.
- [Architecture documentation (arc42)](https://github.com/shinji-san/SecretSharingDotNet/blob/main/docs/architecture/arc42.en.md), also in [German](https://github.com/shinji-san/SecretSharingDotNet/blob/main/docs/architecture/arc42.de.md).
- [Changelog](https://github.com/shinji-san/SecretSharingDotNet/blob/main/CHANGELOG.md): all changes per release.

## 🛠️ Development

Requires the [.NET 8, 9, and 10 SDKs](https://dotnet.microsoft.com/download/dotnet).
The .NET Framework test targets need Windows or Mono; CI runs them on Windows, and Mono can behave differently.
Build and test the solution with:

```shell
dotnet restore SecretSharingDotNet.slnx
dotnet build --configuration Release --no-restore SecretSharingDotNet.slnx
dotnet test --configuration Release --no-restore --no-build SecretSharingDotNet.slnx
```

The tests run single-threaded, configured in `tests/xunit.runner.json`; add `--max-parallel-test-modules 1` to run the target frameworks one after another.
Mono may leave `mono_crash.*.json` files in `tests/` after a passing run; Git ignores them.

## 💭 Feedback & Contributing

Report bugs and request features through the [issue forms](https://github.com/shinji-san/SecretSharingDotNet/issues/new/choose).
Ask questions and discuss ideas in [GitHub Discussions](https://github.com/shinji-san/SecretSharingDotNet/discussions).
Report security vulnerabilities privately through a [security advisory](https://github.com/shinji-san/SecretSharingDotNet/security/advisories/new), not in a public issue.
This project follows a [code of conduct](https://github.com/shinji-san/SecretSharingDotNet/blob/main/CODE_OF_CONDUCT.md).

## 📜 License

Licensed under the MIT License — see [LICENSE.md](https://github.com/shinji-san/SecretSharingDotNet/blob/main/LICENSE.md).
