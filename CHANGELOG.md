# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.12.0] - 2024-11-17
### Added
- Added .NET 9.0 support
- Added use-case interfaces `IMakeSharesUseCase` and `IReconstructUseCase` to the `SecretSharingDotNet` project.
- Added a guide to the `README.md` file on how to use the use-case interfaces with dependency injection.

### Changed
- Changed the `Sqrt` signature in the `BigIntCalculator` class from property to method.
- Changed method visibility from `public` to `protected` in the `BigIntCalculator`and `Calculator` classes to restrict access.

### Removed
- Removed .NET 7 support, because it retires on May 14, 2024. See [.NET and .NET Core Support Policy](https://dotnet.microsoft.com/en-us/platform/support/policy/dotnet-core).
- Removed .NET 6 support, because it retires on November 12, 2024. See [.NET and .NET Core Support Policy](https://dotnet.microsoft.com/en-us/platform/support/policy/dotnet-core).

## [0.11.0] - 2023-12-30
### Added
- Added support for .NET FX v4.8.1
- Added support for .NET 8.0
- Added support for SourceLink (GitHub)
- Enable deterministic builds

### Changed
- Moved `SecurityLevels` from `ShamirsSecretSharing<TNumber, TExtendedGcdAlgorithm, TExtendedGcdResult>` to `ShamirsSecretSharing` class.
- Introduced `ReadOnlySpan<char>` for `string` parameters in `Secret<TNumber>` class.

### Removed
- Removed Legacy Mode from `Secret.cs` class.

## [0.10.2] - 2023-09-16
### Changed
- FinitePoint: Use `ReadOnlySpan<char>` for `string` parameters in ctor and methods.

### Deprecated
- The Secret Legacy Mode is marked as deprecated and will be removed in one of the next releases.

### Fixed
- Fixed NETSDK1187 warning (see #151).  Locale 'de-de' is normalized to the standard locale 'de-DE'.

## [0.10.1] - 2023-05-08
### Fixed
- Fixed BigIntCalculator's Equals method to avoid timing attacks. The slow equal implementation is used now.

## [0.10.0] - 2022-12-24
### Added
- Added .NET 7 support

### Changed
- Update `Microsoft.NETFramework.ReferenceAssemblies` to v1.0.3

### Removed
- Removed .NET Core 3.1 (LTS) support
- Removed ctor `ShamirsSecretSharing(IExtendedGcdAlgorithm<TNumber> extendedGcd, int securityLevel)`.
- Removed method `MakeShares(TNumber numberOfMinimumShares, TNumber numberOfShares)`.

## [0.9.0] - 2022-10-09
### Added
- Add `ToInt32()` method to `BigIntCalculator` and `Calculator` class.
- Introduce the `IExtendedGcdResult` interface to decouple GCD result implementations.

### Changed
- Moved generic version of the `Calculator` class from the `Calculator.cs` file to the ``Calculator`1.cs`` file.
- Updated `Microsoft.NET.Test.Sdk` Nuget package version to 17.2.0.
- Updated `xunit.runner.visualstudio` Nuget package version to 2.4.5.
- Set `Calculator` fields `ChildTypes` and `ChildBaseCtors` from protected to private.
- Performance improvements for `ShamirsSecretSharing` classes.
- Performance improvements for `FinitePoint` class.
- Performance improvements for generic `Calculator` class.

### Deprecated
- Ctor `ShamirsSecretSharing(IExtendedGcdAlgorithm<TNumber> extendedGcd, int securityLevel)` is deprecated.
- Method `MakeShares(TNumber numberOfMinimumShares, TNumber numberOfShares)` is deprecated.

### Fixed
- Fixed style guide violations in `CHANGELOG.md`.
- Fixed style guide violations in `FinitePoint.cs`.
- Fixed style guide violations in `Shares.cs`.
- Fixed style guide violations in `SharesEnumerator.cs`.
- Fixed style guide violations in ``IExtendedGcdAlgorithm`2.cs``.
- Fixed style guide violations in `ExtendedEuclideanAlgorithm.cs`.
- Fixed style guide violations in `Calculator.cs`.
- Fixed style guide violations in ``Calculator`1.cs``.
- Fixed style guide violations in `BigIntCalculator.cs`.
- Fixed style guide violations in `Secret.cs`. Split file into `Secret.cs` and ``Secret`1.cs``.
- Fixed possible null reference exception in `Calculator` class.
- Fixed possible null reference exception in `Shares` class.
- Fixed possible null reference exception in `ShamirsSecretSharing` class.
- Fixed unnecessary boxing/unboxing in the `ToString()` methods in `Calculator` classes.

### Removed
- Removed constructor w/ `ReadOnlyCollection` parameter from the `SharesEnumerator{TNumber}` class.
- Removed tuple type casting from the `Shares` class.
- Removed `Shares.Item1` property.
- Removed `Shares.Item2` property.

## [0.8.0] - 2022-07-05
### Added
- Added more examples in the section *Usage* of the `README.md` file to explain the use of shares and the use of the new type casting from byte array to secret and vice versa.
- Added method `MakeShares(TNumber numberOfMinimumShares, TNumber numberOfShares, int securityLevel)`
- Added method `MakeShares(TNumber numberOfMinimumShares, TNumber numberOfShares, Secret<TNumber> secret, int securityLevel)`
- Added localization for exception messages in English and German languages

### Changed
- Changed existing examples in the section *Usage* of the `README.md` file to explain the use and the type casting of recovered secrets.
- Minify NuGet package `README.md`
- Changed ctor `ShamirsSecretSharing(IExtendedGcdAlgorithm<TNumber> extendedGcd)`. This ctor sets the SecurityLevel to 13.

### Deprecated
- Ctor `ShamirsSecretSharing(IExtendedGcdAlgorithm<TNumber> extendedGcd, int securityLevel)` is deprecated.
- Method `MakeShares(TNumber numberOfMinimumShares, TNumber numberOfShares)` is deprecated.
- Shares to tuple type casting is obsolete and will be remove in the next release.
- `Shares.Item1` property is obsolete and will be remove in the next release.
- `Shares.Item2` property is obsolete and will be remove in the next release.

### Removed
- Removed .NET 5 support, because it retires on May 10, 2022. See [Microsoft .NET and .NET Core - Support Dates](https://docs.microsoft.com/en-us/lifecycle/products/microsoft-net-and-net-core).

## [0.7.0] - 2022-02-09
### Added
- Added implicit casts for byte arrays in *Secret* class.
- Added legacy mode. See `README.md`, section "Usage" for more details.

### Changed
- Changed behavior of *Secret* class for negative secret values. See `README.md`, section "Usage" and bug report [#60](https://github.com/shinji-san/SecretSharingDotNet/issues/60) for more details.
- Changed calculation of maximum security level in Reconstruction method.

### Fixed
- Fixed reopened bug [#60](https://github.com/shinji-san/SecretSharingDotNet/issues/60) "Reconstruction fails at random".
- Fixed assembly output path in `SecretSharingDotNetFx4.6.2.csproj`

### Removed
- Removed .NET FX 4.5.2 support, because it retires on April 26, 2022. See [.NET FX Lifecycle Policy](https://docs.microsoft.com/en-us/lifecycle/products/microsoft-net-framework).
- Removed .NET FX 4.6 support, because it retires on April 26, 2022. See [.NET FX Lifecycle Policy](https://docs.microsoft.com/en-us/lifecycle/products/microsoft-net-framework).
- Removed .NET FX 4.6.1 support, because it retires on April 26, 2022. See [.NET FX Lifecycle Policy](https://docs.microsoft.com/en-us/lifecycle/products/microsoft-net-framework).

## [0.6.0] - 2021-11-25
### Added
- Add .NET 6 support

### Changed
- Use `RandomNumberGenerator` class instead `RNGCryptoServiceProvider` class to create the polynomial. For details see dotnet runtime issue [40169](https://github.com/dotnet/runtime/issues/40169)

### Fixed
- Fixed bug [#60](https://github.com/shinji-san/SecretSharingDotNet/issues/60) "Reconstruction fails at random" which occurs when the secret is created from a base64 string

### Removed
- Removed .NET Core 2.1 (LTS) support

## [0.5.0] - 2021-10-07
### Added
- Introduced a new return type for the split method 'MakeShares'
- Added CLI building instructions in `README.md`

### Changed
- Updated examples in `README.md` based on the new return type for the split method
- Updated xUnit package references in CSharp projects 
- Updated Microsoft Test SDK package references in CSharp projects
- Updated Microsoft .NET FX reference assemblies package references in CSharp projects

### Deprecated
- The tuple return type for the split method 'MakeShares' is obsolete

### Fixed
- Fixed CI version dependency
- Fixed code quality issues in CSharp code
- Fixed spelling mistakes in `README.md`
- Fixed .NET 5 solution filename in `README.md`
- Added missing target framework .NET 5 to `SecretSharingDotNetTest.csproj` 

## [0.4.2] - 2020-12-18
### Fixed
- Fixed wrong NuGet package version

## [0.4.1] - 2020-12-18
### Fixed
- NuGet build environment modified to build for .NET 5.0

## [0.4.0] - 2020-12-18
### Added
- Added .NET 5.0 support

### Fixed
- Fixed bug 40 (_Maximum exceeded!_) reported [@varshadqz](https://github.com/shinji-san/SecretSharingDotNet/issues/40)

## [0.3.0] - 2020-04-19
### Added
- Added .NET FX 4.6 support
- Added .NET FX 4.6.1 support
- Added .NET FX 4.6.2 support
- Added .NET FX 4.7 support
- Added .NET FX 4.7.1 support
- Added .NET FX 4.7.2 support
- Added .NET FX 4.8 support
- Added .NET Standard 2.1 support

### Changed
- `README.md`: Extend build & test status corresponding to the .NET versions

## [0.2.0] - 2020-04-12
### Added
- Added full .NET Core 3.1 support

## [0.1.1] - 2020-04-11
### Fixed
- Fixed wrong NuGet package version

## [0.1.0] - 2020-04-11
### Added
- Added initial version of SecretSharingDotNet
- Added .NET FX 4.5.2 support
- Added .NET Core 2.1 support
- Added limited .NET Core 3.1 support
- Added GitHub issue template
- Added `CODE_OF_CONDUCT.md`
- Added `LICENSE.md`
- Added `README.md`

[Unreleased]: https://github.com/shinji-san/SecretSharingDotNet/compare/v0.12.0...develop
[0.12.0]: https://github.com/shinji-san/SecretSharingDotNet/compare/v0.11.0...v0.12.0
[0.11.0]: https://github.com/shinji-san/SecretSharingDotNet/compare/v0.10.2...v0.11.0
[0.10.2]: https://github.com/shinji-san/SecretSharingDotNet/compare/v0.10.1...v0.10.2
[0.10.1]: https://github.com/shinji-san/SecretSharingDotNet/compare/v0.10.0...v0.10.1
[0.10.0]: https://github.com/shinji-san/SecretSharingDotNet/compare/v0.9.0...v0.10.0
[0.9.0]: https://github.com/shinji-san/SecretSharingDotNet/compare/v0.8.0...v0.9.0
[0.8.0]: https://github.com/shinji-san/SecretSharingDotNet/compare/v0.7.0...v0.8.0
[0.7.0]: https://github.com/shinji-san/SecretSharingDotNet/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/shinji-san/SecretSharingDotNet/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/shinji-san/SecretSharingDotNet/compare/v0.4.2...v0.5.0
[0.4.2]: https://github.com/shinji-san/SecretSharingDotNet/compare/v0.4.1...v0.4.2
[0.4.1]: https://github.com/shinji-san/SecretSharingDotNet/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/shinji-san/SecretSharingDotNet/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/shinji-san/SecretSharingDotNet/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/shinji-san/SecretSharingDotNet/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/shinji-san/SecretSharingDotNet/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/shinji-san/SecretSharingDotNet/releases/tag/v0.1.0
