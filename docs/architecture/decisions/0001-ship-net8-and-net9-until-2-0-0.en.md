# 0001. Ship net8.0 and net9.0 until 2.0.0

- Status: accepted
- Date: 2026-11-19
- Deciders: Maintainer

## Context and Problem Statement

.NET 8 and .NET 9 reached end of support on 2026-11-10, the day .NET 11 shipped. The package
ships `net8.0` and `net9.0` assets, and the next release, 1.2.0, adds `net11.0`. The open
question is when the two unsupported assets leave the package. Once they do, an application on
.NET 8 or .NET 9 resolves the `netstandard2.1` asset instead. That asset lacks five public
members of `Secret<TNumber>`: the two constructors that take a `ReadOnlySpan<byte>`, the implicit
conversions to and from `ReadOnlySpan<byte>`, and `AsReadOnlySpan()`.

## Decision Drivers

- **Semantic Versioning.** `CHANGELOG.md` commits to SemVer. Code that uses any of the five
  members no longer compiles against the `netstandard2.1` asset.
- **Lead time for consumers.** Anyone still on .NET 8 or .NET 9 should learn about the removal
  one release ahead, not when they update.
- **Cost per target framework.** Each of the two takes an SDK pin in seven `setup-dotnet` blocks
  (five workflows) and one of the seven test steps of every `dotnetall.yml` run. Together they
  cause twelve warnings there from System.IO.Hashing 11.0.0, which `Microsoft.SourceLink.GitHub`
  brings into the build only, not into the package, and which does not support
  `net8.0`/`net9.0`.
- **Breaking changes already queued.** 2.0.0 already carries breaking changes: removing the
  `SecretReconstructor` finalizer (announced as *Deprecated* in 1.1.0) and making
  `ShareFormat.Extended` the serialization default (issue #403).

## Considered Options

- Remove both in 1.2.0
- Remove `net9.0` in 1.2.0, `net8.0` in 2.0.0
- Keep both in 1.2.0, remove them in 1.3.0
- Keep both in 1.2.0, remove them in 2.0.0

## Decision

Chosen option: "Keep both in 1.2.0, remove them in 2.0.0", because removing `net8.0` is a
breaking change for consumers that SemVer allows only in a major release, and because 1.2.0 can
then announce the removal one release ahead. `net9.0` goes in the same step: no code is tied to
`NET9_0`, its asset is the `net8.0` asset in substance, and removing it alone earlier would split
one platform change across two releases.

### Consequences

- Good: Consumers on .NET 8 and .NET 9 still get all of 1.2.0 and read in its release notes that
  2.0.0 removes their assets.
- Good: The removal lands in the same major release as the other breaking changes, so consumers
  migrate once.
- Bad: Until 2.0.0 the package ships two assets for runtimes without security updates, and CI
  keeps building and testing them. When 2.0.0 ships is open.
- Bad: The twelve System.IO.Hashing warnings stay until then, deliberately.
  `SuppressTfmSupportBuildWarnings` would hide them, and with them the reminder of the end of
  support.
- Bad: Once an SDK adds `8.0` and `9.0` to its list of unsupported frameworks, NETSDK1138
  warnings join them. SDK 11.0.100 does not list them yet.

## Pros and Cons of the Options

### Remove both in 1.2.0

- Good: No asset for an unsupported runtime; CI and the build shrink at once, and the warnings
  disappear.
- Bad: A breaking change in a minor release, against the SemVer commitment.
- Bad: No advance notice; consumers on .NET 8 find out when they update.

### Remove `net9.0` in 1.2.0, `net8.0` in 2.0.0

- Good: Neutral for consumers, because .NET 9 falls back to the equivalent `net8.0` asset; one
  test step and six warnings go earlier.
- Bad: Splits one platform change across two releases; the breaking change for `net8.0` remains
  either way.

### Keep both in 1.2.0, remove them in 1.3.0

- Good: A shorter period with unsupported assets. There is a precedent: PR #416 shipped a narrow
  breaking change in a minor release.
- Bad: Breaks SemVer for consumers on .NET 8 although 2.0.0 collects breaking changes anyway.

### Keep both in 1.2.0, remove them in 2.0.0

- Good: SemVer-compliant, one release of lead time, one migration together with the other
  breaking changes.
- Bad: Unsupported assets stay in the package until a release that has no date yet, with their
  CI cost and warnings.

## More Information

- `CHANGELOG.md`, `[Unreleased]` → *Deprecated*: the announcement in 1.2.0.
- arc42, chapter 9 (links this ADR) and risk R1 (nine-TFM sprawl):
  [`docs/architecture/arc42.en.md`](../arc42.en.md).
- .NET support periods: <https://dotnet.microsoft.com/platform/support/policy/dotnet-core>.
- German version:
  [0001-net8-und-net9-bis-2-0-0-ausliefern.de.md](0001-net8-und-net9-bis-2-0-0-ausliefern.de.md).
