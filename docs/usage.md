# Usage guide

Detailed examples for SecretSharingDotNet. The [README](../README.md) has the short version.

> [!TIP]
> A runnable end-to-end example lives in [`samples/SecretSharingDotNet.Demo.Console`](../samples/SecretSharingDotNet.Demo.Console). It wires the `SecureBigInteger` backend via `FixedIterationSecretReconstructor` (fixed-iteration `MersenneSafeGcdAlgorithm` inverse) through `Microsoft.Extensions.DependencyInjection`, reads the secret via `ConsolePasswordReader` (no `string` materialisation), splits it, and reconstructs it from a user-selected K-of-N subset of the generated shares.

## Upgrading to 1.x

The [changelog](../CHANGELOG.md) lists every change; the notes below summarize the breaking ones.

### Breaking changes in v1.1.0

- **`Shares<TNumber>` is no longer marked `[Serializable]`.** With a formatter's defaults the type could not be serialized before either, so the change is invisible to consumers who never registered a surrogate. It bites in one case: if you registered an `ISerializationSurrogate` for `Share<TNumber>`, a populated `Shares<TNumber>` used to round-trip through `BinaryFormatter` and the formatter now rejects the root type. Register a surrogate for `Shares<TNumber>` as well, or persist through `ToCharArray(bool, bool, ShareFormat)` — the format this library defines and validates on the way back in.

### Breaking changes in v1.0.1

v1.0.1 is a major version bump from v0.14.0. Highlights for migrating consumers — see [`CHANGELOG.md`](../CHANGELOG.md) for the full list.

- **Text I/O is pinned-buffer-only.** The `string`-based entry points are gone. Wrap a `string` in `.ToPinnedSecure()` and use the pinned factories: `Secret<TNumber>.FromText(PinnedPoolArray<char>)`, `new Share<TNumber>(PinnedPoolArray<char>)`, `Shares<TNumber>.FromText(...)`, `Shares<TNumber>.FromTextLines(...)`. Read back via the matching `ToCharArray()` methods on `Secret`, `Share`, and `Shares`.
- **`Reconstruction(string)` and `Reconstruction(string[])` removed.** Build a `Shares<TNumber>` through one of the pinned factories above and pass that.
- **`Secret<TNumber>.ToBase64()` → `ToBase64String()` (string, redaction-gated) and `ToBase64CharArray()` (pinned char buffer, not redacted).**
- **`Share<TNumber>.X` / `.Y` properties → `.Index` / `.Value`.**
- **`MakeShares` parameter types.** `numberOfMinimumShares` and `numberOfShares` are now `int` instead of `TNumber`.
- **`Calculator.ToInt32()` / `BigIntCalculator.ToInt32()` removed.**
- **`SecretReconstructor<TNumber>.SecurityLevel` is now read-only** — it is derived from the supplied shares on every `Reconstruction` call (see Basics).
- **`Calculator<TNumber>.Clone` is now `abstract`** — custom backends must override it.
- **`ExtendedEuclideanAlgorithm<TNumber>` is now `sealed`** — derive from `IExtendedGcdAlgorithm<TNumber>` or compose around it instead.
- **`SecretSplitter<TNumber>` is now `sealed`** — compose around `IMakeSharesUseCase<TNumber>` instead of deriving.
- **`SecureBigInteger.Pow(int)` throws `ArgumentOutOfRangeException`** (was `ArgumentException`) for negative exponents, consistent with the other length / exponent validations on the type. `ArgumentOutOfRangeException` derives from `ArgumentException`, so wide catches still work.
- **`Shares<TNumber>.OriginalSecret` and `Shares<TNumber>.OriginalSecretExists` removed** (deprecated since v0.14.0).
- **Platform support.** The minimum supported .NET Framework is now 4.7.2; net4.7 and net4.7.1 are removed.
- **`FinitePoint<TNumber>` removed** (replaced by an internal polynomial representation).

The text-secret encoding is UTF-8 (introduced in v0.14.0).

## Basics
Use the function `MakeShares` to generate the shares, based on a random or pre-defined secret.
Afterwards, use the function `Reconstruction` to reconstruct the original secret.

The library is generic in the numeric backend: `BigInteger` (used in the examples below) or `SecureBigInteger` (pinned-memory storage with partially constant-time arithmetic — see the [threat model](threat-model.md)). Both `IMakeSharesUseCase<TNumber>` and `IReconstructionUseCase<TNumber>` implement `IDisposable`; wrap them in `using` so pinned, security-sensitive buffers are released deterministically.

### Choosing a backend and reconstructor

| Backend | Reconstructor + GCD strategy | Pinned memory | Constant-time arithmetic † | Fixed-iteration inverse † | Choose when |
|---|---|:---:|:---:|:---:|---|
| `BigInteger` | `SecretReconstructor` + `ExtendedEuclideanAlgorithm` | no | no | no | performance matters and timing side channels are out of scope |
| `SecureBigInteger` | `FixedIterationSecretReconstructor` (wires `MersenneSafeGcdAlgorithm`) | yes | partial † | yes | secrets where passive timing analysis is in scope |

† Both constant-time properties are best-effort against passive timing analysis — managed .NET cannot guarantee constant time (see the [threat model](threat-model.md)). *Constant-time arithmetic* is **partial**: the per-limb work of the core primitives is fixed by the operand limb counts and branchless — by `max(l, r)` for subtraction, `max(l, r) + 1` for addition, `left × right` for multiplication and squaring, and `dividend × 64` outer iterations for division and remainder — but every result is normalised by a leading-zero trim whose iteration count depends on the result's magnitude, and that trimmed length then sizes the next operation — so the limb count of an intermediate value is itself secret-derived rather than public. It covers the core primitives (add / subtract / multiply / square / divide / remainder) on the public bit length; it does not cover `Pow` (variable-time on its exponent), ordering (`CompareTo`), or the hex / Base64 decoders. *Fixed-iteration inverse* means that at a fixed security level the GCD iteration count depends only on that (public) level, not on the secret operand values — removing the iteration-count side channel of a plain extended-Euclidean GCD. Reconstruction runs at the level the shares record or the caller names, and derives one from the shares' maximum value only for shares recording neither, so the iteration count still reflects that level — which is public either way, recorded in the share or revealed by its size; it is not per-operation constant-time (`MersenneSafeGcdAlgorithm`'s per-iteration timing is not uniform). Together these two properties **reduce but do not eliminate** reconstruction timing side channels — they do not make the whole reconstruction constant-time.

> [!WARNING]
> Do not pair `SecureBigInteger` with `ExtendedEuclideanAlgorithm`: you keep the pinned memory but reintroduce an operand-value-dependent iteration count — the side channel `FixedIterationSecretReconstructor` removes. `FixedIterationSecretReconstructor<SecureBigInteger>` accepts only fixed-iteration GCD strategies, so this mispairing is a compile-time error rather than a silent side channel. See the [threat model](threat-model.md) for the exact scope.

The length of the shares is based on the security level. On the splitter side, you can set it three ways: pass it as the `securityLevel` parameter of the `MakeShares` overload that takes one, assign the `SecretSplitter<TNumber>.SecurityLevel` property, or inject a pre-configured `ISecurityLevelManager<TNumber>` through the constructor. The configured level is overridden when the secret size exceeds the Mersenne prime derived from it — the library auto-adjusts upward. It is not necessary to define a security level for a reconstruction: `SecretReconstructor<TNumber>.SecurityLevel` is read-only and is derived from the supplied shares on every `Reconstruction` call.

The `ToString()` overrides on `Secret<TNumber>`, `Share<TNumber>`, and `Shares<TNumber>` are build-mode-sensitive: DEBUG builds return the actual content, while Release builds return the redaction sentinel `"*** Secured Value ***"` so secrets cannot accidentally leak through logs, exception messages, or other diagnostic output.

## Using the SecretSharingDotNet library with DI in a .NET project
This guide demonstrates two parallel DI wirings: the `BigInteger` backend with `ExtendedEuclideanAlgorithm` (BCL-native, variable-time arithmetic) and the `SecureBigInteger` backend via `FixedIterationSecretReconstructor`, which wires the fixed-iteration `MersenneSafeGcdAlgorithm` (pinned-memory storage, partially constant-time arithmetic — see the [threat model](threat-model.md) for the trade-offs). Both variants share the same import block:

```csharp
using Microsoft.Extensions.DependencyInjection;
using SecretSharingDotNet.Cryptography;
using SecretSharingDotNet.Cryptography.SecureInput;
using SecretSharingDotNet.Cryptography.ShamirsSecretSharing;
using SecretSharingDotNet.Math;
using SecretSharingDotNet.Math.Numerics;
using System;
using System.Linq;
using System.Numerics;
```

The output sites below use the pinned `ToCharArray()` accessors on `Shares<TNumber>` and `Secret<TNumber>` and write them directly via `Console.Out.Write(char[], int, int)`. These accessors are not redaction-gated — they return the actual content in both DEBUG and Release builds — and avoid materialising a managed `string` between the pinned buffer and the writer.

> [!WARNING]
> The Splitter and Reconstructor hold a mutable `ISecurityLevelManager` that each
> `MakeShares` / `Reconstruction` call reads-then-writes; concurrent invocations
> on the same instance race on the security-level field and may return wrong
> results. The registrations below therefore use `AddTransient` for the use-case
> interfaces (each call resolves its own instance) and `AddSingleton` only for
> the stateless GCD algorithm.

> [!NOTE]
> `Reconstruction(shares, securityLevel)` — the overload that names the finite field instead of
> taking it from the shares — lives on `IReconstructionWithSecurityLevelUseCase<TNumber>`, which
> inherits `IReconstructionUseCase<TNumber>`. **Interface inheritance does not create a second
> registration:** registering only `IReconstructionUseCase<TNumber>` leaves the derived interface
> unresolvable. Consumers who need to name the field register it as well, alongside the existing
> line and pointing at the same implementation:
>
> ```csharp
> serviceCollection.AddTransient<IReconstructionWithSecurityLevelUseCase<BigInteger>, SecretReconstructor<BigInteger>>();
> ```
>
> You need this only for shares that carry no record of their field — anything split before the
> level became part of the share, or built from raw coordinates. Shares that do carry a level are
> reconstructed correctly through the existing interface without any change.

### Variant 1 — BigInteger + ExtendedEuclideanAlgorithm

```csharp
var serviceCollection = new ServiceCollection();
serviceCollection.AddSingleton<IExtendedGcdAlgorithm<BigInteger>, ExtendedEuclideanAlgorithm<BigInteger>>();
serviceCollection.AddTransient<IMakeSharesUseCase<BigInteger>, SecretSplitter<BigInteger>>();
serviceCollection.AddTransient<IReconstructionUseCase<BigInteger>, SecretReconstructor<BigInteger>>();
using var serviceProvider = serviceCollection.BuildServiceProvider();

var makeSharesUseCase = serviceProvider.GetRequiredService<IMakeSharesUseCase<BigInteger>>();
var reconstructionUseCase = serviceProvider.GetRequiredService<IReconstructionUseCase<BigInteger>>();

// Build the secret from a pinned UTF-8 char buffer; the plaintext never lives
// in an unpinned managed string past the call site.
using var pinned = "Hello!".ToPinnedSecure();
using var secret = Secret<BigInteger>.FromText(pinned);
using var shares = makeSharesUseCase.MakeShares(3, 7, secret);

using var sharesChars = shares.ToCharArray();
Console.Out.Write(sharesChars.PoolArray, 0, sharesChars.Length);

using var reconstruction = reconstructionUseCase.Reconstruction(shares.Where(p => p.IsIndexEven).ToArray());
using var reconstructionChars = reconstruction.ToCharArray();
Console.Out.Write(reconstructionChars.PoolArray, 0, reconstructionChars.Length);
Console.WriteLine();
```

### Variant 2 — SecureBigInteger + FixedIterationSecretReconstructor

`FixedIterationSecretReconstructor<SecureBigInteger>` is a drop-in `IReconstructionUseCase<SecureBigInteger>` that supplies the fixed-iteration `MersenneSafeGcdAlgorithm` itself, so no separate GCD registration is needed. To use a different fixed-iteration strategy, additionally register `IFixedIterationExtendedGcdAlgorithm<SecureBigInteger>` and the reconstructor picks it up (see the [threat model](threat-model.md)).

```csharp
var serviceCollection = new ServiceCollection();
serviceCollection.AddTransient<IMakeSharesUseCase<SecureBigInteger>, SecretSplitter<SecureBigInteger>>();
serviceCollection.AddTransient<IReconstructionUseCase<SecureBigInteger>, FixedIterationSecretReconstructor<SecureBigInteger>>();
using var serviceProvider = serviceCollection.BuildServiceProvider();

var makeSharesUseCase = serviceProvider.GetRequiredService<IMakeSharesUseCase<SecureBigInteger>>();
var reconstructionUseCase = serviceProvider.GetRequiredService<IReconstructionUseCase<SecureBigInteger>>();

using var pinned = "Hello!".ToPinnedSecure();
using var secret = Secret<SecureBigInteger>.FromText(pinned);
using var shares = makeSharesUseCase.MakeShares(3, 7, secret);

using var sharesChars = shares.ToCharArray();
Console.Out.Write(sharesChars.PoolArray, 0, sharesChars.Length);

using var reconstruction = reconstructionUseCase.Reconstruction(shares.Where(p => p.IsIndexEven).ToArray());
using var reconstructionChars = reconstruction.ToCharArray();
Console.Out.Write(reconstructionChars.PoolArray, 0, reconstructionChars.Length);
Console.WriteLine();
```

Both use-case interfaces extend `IDisposable` and — under the `SecureBigInteger` backend — own pinned, security-sensitive buffers. Note that the use-case instances are not wrapped in `using` after `GetRequiredService`: the container owns the lifetime of services it resolves and disposes every tracked `IDisposable` transient when the `ServiceProvider` itself is disposed (here via `using var`). Disposing them explicitly at the call site would double-dispose against the container's cascade. In long-running hosts (ASP.NET, worker services) the root provider lives for the application's lifetime, so tracked transients accumulate until process exit — wrap each unit of work in a `using var scope = serviceProvider.CreateScope();` block (or register the use-cases as `AddScoped`) so the container disposes the resolved instances at scope end. The results of the calls (`secret`, `shares`, `reconstruction`, and the `ToCharArray` outputs) are caller-owned and remain wrapped in `using`.

## Random secret
Create a random secret in conjunction with the generation of shares. The length of the generated shares and of the secret are based on the security level. Here is an example with a pre-defined security level of 127 using the `BigInteger` backend; for the `SecureBigInteger + MersenneSafeGcdAlgorithm` wiring, see the [threat model](threat-model.md).
```csharp
using System;
using System.Linq;
using System.Numerics;

using SecretSharingDotNet.Cryptography;
using SecretSharingDotNet.Cryptography.ShamirsSecretSharing;
using SecretSharingDotNet.Math;

namespace Example1;

public class Program
{
  public static void Main(string[] args)
  {
    //// Create Shamir's Secret Sharing instance with BigInteger
    using var splitter = new SecretSplitter<BigInteger>();

    //// Minimum number of shared secrets for reconstruction: 3
    //// Maximum number of shared secrets: 7
    //// Security level: 127 (Mersenne prime exponent)
    using var shares = splitter.MakeShares(3, 7, 127, out var secret);
    using (secret)
    {
      //// Secret as big integer number
      Console.WriteLine((BigInteger)secret);

      //// Secret as base64 (pinned char buffer, not redaction-gated)
      using var secretBase64 = secret.ToBase64CharArray();
      Console.Out.Write(secretBase64.PoolArray, 0, secretBase64.Length);
      Console.WriteLine();

      var gcd = new ExtendedEuclideanAlgorithm<BigInteger>();
      //// The 'shares' instance contains the shared secrets
      using var combiner = new SecretReconstructor<BigInteger>(gcd);
      using var recoveredSecret1 = combiner.Reconstruction(shares.Where(p => p.IsIndexEven).ToArray());
      using var recoveredSecret2 = combiner.Reconstruction(shares.Where(p => p.IsIndexOdd).ToArray());

      //// All shares serialised as hex lines (pinned char buffer, not redaction-gated)
      using var sharesChars = shares.ToCharArray();
      Console.Out.Write(sharesChars.PoolArray, 0, sharesChars.Length);

      //// 1st recovered secret as big integer number
      Console.WriteLine((BigInteger)recoveredSecret1);

      //// 2nd recovered secret as big integer number
      Console.WriteLine((BigInteger)recoveredSecret2);

      //// 1st recovered secret as base64 (pinned char buffer, not redaction-gated)
      using var recovered1Base64 = recoveredSecret1.ToBase64CharArray();
      Console.Out.Write(recovered1Base64.PoolArray, 0, recovered1Base64.Length);
      Console.WriteLine();

      //// 2nd recovered secret as base64 (pinned char buffer, not redaction-gated)
      using var recovered2Base64 = recoveredSecret2.ToBase64CharArray();
      Console.Out.Write(recovered2Base64.PoolArray, 0, recovered2Base64.Length);
      Console.WriteLine();
    }
  }
}
```
## Pre-defined secret: text
Use a text as secret, which can be divided into shares. The length of the generated shares is based on the security level.
Here is an example with auto-detected security level using the `BigInteger` backend; for the `SecureBigInteger + MersenneSafeGcdAlgorithm` wiring, see the [threat model](threat-model.md).
```csharp
using System;
using System.Linq;
using System.Numerics;

using SecretSharingDotNet.Cryptography;
using SecretSharingDotNet.Cryptography.SecureInput;
using SecretSharingDotNet.Cryptography.ShamirsSecretSharing;
using SecretSharingDotNet.Math;

namespace Example2;

public class Program
{
  public static void Main(string[] args)
  {
    //// Create Shamir's Secret Sharing instance with BigInteger
    using var splitter = new SecretSplitter<BigInteger>();

    string password = "Hello World!!";
    //// Minimum number of shared secrets for reconstruction: 3
    //// Maximum number of shared secrets: 7
    //// Attention: The password length can change the security level set by passing
    //// it to MakeShares or assigning the SecurityLevel property.
    using var pinned = password.ToPinnedSecure();
    using var secret = Secret<BigInteger>.FromText(pinned);
    using var shares = splitter.MakeShares(3, 7, secret);

    var gcd = new ExtendedEuclideanAlgorithm<BigInteger>();
    //// The 'shares' instance contains the shared secrets
    using var combiner = new SecretReconstructor<BigInteger>(gcd);
    using var recoveredSecret1 = combiner.Reconstruction(shares.Where(p => p.IsIndexEven).ToArray());
    using var recoveredSecret2 = combiner.Reconstruction(shares.Where(p => p.IsIndexOdd).ToArray());

    //// All shares serialised as hex lines (pinned char buffer, not redaction-gated)
    using var sharesChars = shares.ToCharArray();
    Console.Out.Write(sharesChars.PoolArray, 0, sharesChars.Length);

    //// 1st recovered secret as UTF-8 text (pinned char buffer, not redaction-gated)
    using var recovered1Chars = recoveredSecret1.ToCharArray();
    Console.Out.Write(recovered1Chars.PoolArray, 0, recovered1Chars.Length);
    Console.WriteLine();

    //// 2nd recovered secret as UTF-8 text (pinned char buffer, not redaction-gated)
    using var recovered2Chars = recoveredSecret2.ToCharArray();
    Console.Out.Write(recovered2Chars.PoolArray, 0, recovered2Chars.Length);
    Console.WriteLine();
  }
}
```

## Pre-defined secret: number
Use an integer number as secret, which can be divided into shares. The length of the generated shares is based on the security level.
Here is an example with a pre-defined security level of 521 using the `BigInteger` backend; for the `SecureBigInteger + MersenneSafeGcdAlgorithm` wiring, see the [threat model](threat-model.md).
```csharp
using System;
using System.Linq;
using System.Numerics;

using SecretSharingDotNet.Cryptography;
using SecretSharingDotNet.Cryptography.ShamirsSecretSharing;
using SecretSharingDotNet.Math;

namespace Example3;

public class Program
{
  public static void Main(string[] args)
  {
    //// Create Shamir's Secret Sharing instance with BigInteger
    using var splitter = new SecretSplitter<BigInteger>();

    BigInteger number = 20000;
    //// Minimum number of shared secrets for reconstruction: 3
    //// Maximum number of shared secrets: 7
    //// Security level: 521 (Mersenne prime exponent)
    //// Attention: The size of the number can change the security level set by passing
    //// it to MakeShares or assigning the SecurityLevel property.
    using var secret = (Secret<BigInteger>)number;
    using var shares = splitter.MakeShares(3, 7, secret, 521);

    var gcd = new ExtendedEuclideanAlgorithm<BigInteger>();
    //// The 'shares' instance contains the shared secrets
    using var combiner = new SecretReconstructor<BigInteger>(gcd);
    using var recoveredSecret1 = combiner.Reconstruction(shares.Where(p => p.IsIndexEven).ToArray());
    using var recoveredSecret2 = combiner.Reconstruction(shares.Where(p => p.IsIndexOdd).ToArray());

    //// All shares serialised as hex lines (pinned char buffer, not redaction-gated)
    using var sharesChars = shares.ToCharArray();
    Console.Out.Write(sharesChars.PoolArray, 0, sharesChars.Length);

    //// 1st recovered secret as big integer number
    Console.WriteLine((BigInteger)recoveredSecret1);

    //// 2nd recovered secret as big integer number
    Console.WriteLine((BigInteger)recoveredSecret2);
  }
}
```
## Pre-defined secret: byte array
Use a byte array as secret, which can be divided into shares. The length of the generated shares is based on the security level.
Here is an example with auto-detected security level using the `BigInteger` backend; for the `SecureBigInteger + MersenneSafeGcdAlgorithm` wiring, see the [threat model](threat-model.md).
```csharp
using System;
using System.Linq;
using System.Numerics;

using SecretSharingDotNet.Cryptography;
using SecretSharingDotNet.Cryptography.ShamirsSecretSharing;
using SecretSharingDotNet.Math;

namespace Example4;

public class Program
{
  public static void Main(string[] args)
  {
    //// Create Shamir's Secret Sharing instance with BigInteger
    using var splitter = new SecretSplitter<BigInteger>();

    byte[] bytes = { 0x1D, 0x2E, 0x3F };
    //// Minimum number of shared secrets for reconstruction: 4
    //// Maximum number of shared secrets: 10
    //// Attention: The byte array size can change the security level set by passing
    //// it to MakeShares or assigning the SecurityLevel property.
    using var secret = (Secret<BigInteger>)bytes;
    using var shares = splitter.MakeShares(4, 10, secret);

    var gcd = new ExtendedEuclideanAlgorithm<BigInteger>();
    //// The 'shares' instance contains the shared secrets
    using var combiner = new SecretReconstructor<BigInteger>(gcd);
    using var recovered = combiner.Reconstruction(shares.Where(p => p.IsIndexEven).ToArray());
    using var recoveredBytes = recovered.ToByteArray();

    //// All shares serialised as hex lines (pinned char buffer, not redaction-gated)
    using var sharesChars = shares.ToCharArray();
    Console.Out.Write(sharesChars.PoolArray, 0, sharesChars.Length);

    //// The secret bytes
    Console.WriteLine($"{recoveredBytes[0]:X2}, {recoveredBytes[1]:X2}, {recoveredBytes[2]:X2}");
  }
}
```

## Secret
The `Secret<TNumber>` type is the unified envelope for the secrets that flow through `SecretSplitter` and `SecretReconstructor`. The four sub-examples below cover every public construction, inspection, and serialisation path on the `BigInteger` backend, plus a fixed-iteration round-trip on the `SecureBigInteger` backend. Sub-examples 5a–5c share the same payload — UTF-8 text `"Hello World!!"` — so each path can be traced end-to-end with the same expected output.

### Secret<T> — construct
```csharp
using System;
using System.Numerics;
using System.Text;

using SecretSharingDotNet.Cryptography;
using SecretSharingDotNet.SecureMemory;
using SecretSharingDotNet.Cryptography.SecureInput;

namespace Example5a;

public class Program
{
  public static void Main(string[] args)
  {
    //// The shared payload across 5a–5c.
    byte[] payload = Encoding.UTF8.GetBytes("Hello World!!");

    //// (a) From pinned UTF-8 characters via FromText.
    using var pinnedText = "Hello World!!".ToPinnedSecure();
    using var secretFromText = Secret<BigInteger>.FromText(pinnedText);

    //// (b) From pinned standard-Base64 characters via FromBase64 (RFC 4648 §4).
    using var pinnedBase64 = "SGVsbG8gV29ybGQhIQ==".ToPinnedSecure();
    using var secretFromBase64 = Secret<BigInteger>.FromBase64(pinnedBase64);

    //// (c) From byte sources — three equivalent paths.
    using var secretFromBytesCtor = new Secret<BigInteger>(payload);
    using var secretFromBytesImplicit = (Secret<BigInteger>)payload;
    using var pinnedBytes = new PinnedPoolArray<byte>(payload.Length);
    Array.Copy(payload, pinnedBytes.PoolArray, payload.Length);
    using var secretFromPinnedBytes = (Secret<BigInteger>)pinnedBytes;

    //// (d) From a numeric TNumber via implicit operator. The BigInteger is
    //// built from the same bytes in little-endian order — the representation
    //// that round-trips through Secret<BigInteger>.
    BigInteger asNumber = new BigInteger(payload);
    using var secretFromNumber = (Secret<BigInteger>)asNumber;

    //// All five secrets carry the same payload. Equality is constant-time.
    Console.WriteLine($"text  == bytes  : {secretFromText == secretFromBytesCtor}");
    Console.WriteLine($"text  == base64 : {secretFromText == secretFromBase64}");
    Console.WriteLine($"text  == pinned : {secretFromText == secretFromPinnedBytes}");
    Console.WriteLine($"text  == number : {secretFromText == secretFromNumber}");
  }
}
```

### Secret<T> — inspect, compare
```csharp
using System;
using System.Numerics;

using SecretSharingDotNet.Cryptography;
using SecretSharingDotNet.Cryptography.SecureInput;

namespace Example5b;

public class Program
{
  public static void Main(string[] args)
  {
    using var pinnedA = "Hello World!!".ToPinnedSecure();
    using var pinnedB = "Hello World!!".ToPinnedSecure();
    using var pinnedC = "GoodBye World".ToPinnedSecure();
    using var a = Secret<BigInteger>.FromText(pinnedA);
    using var b = Secret<BigInteger>.FromText(pinnedB);
    using var c = Secret<BigInteger>.FromText(pinnedC);

    //// Equality is a fixed-time byte comparison — no early exit on the
    //// first mismatch.
    Console.WriteLine($"a == b       : {a == b}");
    Console.WriteLine($"a != c       : {a != c}");
    Console.WriteLine($"a.Equals(b)  : {a.Equals(b)}");

    //// Ordering operators are defined for equal-length secrets; CompareTo
    //// returns the same three-way result as on any IComparable<T>.
    Console.WriteLine($"c < a              : {c < a}");
    Console.WriteLine($"a.CompareTo(b) = 0 : {a.CompareTo(b) == 0}");

    //// Implicit cast back to the numeric type. With BigInteger the bytes
    //// are interpreted little-endian — the same convention used on the
    //// wire and in Share<T>.
    BigInteger asNumber = a;
    Console.WriteLine($"a as BigInteger : {asNumber}");

    //// ToString() is build-mode-sensitive: DEBUG builds return the UTF-8
    //// decoded text, Release builds return the redaction sentinel
    //// "*** Secured Value ***" so secrets cannot leak through logs,
    //// exception messages, or debugger displays. Use ToCharArray() or
    //// ToByteArray() to read the actual content — neither is gated by
    //// the redaction sentinel.
    Console.WriteLine($"a.ToString()    : {a}");
  }
}
```

### Secret<T> — serialise
```csharp
using System;
using System.Numerics;
using System.Text;

using SecretSharingDotNet.Cryptography;
using SecretSharingDotNet.Cryptography.SecureInput;

namespace Example5c;

public class Program
{
  public static void Main(string[] args)
  {
    using var pinnedText = "Hello World!!".ToPinnedSecure();
    using var secret = Secret<BigInteger>.FromText(pinnedText);

    //// (a) Raw bytes — pinned, not redaction-gated.
    using var bytes = secret.ToByteArray();
    Console.WriteLine($"bytes length        : {bytes.Length}");

    //// (b) UTF-8 characters — pinned, not redaction-gated.
    using var chars = secret.ToCharArray();
    Console.Out.Write(chars.PoolArray, 0, chars.Length);
    Console.WriteLine();

    //// (c) Custom encoding — same payload, different bytes-on-the-wire.
    using var utf16Chars = secret.ToCharArray(Encoding.Unicode);
    Console.WriteLine($"utf-16 chars length : {utf16Chars.Length}");

    //// (d) Base64 as a pinned char buffer — pinned, not redaction-gated.
    using var base64Chars = secret.ToBase64CharArray();
    Console.Out.Write(base64Chars.PoolArray, 0, base64Chars.Length);
    Console.WriteLine();

    //// (e) Base64 as a string — convenient for interop APIs that take
    //// string. Note: the returned string lives on the managed heap and is
    //// NOT pinned or securely cleared; treat it as ephemeral and minimise
    //// its scope.
    string base64 = secret.ToBase64String();
    Console.WriteLine($"base64 string       : {base64}");
  }
}
```

### Secret<SecureBigInteger> — text, number, bytes + fixed-iteration round-trip
```csharp
using System;

using SecretSharingDotNet.Cryptography;
using SecretSharingDotNet.Cryptography.SecureInput;
using SecretSharingDotNet.Cryptography.ShamirsSecretSharing;
using SecretSharingDotNet.Math;
using SecretSharingDotNet.Math.Numerics;

namespace Example5d;

public class Program
{
  public static void Main(string[] args)
  {
    //// Three Secret<SecureBigInteger> instances — one per input shape.
    //// Each one is split through SecretSplitter<SecureBigInteger> and
    //// reconstructed via the fixed-iteration MersenneSafeGcdAlgorithm path.

    //// (a) Text — pinned UTF-8 chars in, Secret<SecureBigInteger> out.
    using var pinnedText = "Hello World!!".ToPinnedSecure();
    using var textSecret = Secret<SecureBigInteger>.FromText(pinnedText);

    //// (b) Number — implicit cast from SecureBigInteger.
    using var numberSecret = (Secret<SecureBigInteger>)(SecureBigInteger)20000;

    //// (c) Bytes — implicit cast from byte[].
    byte[] payload = { 0x1D, 0x2E, 0x3F };
    using var bytesSecret = (Secret<SecureBigInteger>)payload;

    //// SecretSplitter and SecretReconstructor auto-adjust their security
    //// level to the secret being processed, so one pair of instances
    //// serves all three shapes. FixedIterationSecretReconstructor wires the
    //// fixed-iteration MersenneSafeGcdAlgorithm modular inverse used during
    //// Lagrange interpolation.
    using var splitter = new SecretSplitter<SecureBigInteger>();
    using var combiner = new FixedIterationSecretReconstructor<SecureBigInteger>();

    //// (a) Text round-trip.
    using var textShares = splitter.MakeShares(3, 7, textSecret);
    using var recoveredText = combiner.Reconstruction(textShares);
    using var recoveredChars = recoveredText.ToCharArray();
    Console.Out.Write(recoveredChars.PoolArray, 0, recoveredChars.Length);
    Console.WriteLine();

    //// (b) Number round-trip — explicit security level of 521.
    using var numberShares = splitter.MakeShares(3, 7, numberSecret, 521);
    using var recoveredNumber = combiner.Reconstruction(numberShares);
    //// Both Secret<SecureBigInteger>.ToString() and SecureBigInteger.ToString()
    //// return the redaction sentinel "*** Secured Value ***" in Release builds.
    //// Cast through an unprotected primitive — here, explicit (int) — to read
    //// the actual value. Use this only inside an audited scope where revealing
    //// the value is intentional.
    Console.WriteLine((int)(SecureBigInteger)recoveredNumber);

    //// (c) Bytes round-trip.
    using var bytesShares = splitter.MakeShares(4, 10, bytesSecret);
    using var recoveredBytes = combiner.Reconstruction(bytesShares);
    using var recoveredByteArray = recoveredBytes.ToByteArray();
    Console.WriteLine($"{recoveredByteArray[0]:X2} {recoveredByteArray[1]:X2} {recoveredByteArray[2]:X2}");
  }
}
```

## Shares
The library exposes wire-format I/O on two surfaces: individual `Share<TNumber>` points and `Shares<TNumber>` collections. The three sub-examples below cover every public construction and serialisation path for both surfaces, plus a round-trip through `SecretReconstructor`. The example values reconstruct to `52199147989510990914370102003412153`.

### Single Share<T> — construct, inspect, serialize
```csharp
using System;
using System.Numerics;

using SecretSharingDotNet.Cryptography;
using SecretSharingDotNet.Cryptography.SecureInput;
using SecretSharingDotNet.Math;

namespace Example6a;

public class Program
{
  public static void Main(string[] args)
  {
    //// (a) Parse from "INDEX-VALUE" hex text (pinned char buffer). The "0x"
    //// prefix on either coordinate is accepted; the index must be > 0.
    using var pinnedText = "05-CDECB88126DBC04D753E0C2D83D7B55D".ToPinnedSecure();
    using var shareFromText = new Share<BigInteger>(pinnedText);

    //// (b) From raw little-endian byte pairs (index bytes + value bytes).
    byte[] indexBytes = { 0x05 };
    byte[] valueBytes = { 0xCD, 0xEC, 0xB8, 0x81, 0x26, 0xDB, 0xC0, 0x4D,
                          0x75, 0x3E, 0x0C, 0x2D, 0x83, 0xD7, 0xB5, 0x5D };
    using var shareFromBytes = new Share<BigInteger>(indexBytes, valueBytes);

    //// (c) Programmatic — pass Calculator<BigInteger> instances. The Share
    //// takes ownership of both calculators and disposes them in cascade;
    //// do not wrap the calculator locals in 'using' (would double-dispose).
    Calculator<BigInteger> idx = new BigInteger(5);
    Calculator<BigInteger> val = new BigInteger(42);
    using var shareFromCalc = new Share<BigInteger>(idx, val);

    //// Inspect index, value and parity.
    Console.WriteLine($"Index: {(BigInteger)shareFromText.Index}");
    Console.WriteLine($"Value: {(BigInteger)shareFromText.Value}");
    Console.WriteLine($"IsIndexEven: {shareFromText.IsIndexEven}");
    Console.WriteLine($"IsIndexOdd: {shareFromText.IsIndexOdd}");

    //// Serialise back to hex (pinned char buffer, not redaction-gated).
    //// Default: uppercase, no "0x" prefix.
    using var hexDefault = shareFromText.ToCharArray();
    Console.Out.Write(hexDefault.PoolArray, 0, hexDefault.Length);
    Console.WriteLine();

    //// Lowercase with "0x" prefix on each coordinate.
    using var hexLowerPrefixed = shareFromText.ToCharArray(uppercase: false, withPrefix: true);
    Console.Out.Write(hexLowerPrefixed.PoolArray, 0, hexLowerPrefixed.Length);
    Console.WriteLine();
  }
}
```

### Shares<T> collection — construct, serialize
```csharp
using System;
using System.Numerics;

using SecretSharingDotNet.Cryptography;
using SecretSharingDotNet.SecureMemory;
using SecretSharingDotNet.Cryptography.SecureInput;
using SecretSharingDotNet.Math;

namespace Example6b;

public class Program
{
  public static void Main(string[] args)
  {
    //// === Three deserialisation paths ===
    //// (A fourth path is SecretSplitter.MakeShares(...) — see the earlier
    //// examples. The methods below cover deserialisation from wire formats.)

    //// (a) From a Share<T>[] via implicit operator. The Shares<T> adopts the
    //// array and disposes each contained Share in cascade.
    using var p1 = "02-665C74ED38FDFF095B2FC9319A272A75".ToPinnedSecure();
    using var p2 = "05-CDECB88126DBC04D753E0C2D83D7B55D".ToPinnedSecure();
    using var p3 = "07-54A83E34AB0310A7F5D80F2A68FD4F33".ToPinnedSecure();
    using var sharesFromArray = (Shares<BigInteger>)new[]
    {
        new Share<BigInteger>(p1),
        new Share<BigInteger>(p2),
        new Share<BigInteger>(p3),
    };

    //// (b) From a single multi-line text blob via FromText. The pinned buffer
    //// is the caller's; FromText returns a separately-owned Shares<T>.
    using var pinnedBlob = ("02-665C74ED38FDFF095B2FC9319A272A75" + Environment.NewLine +
                           "05-CDECB88126DBC04D753E0C2D83D7B55D" + Environment.NewLine +
                           "07-54A83E34AB0310A7F5D80F2A68FD4F33").ToPinnedSecure();
    using var sharesFromBlob = Shares<BigInteger>.FromText(pinnedBlob);

    //// (c) From per-line pinned buffers via FromTextLines — useful when share
    //// lines arrive separately (e.g., from a UI form).
    using var line1 = "02-665C74ED38FDFF095B2FC9319A272A75".ToPinnedSecure();
    using var line2 = "05-CDECB88126DBC04D753E0C2D83D7B55D".ToPinnedSecure();
    using var line3 = "07-54A83E34AB0310A7F5D80F2A68FD4F33".ToPinnedSecure();
    using var sharesFromLines = Shares<BigInteger>.FromTextLines(new[] { line1, line2, line3 });

    //// === Serialise a Shares<T> back to multi-line text (pinned, not redacted) ===
    //// Default: uppercase, no "0x" prefix.
    using var sharesUpperNoPrefix = sharesFromBlob.ToCharArray();
    Console.Out.Write(sharesUpperNoPrefix.PoolArray, 0, sharesUpperNoPrefix.Length);

    //// Lowercase with "0x" prefix on each coordinate.
    using var sharesLowerPrefixed = sharesFromBlob.ToCharArray(uppercase: false, withPrefix: true);
    Console.Out.Write(sharesLowerPrefixed.PoolArray, 0, sharesLowerPrefixed.Length);

    //// === Implicit conversions on Shares<T> ===
    //// To PinnedPoolArray<char>: allocates a fresh pinned buffer with the
    //// same content as ToCharArray() default; the caller owns the result.
    using PinnedPoolArray<char> asPinnedChars = sharesFromBlob;

    //// To Share<T>[]: a snapshot array whose entries alias the shares owned
    //// by sharesFromBlob — do not dispose the elements individually.
    Share<BigInteger>[] asArray = sharesFromBlob;
    Console.WriteLine($"Share count: {asArray.Length}");
  }
}
```

### Round-trip — reconstruction
```csharp
using System;
using System.Numerics;

using SecretSharingDotNet.Cryptography;
using SecretSharingDotNet.Cryptography.SecureInput;
using SecretSharingDotNet.Cryptography.ShamirsSecretSharing;
using SecretSharingDotNet.Math;

namespace Example6c;

public class Program
{
  public static void Main(string[] args)
  {
    //// Build a Shares<BigInteger> from three lines of wire-format text:
    using var pinnedBlob = ("02-665C74ED38FDFF095B2FC9319A272A75" + Environment.NewLine +
                           "05-CDECB88126DBC04D753E0C2D83D7B55D" + Environment.NewLine +
                           "07-54A83E34AB0310A7F5D80F2A68FD4F33").ToPinnedSecure();
    using var shares = Shares<BigInteger>.FromText(pinnedBlob);

    //// Reconstruct via the variable-time ExtendedEuclideanAlgorithm; for the
    //// fixed-iteration path with SecureBigInteger + MersenneSafeGcdAlgorithm,
    //// see docs/threat-model.md.
    var gcd = new ExtendedEuclideanAlgorithm<BigInteger>();
    using var combiner = new SecretReconstructor<BigInteger>(gcd);
    using var recovered = combiner.Reconstruction(shares);

    //// Output should be 52199147989510990914370102003412153
    Console.WriteLine((BigInteger)recovered);
  }
}
```

## Storing shares

A share is a point on a polynomial over a finite field, and before v1.1.0 it carried no record of
*which* field. Reconstruction therefore derived one from the share values — and when every value in
the supplied subset happened to fall below a smaller Mersenne prime, it interpolated in the wrong
field and returned a different secret, with no error at all
([issue #403](https://github.com/shinji-san/SecretSharingDotNet/issues/403)).

Since v1.1.0, a share created by `MakeShares` records its field in `Share<TNumber>.SecurityLevel`, and
reconstruction uses it. **For shares held in memory, nothing needs to change** — the round trip is
correct.

> [!IMPORTANT]
> **Stored shares are a different matter.** `ToCharArray()` still writes the two-segment
> `INDEX-VALUE` form by default, which has no room for the level, so a share written out and read
> back is in the same position as a share from before v1.1.0. Opting into the three-segment form is
> what closes that, and it becomes the default in the next breaking-change cycle.

### Writing shares that keep their field

```csharp
//// Three segments: INDEX-VALUE-LEVEL, the exponent hexadecimal.
using var text = shares.ToCharArray(uppercase: true, withPrefix: false, ShareFormat.Extended);

//// Reads either form; a third segment is adopted when present.
using var reparsed = Shares<BigInteger>.FromText(text);
```

An older version of this library reading the three-segment form **fails loudly** rather than
misreading it: its parser takes the first separator and treats the remainder as the value, where the
second separator is not a hexadecimal digit and the decode is refused.

### Migrating shares you already stored

```csharp
//// Re-issue with the exponent the split actually used. Coordinates are cloned,
//// so the originals stay usable.
using var migrated = legacyShares.ReissueWithSecurityLevel(17);
using var text = migrated.ToCharArray(uppercase: true, withPrefix: false, ShareFormat.Extended);
```

> [!WARNING]
> **You must supply the exponent the split actually used, after any auto-raise.** `MakeShares`
> raises the level to fit the secret including its mark byte, so a one-byte secret split without an
> explicit level lands on **17**, which is rarely the number a caller remembers asking for. A
> supported exponent that is large enough but simply wrong is accepted without complaint and can
> silently reconstruct a different secret: the coordinates do not say which field produced them,
> which is the absence this whole change works around. What *is* refused is an unsupported
> exponent, a field too small for the coordinates, and one contradicting a level the share already
> records.

"Unsupported" means the library's built-in table of Mersenne exponents. If your
`SecurityLevelManager` is built on your own `IMersennePrimeProvider`, migrate against that provider,
so migration and reconstruction answer to the same table:

```csharp
//// The provider decides exactly: an exponent it supports is accepted even where the
//// built-in table lacks it, and one it rejects is refused even where the table has it.
using var migrated = legacyShares.ReissueWithSecurityLevel(17, mersennePrimeProvider);
```

Checking the exponent against your provider first and then calling the one-argument overload does
not achieve the same: that overload refuses anything the built-in table lacks, whatever your
provider says.

### Naming the field per call instead

If you would rather not rewrite stored shares, name the field at reconstruction time:

```csharp
serviceCollection.AddTransient<IReconstructionWithSecurityLevelUseCase<BigInteger>, SecretReconstructor<BigInteger>>();
// ...
using var recovered = useCase.Reconstruction(legacyShares, 17);
```

The explicit level outranks what the shares record but is checked against it — a contradiction is
refused rather than silently preferred. **Without** such an argument, shares that disagree among
themselves, or where some record a level and others do not, are refused: there is nothing to choose
between them, and choosing would be the guesswork this change removes. **With** one there is nothing
left to choose, because the caller has chosen — so a set mixing re-issued and untouched shares
reconstructs, as long as every level actually recorded matches the argument.

That is also what makes the migration above resumable: a half-migrated set is usable through
`Reconstruction(shares, 17)` rather than being stuck between two states.

Shares that record **nothing** go through the value-derived selection only where no level is named
at all. Where that now collapses to an undecodable secret, the failure is a `ReconstructionException`
naming the exponent the interpolation ran under, rather than an `ArgumentException` from two layers
down. It still cannot name a cause: a tampered share produces exactly the same picture.

## Secure console input
`ConsolePasswordReader` reads keyboard input one keystroke at a time directly into a pinned `PinnedPoolArray<char>` — no `string`, no `StringBuilder`, no intermediate heap copy. The pinned buffer is the same shape that `Secret<TNumber>.FromText(...)`, `Share<TNumber>(...)`, and `Shares<TNumber>.FromText(...)` / `Shares<TNumber>.FromTextLines(...)` accept directly, so secrets and shares can flow end-to-end without ever materialising as a `string`. The two sub-examples below cover both directions: reading a secret to split, and reading shares to reconstruct.

Editing behaviour of `ConsolePasswordReader.ReadPassword(int maxLength, char? echoChar = null)`:

- Pressing **Enter** ends the input and returns the pinned buffer; the buffer's `Length` reflects the number of characters actually entered.
- Pressing **Backspace** deletes the most recently accepted character and erases the echo on the console if `echoChar` is set.
- Once `maxLength` characters have been entered, additional printable keystrokes are silently ignored until the user presses **Enter** or **Backspace**.
- Non-printable control keys other than **Enter** and **Backspace** are ignored.
- **Ctrl+C** is not intercepted — the default console behaviour (process termination) applies.
- `ReadPassword` throws `InvalidOperationException` when standard input is redirected (`Console.IsInputRedirected == true`); the API is interactive-only and cannot read from a pipe or a redirected file.

### Read a secret, then split
```csharp
using System;
using System.Numerics;

using SecretSharingDotNet.Cryptography;
using SecretSharingDotNet.Cryptography.SecureInput;
using SecretSharingDotNet.Cryptography.ShamirsSecretSharing;
using SecretSharingDotNet.Math;

namespace Example7a;

public class Program
{
  public static void Main(string[] args)
  {
    //// Read up to 64 characters from the console, echoing '*' per keystroke.
    //// The returned buffer is pinned and securely cleared on dispose.
    Console.Write("Secret: ");
    using var pinnedSecret = ConsolePasswordReader.ReadPassword(maxLength: 64, echoChar: '*');
    Console.WriteLine();
    using var secret = Secret<BigInteger>.FromText(pinnedSecret);

    //// Split the secret into 7 shares; any 3 are enough to reconstruct.
    using var splitter = new SecretSplitter<BigInteger>();
    using var shares = splitter.MakeShares(3, 7, secret);

    //// Emit all shares as hex lines (pinned char buffer, not redaction-gated).
    using var sharesChars = shares.ToCharArray();
    Console.Out.Write(sharesChars.PoolArray, 0, sharesChars.Length);
    Console.WriteLine();
  }
}
```

### Read shares, then reconstruct
```csharp
using System;
using System.Numerics;

using SecretSharingDotNet.Cryptography;
using SecretSharingDotNet.SecureMemory;
using SecretSharingDotNet.Cryptography.SecureInput;
using SecretSharingDotNet.Cryptography.ShamirsSecretSharing;
using SecretSharingDotNet.Math;

namespace Example7b;

public class Program
{
  public static void Main(string[] args)
  {
    //// Read three share lines from the console — silent input, since
    //// echoChar defaults to null. Each line lands in its own pinned buffer.
    const int shareCount = 3;
    var entries = new PinnedPoolArray<char>[shareCount];
    for (int i = 0; i < shareCount; i++)
    {
      Console.Write($"Share {i + 1}: ");
      entries[i] = ConsolePasswordReader.ReadPassword(maxLength: 256);
      Console.WriteLine();
    }

    //// Wrap the per-line buffers in a PinnedPoolArrayList — disposing it
    //// cascades to every contained PinnedPoolArray<char>. Shares.FromTextLines
    //// reads from the lines without taking ownership; the caller (this scope)
    //// retains and disposes them.
    using var pinnedLines = new PinnedPoolArrayList<char>(entries);
    using var shares = Shares<BigInteger>.FromTextLines(pinnedLines);

    //// Reconstruct via the variable-time ExtendedEuclideanAlgorithm; for the
    //// fixed-iteration path with SecureBigInteger and MersenneSafeGcdAlgorithm,
    //// see docs/threat-model.md.
    var gcd = new ExtendedEuclideanAlgorithm<BigInteger>();
    using var combiner = new SecretReconstructor<BigInteger>(gcd);
    using var recovered = combiner.Reconstruction(shares);

    //// Emit the recovered secret as UTF-8 text (pinned char buffer, not
    //// redaction-gated).
    using var recoveredChars = recovered.ToCharArray();
    Console.Out.Write(recoveredChars.PoolArray, 0, recoveredChars.Length);
    Console.WriteLine();
  }
}
```
