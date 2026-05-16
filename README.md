# ✨ SecretSharingDotNet ✨
A C# implementation of Shamir's Secret Sharing.

# Build & Test Status Of Default Branch 👷
<table>
  <thead>
    <tr>
        <th>Status</th>
        <th>Solution</th>
        <th>Project Format</th>
        <th>.NET Version</th>
    </tr>
  </thead>
  <tbody>
      <tr>
          <td rowspan=8><a href ="https://github.com/shinji-san/SecretSharingDotNet/actions/workflows/dotnetall.yml" target="_blank"><img src="https://github.com/shinji-san/SecretSharingDotNet/actions/workflows/dotnetall.yml/badge.svg?branch=main" alt="Build status"/></a></td>
          <td rowspan=8><code>SecretSharingDotNet.slnx</code></td>
          <td rowspan=8>SDK</td>
          <td>Standard 2.0</td>
      </tr>
      <tr>
          <td>Standard 2.1</td>
      </tr>
      <tr>
          <td>FX 4.7.2</td>
      </tr>
      <tr>
          <td>FX 4.8</td>
      </tr>
      <tr>
          <td>FX 4.8.1</td>
      </tr>
      <tr>
          <td>.NET 8</td>
      </tr>
      <tr>
          <td>.NET 9</td>
      </tr>
      <tr>
          <td>.NET 10</td>
      </tr>
  </tbody>
</table>

# NuGet 📦
## Supported Target Frameworks
<table>
  <thead>
    <tr>
        <th>Build And Test Status</th>
        <th>NuGet Version</th>
        <th>Git Tag</th>
        <th>Target Frameworks</th>
    </tr>
  </thead>
  <tbody>
      <tr>
          <td rowspan=8><a href="https://github.com/shinji-san/SecretSharingDotNet/actions/workflows/publishing.yml" target="_blank"><img src="https://github.com/shinji-san/SecretSharingDotNet/actions/workflows/publishing.yml/badge.svg" alt="SecretSharingDotNet - NuGet Publishing"/></a></td>
          <td rowspan=8><a href="https://badge.fury.io/nu/SecretSharingDotNet" target="_blank"><img src="https://badge.fury.io/nu/SecretSharingDotNet.svg" alt="NuGet Version 0.14.0"/></a></td>
          <td rowspan=8><a href="https://github.com/shinji-san/SecretSharingDotNet/tree/v0.14.0" target="_blank"><img src="https://img.shields.io/badge/SecretSharingDotNet-0.14.0-green.svg?logo=github&logoColor=959da5&color=2ebb4e&labelColor=2b3137" alt="Tag"/></a></td>
          <td>Standard 2.0</td>
      </tr>
      <tr>
          <td>Standard 2.1</td>
      </tr>
      <tr>
          <td>FX 4.7.2</td>
      </tr>
      <tr>
          <td>FX 4.8</td>
      </tr>
      <tr>
          <td>FX 4.8.1</td>
      </tr>
      <tr>
          <td>.NET 8</td>
      </tr>
      <tr>
          <td>.NET 9</td>
      </tr>
      <tr>
          <td>.NET 10</td>
      </tr>
  </tbody>
</table>

## Install SecretSharingDotNet package 📥

1. Open a console and switch to the directory containing your project file.

2. Use the following command to install version 0.14.0 of the SecretSharingDotNet package:

    ```dotnetcli
    dotnet add package SecretSharingDotNet -v 0.14.0 -f <FRAMEWORK>
    ```

3. After the completion of the command, look at the project file to make sure that the package is successfully installed.

   You can open the `.csproj` file to see the added package reference:

    ```xml
    <ItemGroup>
      <PackageReference Include="SecretSharingDotNet" Version="0.14.0" />
    </ItemGroup>
    ```
## Remove SecretSharingDotNet package 📤

1. Open a console and switch to the directory containing your project file.

2. Use the following command to remove the SecretSharingDotNet package:

    ```dotnetcli
    dotnet remove package SecretSharingDotNet
    ```

3. After the completion of the command, look at the project file to make sure that the package is successfully removed.

   You can open the `.csproj` file to check the deleted package reference.

# Usage 🔧
> [!IMPORTANT]
> Breaking Change in v0.14.0: The string encoding in `SecretSharingDotNet` with text secrets is UTF-8.

## Basics
Use the function `MakeShares` to generate the shares, based on a random or pre-defined secret.
Afterwards, use the function `Reconstruction` to reconstruct the original secret.

The library is generic in the numeric backend: `BigInteger` (used in the examples below) or `SecureBigInteger` (pinned-memory storage with constant-time arithmetic — see the Security & Threat Model section). Both `IMakeSharesUseCase<TNumber>` and `IReconstructionUseCase<TNumber>` implement `IDisposable`; wrap them in `using` so pinned, security-sensitive buffers are released deterministically.

The length of the shares is based on the security level. On the splitter side, you can set it three ways: pass it as the `securityLevel` parameter of the `MakeShares` overload that takes one, assign the `SecretSplitter<TNumber>.SecurityLevel` property, or inject a pre-configured `ISecurityLevelManager<TNumber>` through the constructor. The configured level is overridden when the secret size exceeds the Mersenne prime derived from it — the library auto-adjusts upward. It is not necessary to define a security level for a reconstruction: `SecretReconstructor<TNumber>.SecurityLevel` is read-only and is derived from the supplied shares on every `Reconstruction` call.

The `ToString()` overrides on `Secret<TNumber>`, `Share<TNumber>`, and `Shares<TNumber>` are build-mode-sensitive: DEBUG builds return the actual content, while Release builds return the redaction sentinel `"*** Secured Value ***"` so secrets cannot accidentally leak through logs, exception messages, or other diagnostic output.

## Using the SecretSharingDotNet library with DI in a .NET project
This guide demonstrates two parallel DI wirings: the `BigInteger` backend with `ExtendedEuclideanAlgorithm` (BCL-native, variable-time arithmetic) and the `SecureBigInteger` backend with `MersenneSafeGcdAlgorithm` (pinned-memory storage, constant-time arithmetic on public bit-length — see the Security & Threat Model section for the trade-offs). Both variants share the same import block:

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

### Variant 2 — SecureBigInteger + MersenneSafeGcdAlgorithm

The wiring is identical except for the substituted `TNumber` and the GCD algorithm — `MersenneSafeGcdAlgorithm<SecureBigInteger>` is the constant-time alternative to `ExtendedEuclideanAlgorithm<SecureBigInteger>` (see the Security & Threat Model section).

```csharp
var serviceCollection = new ServiceCollection();
serviceCollection.AddSingleton<IExtendedGcdAlgorithm<SecureBigInteger>, MersenneSafeGcdAlgorithm<SecureBigInteger>>();
serviceCollection.AddTransient<IMakeSharesUseCase<SecureBigInteger>, SecretSplitter<SecureBigInteger>>();
serviceCollection.AddTransient<IReconstructionUseCase<SecureBigInteger>, SecretReconstructor<SecureBigInteger>>();
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

## Random secret 🎲
Create a random secret in conjunction with the generation of shares. The length of the generated shares and of the secret are based on the security level. Here is an example with a pre-defined security level of 127 using the `BigInteger` backend; for the constant-time `SecureBigInteger + MersenneSafeGcdAlgorithm` wiring, see the Security & Threat Model section.
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
## Pre-defined secret: text 📄
Use a text as secret, which can be divided into shares. The length of the generated shares is based on the security level.
Here is an example with auto-detected security level using the `BigInteger` backend; for the constant-time `SecureBigInteger + MersenneSafeGcdAlgorithm` wiring, see the Security & Threat Model section.
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

## Pre-defined secret: number 🔢
Use an integer number as secret, which can be divided into shares. The length of the generated shares is based on the security level.
Here is an example with a pre-defined security level of 521 using the `BigInteger` backend; for the constant-time `SecureBigInteger + MersenneSafeGcdAlgorithm` wiring, see the Security & Threat Model section.
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
## Pre-defined secret: byte array ▦
Use a byte array as secret, which can be divided into shares. The length of the generated shares is based on the security level.
Here is an example with auto-detected security level using the `BigInteger` backend; for the constant-time `SecureBigInteger + MersenneSafeGcdAlgorithm` wiring, see the Security & Threat Model section.
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

## Shares 🔑
The library exposes wire-format I/O on two surfaces: individual `Share<TNumber>` points and `Shares<TNumber>` collections. The three sub-examples below cover every public construction and serialisation path for both surfaces, plus a round-trip through `SecretReconstructor`. The example values reconstruct to `52199147989510990914370102003412153`.

### Single Share<T> — construct, inspect, serialize
```csharp
using System;
using System.Numerics;

using SecretSharingDotNet.Cryptography;
using SecretSharingDotNet.Cryptography.SecureInput;
using SecretSharingDotNet.Math;

namespace Example5a;

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
using SecretSharingDotNet.Cryptography.SecureArray;
using SecretSharingDotNet.Cryptography.SecureInput;
using SecretSharingDotNet.Math;

namespace Example5b;

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

namespace Example5c;

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
    //// constant-time path with SecureBigInteger + MersenneSafeGcdAlgorithm,
    //// see the Security & Threat Model section.
    var gcd = new ExtendedEuclideanAlgorithm<BigInteger>();
    using var combiner = new SecretReconstructor<BigInteger>(gcd);
    using var recovered = combiner.Reconstruction(shares);

    //// Output should be 52199147989510990914370102003412153
    Console.WriteLine((BigInteger)recovered);
  }
}
```

# Security & Threat Model 🛡️

The library targets two backends through the `Calculator<TNumber>` strategy pattern: the
.NET-native `BigInteger` and a custom `SecureBigInteger`. The latter is positioned as the
security-conscious option, but its protection is scoped — it is not a drop-in replacement
for hardened native crypto stacks.

**`SecureBigInteger` protects against:**

- **Passive memory disclosure.** The internal byte buffer is GC-pinned and overwritten with
  a 3-pass scramble plus `CryptographicOperations.ZeroMemory` on dispose. Heap snapshots,
  swap files, and reuse-after-free of the same physical pages cannot recover plaintext.
- **Length-vs-content equality leaks.** `SecureBigInteger.Equals` pre-pads to
  `max(left, right)` and uses fixed-time comparison; equality timing does not leak which
  prefix bytes match. The comparison runs uniformly across all targeted TFMs via a
  private XOR-OR-fold helper, with no `#if`-conditional code path.
- **Insecure RNG.** Every random draw goes through
  `System.Security.Cryptography.RandomNumberGenerator` via the internal
  `Cryptography.SecureRandom` helper. No `System.Random`, no PRNG seeds.
- **Operand-value timing leaks in core arithmetic.** `Add`, `Subtract`, `Multiply`,
  `Square`, `Divide`, and `Remainder` iterate a fixed number of limbs equal to the public
  `max(left.LimbCount, right.LimbCount)` and use branchless carry/borrow propagation;
  their timing depends only on the public operand bit length, not on operand values.
  `MersenneModulo` is constant-time on the public Mersenne exponent and operand limb
  count.
- **No variable-time number-theoretic surface.** The legacy `Gcd`, `ModPow`, `Log`,
  `Log10`, and `Log2` static methods — whose implementations branched on operand values
  or invoked `Math.Log` on operand-derived doubles — were removed from
  `SecureBigInteger`. The surface is narrowed to operations whose timing is bounded by
  the public bit-length, so there is no longer a way to call a variable-time-on-secret-
  operand method by accident.
- **Timing leaks in modular inversion** (when the consumer opts in).
  `MersenneSafeGcdAlgorithm<TNumber>` implements the Bernstein–Yang "safegcd" / divstep
  recurrence and provides a constant-time modular inverse for use inside
  `SecretReconstructor.DivMod`. The iteration count is fixed at the public Mersenne
  exponent, independent of operand values. The exponent is derived from the
  modulus passed to `Compute` at call time — the algorithm holds no
  `ISecurityLevelManager` reference, so it cannot drift from the
  `SecretReconstructor` consuming it. To wire it in, pass a
  `MersenneSafeGcdAlgorithm<TNumber>` instance as the GCD strategy when constructing
  `SecretReconstructor<TNumber>`:

  ```csharp
  var gcd = new MersenneSafeGcdAlgorithm<SecureBigInteger>();
  var combiner = new SecretReconstructor<SecureBigInteger>(gcd);
  var recovered = combiner.Reconstruction(shares);
  ```

**Public-input dependence (treated as public, not secret):**

- **`Pow(int exponent)`** is variable-time *on the exponent value* (iteration count is
  `O(log₂(exponent))`). The exponent is **not** treated as secret; the per-iteration
  arithmetic on the secret base goes through the constant-time-on-bit-length `Multiply`.
  Callers must not pass secret-derived exponents through this method.

**`SecureBigInteger` does *not* protect against:**

- **Variable-time modular inverse on the default reconstruction path.** When
  `SecretReconstructor` is constructed with the customary
  `ExtendedEuclideanAlgorithm<TNumber>` GCD strategy, its iteration count is
  variable on the operand values. Consumers whose threat model includes timing
  analysis of reconstruction must inject `MersenneSafeGcdAlgorithm<TNumber>`
  explicitly. A convenience overload routing the SecureBigInteger backend to
  `MersenneSafeGcdAlgorithm<SecureBigInteger>` by default is planned future work.

Constant-time big-integer arithmetic in pure managed .NET is non-trivial; canonical
implementations (libsodium, BoringSSL) rely on fixed-width representation, branchless
conditional moves, and hand-tuned cache-pattern audits. The constant-time primitives
exposed here approximate that approach within the constraints of managed .NET — they
are best-effort against passive timing analysis and have *not* been audited against
active co-located attackers (cross-VM cache attacks, browser high-resolution timers,
network-RTT measurements). Consumers whose threat model includes such attackers should
layer the operation through a constant-time crypto stack (e.g. libsodium-net,
hardware-backed enclaves) rather than rely on the `SecureBigInteger` naming alone.

# CLI building instructions
## Prerequisites
For the following instructions, please make sure that you are connected to the internet. If necessary, NuGet will try to restore the [xUnit](https://xunit.net/) packages.

If you start the unit tests on Linux, you must install the `mono-complete` package in case of the .NET Frameworks 4.7.2, 4.8 and 4.8.1.
You can find the Mono installation instructions [here](https://www.mono-project.com/download/stable/#download-lin).

The .NET Frameworks 4.7.2, 4.8 and 4.8.1 can be found [here](https://dotnet.microsoft.com/download/dotnet-framework).

The .NET SDKs 8.0, 9.0 and 10.0 can be found [here](https://dotnet.microsoft.com/download/dotnet).

## Build and test the solution
You can use the `SecretSharingDotNet.slnx` solution file with the `dotnet` command to build the [SecretSharingDotNet](#secretsharingdotnet) library in the `Debug` or `Release` configuration. You can also use the `dotnet` command to start the unit tests.

### 1. Restore NuGet packages

```dotnetcli
dotnet restore SecretSharingDotNet.slnx
```

### 2. Build the solution

```dotnetcli
dotnet build -c Debug --no-restore SecretSharingDotNet.slnx
```

or

```dotnetcli
dotnet build -c Release --no-restore SecretSharingDotNet.slnx
```

### 3. Test the solution

```dotnetcli
dotnet test -c Debug --no-restore --no-build SecretSharingDotNet.slnx -- RunConfiguration.TargetPlatform=x64 RunConfiguration.MaxCpuCount=1  xUnit.AppDomain=denied xUnit.ParallelizeAssembly=false xUnit.ParallelizeTestCollections=false
```

or 

```dotnetcli
dotnet test -c Release --no-restore --no-build SecretSharingDotNet.slnx -- RunConfiguration.TargetPlatform=x64 RunConfiguration.MaxCpuCount=1  xUnit.AppDomain=denied xUnit.ParallelizeAssembly=false xUnit.ParallelizeTestCollections=false
```
