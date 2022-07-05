# SecretSharingDotNet
An C# implementation of Shamir's Secret Sharing.

# Build & Test Status Of Default Branch
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
          <td rowspan=9><a href ="https://github.com/shinji-san/SecretSharingDotNet/actions?query=workflow%3A%22SecretSharingDotNet+%28All+supported+TFM%29%22" target="_blank"><img src="https://github.com/shinji-san/SecretSharingDotNet/workflows/SecretSharingDotNet%20(All%20supported%20TFM)/badge.svg" alt="Build status"/></a></td>
          <td rowspan=9><code>SecretSharingDotNet.sln</code></td>
          <td rowspan=9>Core</td>
          <td>Core 3.1 (LTS)</td>
      </tr>
      <tr>
          <td>Standard 2.0</td>
      </tr>
      <tr>
          <td>Standard 2.1</td>
      </tr>
      <tr>
          <td>FX 4.6.2</td>
      </tr>
      <tr>
          <td>FX 4.7</td>
      </tr>
      <tr>
          <td>FX 4.7.1</td>
      </tr>
      <tr>
          <td>FX 4.7.2</td>
      </tr>
      <tr>
          <td>FX 4.8</td>
      </tr>
      <tr>
          <td>.NET 6</td>
      </tr>
      <tr>
          <td rowspan=2><a href="https://github.com/shinji-san/SecretSharingDotNet/actions?query=workflow%3A%22SecretSharingDotNet+.NET+Core%22" target="_blank"><img src="https://github.com/shinji-san/SecretSharingDotNet/workflows/SecretSharingDotNet%20.NET%20Core/badge.svg" alt="Build status"></a></td>
          <td><code>SecretSharingDotNetCore3.1.sln</code></td>
          <td rowspan=2>Core</td>
          <td>Core 3.1 (LTS)</td>
      </tr>
      <tr>
          <td rowspan=1><code>SecretSharingDotNet6.sln</code></td>
          <td>.NET 6</td>
      </tr>
      <tr>
          <td><a href="https://github.com/shinji-san/SecretSharingDotNet/actions?query=workflow%3A%22SecretSharingDotNet+.NET+FX%22" target="_blank"><img src="https://github.com/shinji-san/SecretSharingDotNet/workflows/SecretSharingDotNet%20.NET%20FX/badge.svg" alt="Build status"></a></td>
          <td><code>SecretSharingDotNetFx4.6.2.sln</code></td>
          <td>FX</td>
          <td>FX 4.6.2</td>
      </tr>
  </tbody>
</table>

# NuGet
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
          <td rowspan=9><a href="https://github.com/shinji-san/SecretSharingDotNet/actions?query=workflow%3A%22SecretSharingDotNet+NuGet%22" target="_blank"><img src="https://github.com/shinji-san/SecretSharingDotNet/workflows/SecretSharingDotNet%20NuGet/badge.svg?branch=v0.8.0" alt="SecretSharingDotNet NuGet"/></a></td>
          <td rowspan=9><a href="https://badge.fury.io/nu/SecretSharingDotNet" target="_blank"><img src="https://badge.fury.io/nu/SecretSharingDotNet.svg" alt="NuGet Version 0.8.0"/></a></td>
          <td rowspan=9><a href="https://github.com/shinji-san/SecretSharingDotNet/tree/v0.8.0" target="_blank"><img src="https://img.shields.io/badge/SecretSharingDotNet-0.8.0-green.svg?logo=github&logoColor=959da5&color=2ebb4e&labelColor=2b3137" alt="Tag"/></a></td>
          <td>Core 3.1 (LTS)</td>
      </tr>
      <tr>
          <td>.NET 6</td>
      </tr>
      <tr>
          <td>Standard 2.0</td>
      </tr>
      <tr>
          <td>Standard 2.1</td>
      </tr>
      <tr>
          <td>FX 4.6.2</td>
      </tr>
      <tr>
          <td>FX 4.7</td>
      </tr>
      <tr>
          <td>FX 4.7.1</td>
      </tr>
      <tr>
          <td>FX 4.7.2</td>
      </tr>
      <tr>
          <td>FX 4.8</td>
      </tr>
  </tbody>
</table>

## Install SecretSharingDotNet package

1. Open a console and switch to the directory, containing your project file.

2. Use the following command to install version 0.8.0 of the SecretSharingDotNet package:

    ```dotnetcli
    dotnet add package SecretSharingDotNet -v 0.8.0 -f <FRAMEWORK>
    ```

3. After the completition of the command, look at the project file to make sure that the package is successfuly installed.

   You can open the `.csproj` file to see the added package reference:

    ```xml
    <ItemGroup>
      <PackageReference Include="SecretSharingDotNet" Version="0.8.0" />
    </ItemGroup>
    ```
## Remove SecretSharingDotNet package

1. Open a console and switch to the directory, containing your project file.

2. Use the following command to remove the SecretSharingDotNet package:

    ```dotnetcli
    dotnet remove package SecretSharingDotNet
    ```

3. After the completition of the command, look at the project file to make sure that the package is successfuly removed.

   You can open the `.csproj` file to check the deleted package reference.

# Usage
## Basics
Use the function `MakeShares` to generate the shares, based on a random or pre-defined secret.
Afterwards, use the function `Reconstruction` to re-construct the original secret.

The length of the shares is based on the security level. It's possible to pre-define a security level by `ctor` or the `SecurityLevel` property. The pre-defined security level will be overriden, if the secret size is greater than the Mersenne prime, which is calculated by means of the security level. It is not necessary to define a security level for a re-construction.

## Attention: Breaking change - Normal and legacy mode in v0.7.0

Library version 0.7.0 introduces a normal mode and a legacy mode for secrets. The normal mode is the new and default mode. The legacy mode is for backward compatibility.

*Why was the normal mode introduced?*

The normal mode supports positive secret values and also negative secret values like negative integer numbers or byte arrays with most significant byte greater than 0x7F. The legacy mode generates shares that can't be used to reconstruct negative secret values. So the original secret and the reconstructed secret aren't identical for negative secret values (e.g. `BigInetger secret = -2000`). The legacy mode only returns correct results for positive secret values.

*Mode overview*

* **Normal mode** (`Secret.LegacyMode.Value = false`):
  * Shares generated with v0.7.0 or later *cannot* be used with v0.6.0 or earlier to reconstruct the secret.
  * Shares generated with v0.6.0 or earlier *cannot* be used with v0.7.0 or later to reconstruct the secret.
  * This mode supports security level 13 as minimum.
* **Legacy mode:** (`Secret.LegacyMode.Value = true`):
  * Shares generated with v0.7.0 or later *can* be used with v0.6.0 or earlier to reconstruct the secret.
  * Shares generated with v0.6.0 or earlier *can* be used with v0.7.0 or later to reconstruct the secret.
  * This mode supports security level 5 as minimum.

A mixed mode is not possible. It is recommended to reconstruct the secret with the old procedure and to split again with the new procedure.

The legacy mode is thread-safe, but not task-safe.

For further details see the example below:

```csharp
using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;

using SecretSharingDotNet.Cryptography;
using SecretSharingDotNet.Math;

namespace LegacyModeExample
{
  public class Program
  {
    public static void Main(string[] args)
    {
      //// Legacy mode on / normal mode off
      Secret.LegacyMode.Value = true
      try
      {
        var gcd = new ExtendedEuclideanAlgorithm<BigInteger>();

        var split = new ShamirsSecretSharing<BigInteger>(gcd);

        string password = "Hello World!!";
        
        var shares = split.MakeShares(3, 7, password);

        var combine = new ShamirsSecretSharing<BigInteger>(gcd);
        var subSet = shares.Where(p => p.X.IsEven).ToList();
        var recoveredSecret = combine.Reconstruction(subSet.ToArray());

      }
      finally
      {
        //// Legacy mode off / normal mode on
        Secret.LegacyMode.Value = false
      }
    }
  }
}
```

## Random secret
Create a random secret in conjunction with the generation of shares. The length of the generated shares and of the secret are based on the security level. Here is an example with a pre-defined security level of 127:
```csharp
using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;

using SecretSharingDotNet.Cryptography;
using SecretSharingDotNet.Math;

namespace Example1
{
  public class Program
  {
    public static void Main(string[] args)
    {
      var gcd = new ExtendedEuclideanAlgorithm<BigInteger>();

      //// Create Shamir's Secret Sharing instance with BigInteger
      var split = new ShamirsSecretSharing<BigInteger>(gcd);

      //// Minimum number of shared secrets for reconstruction: 3
      //// Maximum number of shared secrets: 7
      //// Security level: 127 (Mersenne prime exponent)
      var shares = split.MakeShares(3, 7, 127);

      //// The property 'shares.OriginalSecret' represents the random secret
      var secret = shares.OriginalSecret;

      //// Secret as big integer number
      Console.WriteLine((BigInteger)secret);

      //// Secret as base64 string
      Console.WriteLine(secret.ToBase64());

      //// The 'shares' instance contains the shared secrets
      var combine = new ShamirsSecretSharing<BigInteger>(gcd);
      var subSet1 = shares.Where(p => p.X.IsEven).ToList();
      var recoveredSecret1 = combine.Reconstruction(subSet1.ToArray());
      var subSet2 = shares.Where(p => !p.X.IsEven).ToList();
      var recoveredSecret2 = combine.Reconstruction(subSet2.ToArray());

      //// String representation of all shares
      Console.WriteLine(shares);

      //// 1st recovered secret as big integer number
      Console.WriteLine((BigInteger)recoveredSecret1);

      //// 2nd recovered secret as big integer number
      Console.WriteLine((BigInteger)recoveredSecret2);

      //// 1st recovered secret as base64 string
      Console.WriteLine(recoveredSecret1.ToBase64());

      //// 2nd recovered secret as base64 string
      Console.WriteLine(recoveredSecret2.ToBase64());
    }
  }
}
```
## Pre-defined secret: text
Use a text as secret, which can be divided into shares. The length of the generated shares is based on the security level.
Here is an example with auto-detected security level:
```csharp
using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;

using SecretSharingDotNet.Cryptography;
using SecretSharingDotNet.Math;

namespace Example2
{
  public class Program
  {
    public static void Main(string[] args)
    {
      var gcd = new ExtendedEuclideanAlgorithm<BigInteger>();

      //// Create Shamir's Secret Sharing instance with BigInteger
      var split = new ShamirsSecretSharing<BigInteger>(gcd);

      string password = "Hello World!!";
      //// Minimum number of shared secrets for reconstruction: 3
      //// Maximum number of shared secrets: 7
      //// Attention: The password length can change the security level set by the ctor
      //// or SecurityLevel property.
      var shares = split.MakeShares(3, 7, password);

      //// The property 'shares.OriginalSecret' represents the original password
      var secret = shares.OriginalSecret;

      //// The 'shares' instance contains the shared secrets
      var combine = new ShamirsSecretSharing<BigInteger>(gcd);
      var subSet1 = shares.Where(p => p.X.IsEven).ToList();
      var recoveredSecret1 = combine.Reconstruction(subSet1.ToArray());
      var subSet2 = shares.Where(p => !p.X.IsEven).ToList();
      var recoveredSecret2 = combine.Reconstruction(subSet2.ToArray());

      //// String representation of all shares
      Console.WriteLine(shares);

      //// 1st recovered secret as string (not base64!)
      Console.WriteLine(recoveredSecret1);

      //// 2nd recovered secret as string (not base64!)
      Console.WriteLine(recoveredSecret2);
    }
  }
}
```

## Pre-defined secret: number
Use an integer number as secret, which can be divided into shares. The length of the generated shares is based on the security level.
Here is an example with a pre-defined security level of 521:
```csharp
using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;

using SecretSharingDotNet.Cryptography;
using SecretSharingDotNet.Math;

namespace Example3
{
  public class Program
  {
    public static void Main(string[] args)
    {
      var gcd = new ExtendedEuclideanAlgorithm<BigInteger>();

      //// Create Shamir's Secret Sharing instance with BigInteger
      //// and 
      var split = new ShamirsSecretSharing<BigInteger>(gcd);

      BigInteger number = 20000;
      //// Minimum number of shared secrets for reconstruction: 3
      //// Maximum number of shared secrets: 7
      //// Security level: 521 (Mersenne prime exponent)
      //// Attention: The size of the number can change the security level set by the ctor
      //// or SecurityLevel property.
      var shares = split.MakeShares (3, 7, number, 521);

      //// The property 'shares.OriginalSecret' represents the number (original secret)
      var secret = shares.OriginalSecret;

      ////  The 'shares' instance contains the shared secrets
      var combine = new ShamirsSecretSharing<BigInteger>(gcd);
      var subSet1 = shares.Where(p => p.X.IsEven).ToList();
      var recoveredSecret1 = combine.Reconstruction(subSet1.ToArray());
      var subSet2 = shares.Where(p => !p.X.IsEven).ToList();
      var recoveredSecret2 = combine.Reconstruction(subSet2.ToArray());

      //// String representation of all shares
      Console.WriteLine(shares);

      //// 1st recovered secret as big integer number
      Console.WriteLine((BigInteger)recoveredSecret1);

      //// 2nd recovered secret as big integer number
      Console.WriteLine((BigInteger)recoveredSecret2);
    }
  }
}
```
## Pre-defined secret: byte array
Use a byte array as secret, which can be divided into shares. The length of the generated shares is based on the security level.
Here is an example with auto-detected security level:
```csharp
using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;

using SecretSharingDotNet.Cryptography;
using SecretSharingDotNet.Math;

namespace Example4
{
  public class Program
  {
    public static void Main(string[] args)
    {
      var gcd = new ExtendedEuclideanAlgorithm<BigInteger>();

      //// Create Shamir's Secret Sharing instance with BigInteger
      var split = new ShamirsSecretSharing<BigInteger>(gcd);

      byte[] bytes = { 0x1D, 0x2E, 0x3F };
      //// Minimum number of shared secrets for reconstruction: 4
      //// Maximum number of shared secrets: 10
      //// Attention: The password length changes the security level set by the ctor
      var shares = split.MakeShares(4, 10, bytes);

      //// The 'shares' instance contains the shared secrets
      var combine = new ShamirsSecretSharing<BigInteger>(gcd);
      var subSet = shares.Where(p => p.X.IsEven).ToList();
      var recoveredSecret = combine.Reconstruction(subSet.ToArray()).ToByteArray();

      //// String representation of all shares
      Console.WriteLine(shares);

      //// The secret bytes.
      Console.WriteLine($"{recoveredSecret[0]:X2}, {recoveredSecret[1]:X2}, {recoveredSecret[2]:X2}");
    }
  }
}
```

## Shares
The following example shows three ways to use shares to reconstruct a secret:
```csharp
using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;

using SecretSharingDotNet.Cryptography;
using SecretSharingDotNet.Math;

namespace Example5
{
  public class Program
  {
    public static void Main(string[] args)
    {
      var gcd = new ExtendedEuclideanAlgorithm<BigInteger>();

      //// One way to use shares
      string shares1 = "02-665C74ED38FDFF095B2FC9319A272A75" + Environment.NewLine +
                       "05-CDECB88126DBC04D753E0C2D83D7B55D" + Environment.NewLine +
                       "07-54A83E34AB0310A7F5D80F2A68FD4F33";

      //// A 2nd way to use shares
      string[] shares2 = {"02-665C74ED38FDFF095B2FC9319A272A75",
                          "07-54A83E34AB0310A7F5D80F2A68FD4F33",
                          "05-CDECB88126DBC04D753E0C2D83D7B55D"};

      //// Another way to use shares
      var fp1 = new FinitePoint<BigInteger>("05-CDECB88126DBC04D753E0C2D83D7B55D");
      var fp2 = new FinitePoint<BigInteger>("07-54A83E34AB0310A7F5D80F2A68FD4F33");
      var fp3 = new FinitePoint<BigInteger>("02-665C74ED38FDFF095B2FC9319A272A75");

      var combine = new ShamirsSecretSharing<BigInteger>(gcd);
 
      var recoveredSecret1 = combine.Reconstruction(shares1);
      //// Output should be 52199147989510990914370102003412153
      Console.WriteLine((BigInteger)recoveredSecret1);

      var recoveredSecret2 = combine.Reconstruction(shares2);
      //// Output should be 52199147989510990914370102003412153
      Console.WriteLine((BigInteger)recoveredSecret2);

      //// Output should be 52199147989510990914370102003412153
      var recoveredSecret3 = combine.Reconstruction(fp1, fp2, fp3);
      Console.WriteLine((BigInteger)recoveredSecret3);
    }
  }
}
```

# CLI building instructions
For the following instructions, please make sure that you are connected to the internet. If necessary, NuGet will try to restore the [xUnit](https://xunit.net/) packages.
## Using dotnet to build for .NET6, .NET Core and .NET FX 4.x
Use one of the following solutions with `dotnet` to build [SecretSharingDotNet](#secretsharingdotnet):
* `SecretSharingDotNet.sln` (all, [see table](#build--test-status-of-default-branch))
* `SecretSharingDotNet6.sln` (.NET 6 only)
* `SecretSharingDotNetCore3.1.sln` (.NET Core 3.1 only)

The syntax is:
```dotnetcli
dotnet {build|test} -c {Debug|Release} SecretSharingDotNet{6|Core3.1}.sln
```

The instructions below are examples, which operate on the `SecretSharingDotNet6.sln`.
### Build Debug configuration

```dotnetcli
dotnet build -c Debug SecretSharingDotNet6.sln
```

### Build Release configuration

```dotnetcli
dotnet build -c Release SecretSharingDotNet6.sln
```

### Test Debug configuration

```dotnetcli
dotnet test -c Debug SecretSharingDotNet6.sln
```

### Test Release configuration

```dotnetcli
dotnet test -c Release SecretSharingDotNet6.sln
```

## Using MSBuild to build for .NET FX 4.6.2
Use one of the following solutions with `msbuild` to build [SecretSharingDotNet](#secretsharingdotnet):
* `SecretSharingDotNetFx4.6.2.sln`

Currently unit testing with MSBuild isn't possible.

The syntax is:
```dotnetcli
msbuild /p:RestorePackagesConfig=true;Configuration={Debug|Release} /t:restore;build SecretSharingDotNetFx4.6.2.sln
```

### Build Debug configuration

```dotnetcli
msbuild /p:RestorePackagesConfig=true;Configuration=Debug /t:restore;build SecretSharingDotNetFx4.6.2.sln
```

### Build Release configuration

```dotnetcli
msbuild /p:RestorePackagesConfig=true;Configuration=Release /t:restore;build SecretSharingDotNetFx4.6.2.sln
```
