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
          <td rowspan=13><a href ="https://github.com/shinji-san/SecretSharingDotNet/actions?query=workflow%3A%22SecretSharingDotNet+%28All+supported+TFM%29%22" target="_blank"><img src="https://github.com/shinji-san/SecretSharingDotNet/workflows/SecretSharingDotNet%20(All%20supported%20TFM)/badge.svg" alt="Build status"/></a></td>
          <td rowspan=13><code>SecretSharingDotNet.sln</code></td>
          <td rowspan=13>Core</td>
          <td>Core 3.1 (LTS)</td>
      </tr>
      <tr>
          <td>Standard 2.0</td>
      </tr>
      <tr>
          <td>Standard 2.1</td>
      </tr>
      <tr>
          <td>FX 4.5.2</td>
      </tr>
      <tr>
          <td>FX 4.6</td>
      </tr>
      <tr>
          <td>FX 4.6.1</td>
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
          <td>.NET 5</td>
      </tr>
      <tr>
          <td>.NET 6</td>
      </tr>
      <tr>
          <td rowspan=3><a href="https://github.com/shinji-san/SecretSharingDotNet/actions?query=workflow%3A%22SecretSharingDotNet+.NET+Core%22" target="_blank"><img src="https://github.com/shinji-san/SecretSharingDotNet/workflows/SecretSharingDotNet%20.NET%20Core/badge.svg" alt="Build status"></a></td>
          <td><code>SecretSharingDotNetCore3.1.sln</code></td>
          <td rowspan=3>Core</td>
          <td>Core 3.1 (LTS)</td>
      </tr>
      <tr>
          <td rowspan=1><code>SecretSharingDotNet5.sln</code></td>
          <td>.NET 5</td>
      </tr>
      <tr>
          <td rowspan=1><code>SecretSharingDotNet6.sln</code></td>
          <td>.NET 6</td>
      </tr>
      <tr>
          <td><a href="https://github.com/shinji-san/SecretSharingDotNet/actions?query=workflow%3A%22SecretSharingDotNet+.NET+FX%22" target="_blank"><img src="https://github.com/shinji-san/SecretSharingDotNet/workflows/SecretSharingDotNet%20.NET%20FX/badge.svg" alt="Build status"></a></td>
          <td><code>SecretSharingDotNetFx4.5.2.sln</code></td>
          <td>FX</td>
          <td>FX 4.5.2</td>
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
          <td rowspan=13><a href="https://github.com/shinji-san/SecretSharingDotNet/actions?query=workflow%3A%22SecretSharingDotNet+NuGet%22" target="_blank"><img src="https://github.com/shinji-san/SecretSharingDotNet/workflows/SecretSharingDotNet%20NuGet/badge.svg?branch=v0.5.0" alt="SecretSharingDotNet NuGet"/></a></td>
          <td rowspan=13><a href="https://badge.fury.io/nu/SecretSharingDotNet" target="_blank"><img src="https://badge.fury.io/nu/SecretSharingDotNet.svg" alt="NuGet Version 0.5.0"/></a></td>
          <td rowspan=13><a href="https://github.com/shinji-san/SecretSharingDotNet/tree/v0.5.0" target="_blank"><img src="https://img.shields.io/badge/SecretSharingDotNet-0.5.0-green.svg?logo=github&logoColor=959da5&color=2ebb4e&labelColor=2b3137" alt="Tag"/></a></td>
          <td>Core 3.1 (LTS)</td>
      </tr>
      <tr>
          <td>.NET 5</td>
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
          <td>FX 4.5.2</td>
      </tr>
      <tr>
          <td>FX 4.6</td>
      </tr>
      <tr>
          <td>FX 4.6.1</td>
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

2. Use the following command to install version 0.5.0 of the SecretSharingDotNet package:

    ```dotnetcli
    dotnet add package SecretSharingDotNet -v 0.5.0 -f <FRAMEWORK>
    ```

3. After the completition of the command, look at the project file to make sure that the package is successfuly installed.

   You can open the `.csproj` file to see the added package reference:

    ```xml
    <ItemGroup>
      <PackageReference Include="SecretSharingDotNet" Version="0.5.0" />
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
      //// and security level 127 (Mersenne prime exponent)
      var split = new ShamirsSecretSharing<BigInteger>(gcd, 127);

      //// Minimum number of shared secrets for reconstruction: 3
      //// Maximum number of shared secrets: 7
      var shares = split.MakeShares(3, 7);

      //// The property 'shares.OriginalSecret' represents the random secret
      var secret = shares.OriginalSecret;

      //// The 'shares' instance contains the shared secrets
      var combine = new ShamirsSecretSharing<BigInteger>(gcd);
      var subSet1 = shares.Where(p => p.X.IsEven).ToList();
      var recoveredSecret1 = combine.Reconstruction(subSet1.ToArray());
      var subSet2 = shares.Where(p => !p.X.IsEven).ToList();
      var recoveredSecret2 = combine.Reconstruction(subSet2.ToArray());
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
      //// Attention: The password length changes the security level set by the ctor
      var shares = split.MakeShares(3, 7, password);

      //// The property 'shares.OriginalSecret' represents the original password
      var secret = shares.OriginalSecret;

      //// The 'shares' instance contains the shared secrets
      var combine = new ShamirsSecretSharing<BigInteger>(gcd);
      var subSet1 = shares.Where(p => p.X.IsEven).ToList();
      var recoveredSecret1 = combine.Reconstruction(subSet1.ToArray());
      var subSet2 = shares.Where(p => !p.X.IsEven).ToList();
      var recoveredSecret2 = combine.Reconstruction(subSet2.ToArray());
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
      //// and security level 521 (Mersenne prime exponent)
      var split = new ShamirsSecretSharing<BigInteger>(gcd, 521);

      BigInteger number = 20000;
      //// Minimum number of shared secrets for reconstruction: 3
      //// Maximum number of shared secrets: 7
      //// Attention: The number size changes the security level set by the ctor
      var shares = split.MakeShares (3, 7, number);

      //// The property 'shares.OriginalSecret' represents the number (original secret)
      var secret = shares.OriginalSecret;

      ////  The 'shares' instance contains the shared secrets
      var combine = new ShamirsSecretSharing<BigInteger>(gcd);
      var subSet1 = shares.Where(p => p.X.IsEven).ToList();
      var recoveredSecret1 = combine.Reconstruction(subSet1.ToArray());
      var subSet2 = shares.Where(p => !p.X.IsEven).ToList();
      var recoveredSecret2 = combine.Reconstruction(subSet2.ToArray());
    }
  }
}
```
# CLI building instructions
For the following instructions, please make sure that you are connected to the internet. If necessary, NuGet will try to restore the [xUnit](https://xunit.net/) packages.
## Using dotnet to build for .NET6, .NET 5, .NET Core and .NET FX 4.x
Use one of the following solutions with `dotnet` to build [SecretSharingDotNet](#secretsharingdotnet):
* `SecretSharingDotNet.sln` (all, [see table](#build--test-status-of-default-branch))
* `SecretSharingDotNet5.sln` (.NET 5 only)
* `SecretSharingDotNet6.sln` (.NET 6 only)
* `SecretSharingDotNetCore3.1.sln` (.NET Core 3.1 only)

The syntax is:
```dotnetcli
dotnet {build|test} -c {Debug|Release} SecretSharingDotNet{6|5|Core3.1}.sln
```

The instructions below are examples, which operate on the `SecretSharingDotNet5.sln`.
### Build Debug configuration

```dotnetcli
dotnet build -c Debug SecretSharingDotNet5.sln
```

### Build Release configuration

```dotnetcli
dotnet build -c Release SecretSharingDotNet5.sln
```

### Test Debug configuration

```dotnetcli
dotnet test -c Debug SecretSharingDotNet5.sln
```

### Test Release configuration

```dotnetcli
dotnet test -c Release SecretSharingDotNet5.sln
```

## Using MSBuild to build for .NET FX 4.5.2
Use one of the following solutions with `msbuild` to build [SecretSharingDotNet](#secretsharingdotnet):
* `SecretSharingDotNetFx4.5.2.sln`

Currently unit testing with MSBuild isn't possible.

The syntax is:
```dotnetcli
msbuild /p:RestorePackagesConfig=true;Configuration={Debug|Release} /t:restore;build SecretSharingDotNetFx4.5.2.sln
```

### Build Debug configuration

```dotnetcli
msbuild /p:RestorePackagesConfig=true;Configuration=Debug /t:restore;build SecretSharingDotNetFx4.5.2.sln
```

### Build Release configuration

```dotnetcli
msbuild /p:RestorePackagesConfig=true;Configuration=Release /t:restore;build SecretSharingDotNetFx4.5.2.sln
```
