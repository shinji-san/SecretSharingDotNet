# SecretSharingDotNet
An C# implementation of Shamir's Secret Sharing.

# Build & Test Status Of Default Branch
| Status               | .NET Version  | Solution    |
| -------------------- | ------------- | ----------- |
| [![Build status](https://github.com/shinji-san/SecretSharingDotNet/workflows/SecretSharingDotNet%20.NET%20Core/badge.svg)](https://github.com/shinji-san/SecretSharingDotNet/actions?query=workflow%3A%22SecretSharingDotNet+.NET+Core%22)| 2.1 (LTS) | `SecretSharingDotNetCore2.1.sln` |
| [![Build status](https://github.com/shinji-san/SecretSharingDotNet/workflows/SecretSharingDotNet%20.NET%20Core/badge.svg)](https://github.com/shinji-san/SecretSharingDotNet/actions?query=workflow%3A%22SecretSharingDotNet+.NET+Core%22)| 3.1 (LTS) | `SecretSharingDotNetCore3.1.sln` |
| [![Build status](https://github.com/shinji-san/SecretSharingDotNet/workflows/SecretSharingDotNet%20.NET%20FX/badge.svg)](https://github.com/shinji-san/SecretSharingDotNet/actions?query=workflow%3A%22SecretSharingDotNet+.NET+FX%22)  | 4.5.2 | `SecretSharingDotNetFx4.5.2.sln` |

# NuGet
## Supported Target Frameworks
| Build And Test Status        | NuGet Version   | Git Tag   | Target Frameworks  |
| ---------------------------- | --------------- | --------- | ------------------ |
| [![SecretSharingDotNet NuGet](https://github.com/shinji-san/SecretSharingDotNet/workflows/SecretSharingDotNet%20NuGet/badge.svg?branch=master)](https://github.com/shinji-san/SecretSharingDotNet/actions?query=workflow%3A%22SecretSharingDotNet+NuGet%22)| [![NuGet version](https://badge.fury.io/nu/SecretSharingDotNet.svg)](https://badge.fury.io/nu/SecretSharingDotNet) | [![Tag](https://img.shields.io/badge/SecretSharingDotNet-0.2.0-green.svg?logo=github&logoColor=959da5&color=2ebb4e&labelColor=2b3137)](https://github.com/shinji-san/SecretSharingDotNet/tree/v0.2.0) | .NET Core 2.1      |
| [![SecretSharingDotNet NuGet](https://github.com/shinji-san/SecretSharingDotNet/workflows/SecretSharingDotNet%20NuGet/badge.svg?branch=master)](https://github.com/shinji-san/SecretSharingDotNet/actions?query=workflow%3A%22SecretSharingDotNet+NuGet%22)| [![NuGet version](https://badge.fury.io/nu/SecretSharingDotNet.svg)](https://badge.fury.io/nu/SecretSharingDotNet) | [![Tag](https://img.shields.io/badge/SecretSharingDotNet-0.2.0-green.svg?logo=github&logoColor=959da5&color=2ebb4e&labelColor=2b3137)](https://github.com/shinji-san/SecretSharingDotNet/tree/v0.2.0) | .NET Core 3.1      |
| [![SecretSharingDotNet NuGet](https://github.com/shinji-san/SecretSharingDotNet/workflows/SecretSharingDotNet%20NuGet/badge.svg?branch=master)](https://github.com/shinji-san/SecretSharingDotNet/actions?query=workflow%3A%22SecretSharingDotNet+NuGet%22)| [![NuGet version](https://badge.fury.io/nu/SecretSharingDotNet.svg)](https://badge.fury.io/nu/SecretSharingDotNet) | [![Tag](https://img.shields.io/badge/SecretSharingDotNet-0.2.0-green.svg?logo=github&logoColor=959da5&color=2ebb4e&labelColor=2b3137)](https://github.com/shinji-san/SecretSharingDotNet/tree/v0.2.0) | .NET Standard 2.0   |
| [![SecretSharingDotNet NuGet](https://github.com/shinji-san/SecretSharingDotNet/workflows/SecretSharingDotNet%20NuGet/badge.svg?branch=master)](https://github.com/shinji-san/SecretSharingDotNet/actions?query=workflow%3A%22SecretSharingDotNet+NuGet%22)| [![NuGet version](https://badge.fury.io/nu/SecretSharingDotNet.svg)](https://badge.fury.io/nu/SecretSharingDotNet) | [![Tag](https://img.shields.io/badge/SecretSharingDotNet-0.2.0-green.svg?logo=github&logoColor=959da5&color=2ebb4e&labelColor=2b3137)](https://github.com/shinji-san/SecretSharingDotNet/tree/v0.2.0) | .NET Framework 4.5.2 |
## Install SecretSharingDotNet package

1. Open a console and switch to the directory containing your project file.

2. Use the following command to install version 0.2.0 of the SecretSharingDotNet package:

    ```dotnetcli
    dotnet add package SecretSharingDotNet -v 0.2.0 -f <FRAMEWORK>
    ```

3. After the command completes, look at the project file to make sure the package was installed.

   You can open the `.csproj` file to see the added package reference:

    ```xml
    <ItemGroup>
      <PackageReference Include="SecretSharingDotNet" Version="0.2.0" />
    </ItemGroup>
    ```
## Remove SecretSharingDotNet package

1. Open a console and switch to the directory containing your project file.

2. Use the following command to remove the SecretSharingDotNet package:

    ```dotnetcli
    dotnet remove package SecretSharingDotNet
    ```

3. After the command completes, look at the project file to make sure the package was removed.

   You can open the `.csproj` file to check the deleted package reference.

# Usage
## Basics
Use the function `MakeShares` to generate the shares based on a random or pre-defined secret.
Afterwards use the function `Reconstruction` to re-constructing the original secret.

The length of shares based on the security level. It's possible to pre-define a security level by `ctor` or the `SecurityLevel` property. The pre-defined security level will be overriden if secret size is greater than the Mersenne prime which is calculated by means of security level. It is not necessary to define a security level for re-construction.

## Random Secret
Create a random secret in conjunction with the generation of shares. The length of the generated shares and the secret based on the security level. Here is an example with a pre-defined security level of 127:
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
      var x = split.MakeShares (3, 7);

      //// Item1 represents the random secret
      var secret = x.Item1;

      //// Item 2 contains the shared secrets
      var combine = new ShamirsSecretSharing<BigInteger>(gcd);
      var subSet1 = x.Item2.Where (p => p.X.IsEven).ToList ();
      var recoveredSecret1 = combine.Reconstruction(subSet1.ToArray());
      var subSet2 = x.Item2.Where (p => !p.X.IsEven).ToList ();
      var recoveredSecret2 = combine.Reconstruction(subSet2.ToArray());
    }
  }
}
```
## Pre-defined Secret: Text
Use a text as secret which can be divided into shares. The length of the generated shares based on the security level.
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
      var x = split.MakeShares (3, 7, password);

      //// Item1 represents the password (original secret)
      var secret = x.Item1;

      //// Item 2 contains the shared secrets
      var combine = new ShamirsSecretSharing<BigInteger>(gcd);
      var subSet1 = x.Item2.Where (p => p.X.IsEven).ToList ();
      var recoveredSecret1 = combine.Reconstruction(subSet1.ToArray());
      var subSet2 = x.Item2.Where (p => !p.X.IsEven).ToList ();
      var recoveredSecret2 = combine.Reconstruction(subSet2.ToArray());
    }
  }
}
```

## Pre-defined Secret: Number
Use an integer number as secret which can be divided into shares. The length of the generated shares based on the security level.
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
      var x = split.MakeShares (3, 7, number);

      //// Item1 represents the number (original secret)
      var secret = x.Item1;

      //// Item 2 contains the shared secrets
      var combine = new ShamirsSecretSharing<BigInteger>(gcd);
      var subSet1 = x.Item2.Where (p => p.X.IsEven).ToList ();
      var recoveredSecret1 = combine.Reconstruction(subSet1.ToArray());
      var subSet2 = x.Item2.Where (p => !p.X.IsEven).ToList ();
      var recoveredSecret2 = combine.Reconstruction(subSet2.ToArray());
    }
  }
}
```
