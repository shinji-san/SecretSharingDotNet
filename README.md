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
          <td rowspan=8><a href ="https://github.com/shinji-san/SecretSharingDotNet/actions?query=workflow%3A%22SecretSharingDotNet+%28All+supported+TFM%29%22" target="_blank"><img src="https://github.com/shinji-san/SecretSharingDotNet/workflows/SecretSharingDotNet%20(All%20supported%20TFM)/badge.svg" alt="Build status"/></a></td>
          <td rowspan=9><code>SecretSharingDotNet.sln</code></td>
          <td rowspan=8>SDK</td>
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
          <td>.NET 8</td>
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
          <td rowspan=8><a href="https://github.com/shinji-san/SecretSharingDotNet/actions?query=workflow%3A%22SecretSharingDotNet+NuGet%22" target="_blank"><img src="https://github.com/shinji-san/SecretSharingDotNet/workflows/SecretSharingDotNet%20NuGet/badge.svg?branch=v0.11.0" alt="SecretSharingDotNet NuGet"/></a></td>
          <td rowspan=8><a href="https://badge.fury.io/nu/SecretSharingDotNet" target="_blank"><img src="https://badge.fury.io/nu/SecretSharingDotNet.svg" alt="NuGet Version 0.11.0"/></a></td>
          <td rowspan=8><a href="https://github.com/shinji-san/SecretSharingDotNet/tree/v0.11.0" target="_blank"><img src="https://img.shields.io/badge/SecretSharingDotNet-0.11.0-green.svg?logo=github&logoColor=959da5&color=2ebb4e&labelColor=2b3137" alt="Tag"/></a></td>
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
          <td>.NET 8</td>
      </tr>
  </tbody>
</table>

## Install SecretSharingDotNet package

1. Open a console and switch to the directory, containing your project file.

2. Use the following command to install version 0.11.0 of the SecretSharingDotNet package:

    ```dotnetcli
    dotnet add package SecretSharingDotNet -v 0.11.0 -f <FRAMEWORK>
    ```

3. After the completion of the command, look at the project file to make sure that the package is successfully installed.

   You can open the `.csproj` file to see the added package reference:

    ```xml
    <ItemGroup>
      <PackageReference Include="SecretSharingDotNet" Version="0.11.0" />
    </ItemGroup>
    ```
## Remove SecretSharingDotNet package

1. Open a console and switch to the directory, containing your project file.

2. Use the following command to remove the SecretSharingDotNet package:

    ```dotnetcli
    dotnet remove package SecretSharingDotNet
    ```

3. After the completion of the command, look at the project file to make sure that the package is successfully removed.

   You can open the `.csproj` file to check the deleted package reference.

# Usage
## Basics
Use the function `MakeShares` to generate the shares, based on a random or pre-defined secret.
Afterwards, use the function `Reconstruction` to re-construct the original secret.

The length of the shares is based on the security level. It is possible to pre-define a security level by `ctor` or the `SecurityLevel` property. The pre-defined security level will be overriden, if the secret size is greater than the Mersenne prime, which is calculated by means of the security level. It is not necessary to define a security level for a re-construction.

## Using the SecretSharingDotNet library with DI in a .NET project.
This guide will demonstrate how to use the SecretSharingDotNet library with Dependency Injection (DI) in a .NET project.

Firstly, add the following dependencies:
```csharp
using Microsoft.Extensions.DependencyInjection;
using SecretSharingDotNet.Cryptography;
using SecretSharingDotNet.Math;
using System.Numerics;
```
Next, initialize a `ServiceCollection` instance and add dependencies to the DI container:
```csharp
var serviceCollection = new ServiceCollection();
serviceCollection.AddSingleton<IExtendedGcdAlgorithm<BigInteger>,  ExtendedEuclideanAlgorithm<BigInteger>>();
serviceCollection.AddSingleton<IMakeSharesUseCase<BigInteger>, ShamirsSecretSharing<BigInteger>>();
serviceCollection.AddSingleton<IReconstructionUseCase<BigInteger>, ShamirsSecretSharing<BigInteger>>();
using var serviceProvider = serviceCollection.BuildServiceProvider();
```
In the code above, the `ServiceCollection` registers an implementation for each of the main components of the SecretSharingDotNet library.

Next, create an instance of the `IMakeSharesUseCase<BigInteger>`:
```csharp
var makeSharesUseCase = serviceProvider.GetRequiredService<IMakeSharesUseCase<BigInteger>>();
```
Using this instance, it is possible to create shares from a secret:
```csharp
var shares = makeSharesUseCase.MakeShares(3, 7, "Hello!");
Console.WriteLine(shares);
```
Similarly, an instance of `IReconstructionUseCase<BigInteger>` can be created to rebuild the original secret:
```csharp
var reconstructionUseCase = serviceProvider.GetRequiredService<IReconstructionUseCase<BigInteger>>();
var reconstruction = reconstructionUseCase.Reconstruction(shares.Where(p => p.X.IsEven).ToArray());
Console.WriteLine(reconstruction);
```

The code above reconstructs the original secret from the shares, and then outputs it.

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
## Prerequisites
For the following instructions, please make sure that you are connected to the internet. If necessary, NuGet will try to restore the [xUnit](https://xunit.net/) packages.

If you start the unit tests on Linux, you must install the `mono-complete` package in case of the .NET Frameworks 4.6.2, 4.7, 4.7.1, 4.7.2, 4.8 and 4.8.1.
You can find the Mono installation instructions [here](https://www.mono-project.com/download/stable/#download-lin).

The .NET Frameworks 4.6.2, 4.7, 4.7.1, 4.7.2, 4.8 and 4.8.1 can be found [here](https://dotnet.microsoft.com/download/dotnet-framework).

The .NET SDK 8.0 can be found [here](https://dotnet.microsoft.com/download/dotnet).

## Build and test the solution
You can use the `SecretSharingDotNet.sln` solution file with the `dotnet` command to build the [SecretSharingDotNet](#secretsharingdotnet) library in the `Debug` or `Release` configuration. You can also use the `dotnet` command to start the unit tests.

### 1. Restore NuGet packages

```dotnetcli
dotnet restore SecretSharingDotNet.sln
```

### 2. Build the solution

```dotnetcli
dotnet build -c Debug --no-restore SecretSharingDotNet.sln
```

or

```dotnetcli
dotnet build -c Release --no-restore SecretSharingDotNet.sln
```

### 3. Test the solution

```dotnetcli
dotnet test -c Debug --no-restore --no-build SecretSharingDotNet.sln -- RunConfiguration.TargetPlatform=x64 RunConfiguration.MaxCpuCount=1  xUnit.AppDomain=denied xUnit.ParallelizeAssembly=false xUnit.ParallelizeTestCollections=false
```

or 

```dotnetcli
dotnet test -c Release --no-restore --no-build SecretSharingDotNet.sln -- RunConfiguration.TargetPlatform=x64 RunConfiguration.MaxCpuCount=1  xUnit.AppDomain=denied xUnit.ParallelizeAssembly=false xUnit.ParallelizeTestCollections=false
```
