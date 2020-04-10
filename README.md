# SecretSharingDotNet
An C# implementation of Shamir's Secret Sharing.

# Build and Test Status
[![Build status](https://github.com/shinji-san/SecretSharingDotNet/workflows/SecretSharingDotNet%20.NET%20Core/badge.svg)](https://github.com/shinji-san/SecretSharingDotNet/actions?query=workflow%3A%22SecretSharingDotNet+.NET+Core%22)

[![Build status](https://github.com/shinji-san/SecretSharingDotNet/workflows/SecretSharingDotNet%20.NET%20FX/badge.svg)](https://github.com/shinji-san/SecretSharingDotNet/actions?query=workflow%3A%22SecretSharingDotNet+.NET+FX%22)

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
