# SecretSharingDotNet
An C# implementation of Shamir's Secret Sharing.

# Build and Test Status
[![Build status](https://github.com/shinji-san/SecretSharingDotNet/workflows/SecretSharingDotNet%20.NET%20Core/badge.svg)](https://github.com/shinji-san/SecretSharingDotNet/actions?query=workflow%3A%22SecretSharingDotNet+.NET+Core%22)

[![Build status](https://github.com/shinji-san/SecretSharingDotNet/workflows/SecretSharingDotNet%20.NET%20FX/badge.svg)](https://github.com/shinji-san/SecretSharingDotNet/actions?query=workflow%3A%22SecretSharingDotNet+.NET+FX%22)

# Usage
## Basics
Use the function `MakeShares` to generate the secret shares based on a random or pre-defined secret.
Afterwards use the function `Reconstruction` to re-constructing the original secret

## Random Secret
Here is an example:
```csharp
//// Create Shamir's Secret Sharing instance with BigInteger and
//// security level 127 (Mersenne prime exponent)
var sss = new ShamirsSecretSharing<BigInteger> (new ExtendedEuclideanAlgorithm<BigInteger> (), 127);

//// Minimum number of shared secrets for reconstruction: 3
//// Maximum number of shared secrets: 7
var x = sss.MakeShares (3, 7);

//// Item1 represents the random secret
var secret = x.Item1;

//// Item 2 contains the shared secrets
var subSet1 = x.Item2.Where (p => p.X.IsEven).ToList ();
var recoveredSecret1 = sss.Reconstruction(subSet1.ToArray());
var subSet2 = x.Item2.Where (p => !p.X.IsEven).ToList ();
var recoveredSecret2 = sss.Reconstruction(subSet2.ToArray());
```
## Pre-defined Secret: Text
Here is an example:
```csharp
//// Create Shamir's Secret Sharing instance with BigInteger and
//// security level 127 (Mersenne prime exponent)
var sss = new ShamirsSecretSharing<BigInteger> (new ExtendedEuclideanAlgorithm<BigInteger> (), 127);

string password = "Hello World!!";
//// Minimum number of shared secrets for reconstruction: 3
//// Maximum number of shared secrets: 7
//// Attention: The password length changes the security level set by the ctor
var x = sss.MakeShares (3, 7, password);

//// Item1 represents the password (original secret)
var secret = x.Item1;

//// Item 2 contains the shared secrets
var subSet1 = x.Item2.Where (p => p.X.IsEven).ToList ();
var recoveredSecret1 = sss.Reconstruction(subSet1.ToArray());
var subSet2 = x.Item2.Where (p => !p.X.IsEven).ToList ();
var recoveredSecret2 = sss.Reconstruction(subSet2.ToArray());
```

## Pre-defined Secret: Number
Here is an example:
```csharp
//// Create Shamir's Secret Sharing instance with BigInteger and
//// security level 127 (Mersenne prime exponent)
var sss = new ShamirsSecretSharing<BigInteger> (new ExtendedEuclideanAlgorithm<BigInteger> (), 127);

BigInteger number = 20000;
//// Minimum number of shared secrets for reconstruction: 3
//// Maximum number of shared secrets: 7
var x = sss.MakeShares (3, 7, number);

//// Item1 represents the number (original secret)
var secret = x.Item1;

//// Item 2 contains the shared secrets
var subSet1 = x.Item2.Where (p => p.X.IsEven).ToList ();
var recoveredSecret1 = sss.Reconstruction(subSet1.ToArray());
var subSet2 = x.Item2.Where (p => !p.X.IsEven).ToList ();
var recoveredSecret2 = sss.Reconstruction(subSet2.ToArray());
```
