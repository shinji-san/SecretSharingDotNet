namespace SecretSharingDotNet.Cryptography;

/// <summary>
/// Abstract class for Shamir's secret sharing algorithm implementation
/// </summary>
public abstract class ShamirsSecretSharing
{
    /// <summary>
    /// The minimum number of shares required to reconstruct the secret
    /// </summary>
    protected const int MinimumShareLimit = 2;

    /// <summary>
    /// Saves the known security levels (Mersenne prime exponents)
    /// </summary>
    protected static readonly int[] SecurityLevels =
    [
        13, 17, 19, 31, 61, 89, 107, 127, 521, 607, 1279, 2203, 2281, 3217, 4253, 4423, 9689, 9941, 11213,
        19937, 21701, 23209, 44497, 86243, 110503, 132049, 216091, 756839, 859433, 1257787, 1398269, 2976221,
        3021377, 6972593, 13466917, 20996011, 24036583, 25964951, 30402457, 32582657, 37156667, 42643801, 43112609
    ];
}