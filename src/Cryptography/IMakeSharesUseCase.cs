namespace SecretSharingDotNet.Cryptography;

/// <summary>
/// Interface for the Shamir's Secret Sharing algorithm implementation for creating shared secrets. 
/// </summary>
/// <typeparam name="TNumber">Numeric data type (An integer type)</typeparam>
public interface IMakeSharesUseCase<TNumber>
{
    /// <summary>
    /// Generates a random shamir pool and returns the share points.
    /// The generated random secret is provided via the <paramref name="generatedSecret"/> out parameter.
    /// </summary>
    /// <param name="numberOfMinimumShares">Minimum number of shared secrets for reconstruction</param>
    /// <param name="numberOfShares">Maximum number of shared secrets</param>
    /// <param name="securityLevel">Security level (in number of bits). The minimum is 13.</param>
    /// <param name="generatedSecret">output parameter returning the generated secret as <see cref="Secret{TNumber}"/></param>
    /// <returns>A <see cref="Shares{TNumber}"/> object</returns>
    /// <exception cref="T:System.ArgumentOutOfRangeException">
    /// The <paramref name="securityLevel"/> parameter is lower than 13 or greater than 43.112.609. OR The <paramref name="numberOfMinimumShares"/> parameter is lower than 2 or greater than <paramref name="numberOfShares"/>.
    /// </exception>
    Shares<TNumber> MakeShares(TNumber numberOfMinimumShares, TNumber numberOfShares, int securityLevel, out Secret<TNumber> generatedSecret);

    /// <summary>
    /// Generates a shamir pool using the provided <paramref name="secret"/> and returns the share points.
    /// </summary>
    /// <param name="numberOfMinimumShares">Minimum number of shared secrets for reconstruction</param>
    /// <param name="numberOfShares">Maximum number of shared secrets</param>
    /// <param name="secret">secret text as <see cref="Secret{TNumber}"/> or see cref="string"/></param>
    /// <param name="securityLevel">Security level (in number of bits). The minimum is 13.</param>
    /// <returns>A <see cref="Shares{TNumber}"/> object</returns>
    /// <exception cref="T:System.ArgumentOutOfRangeException">
    /// The <paramref name="securityLevel"/> is lower than 13 or greater than 43.112.609. OR <paramref name="numberOfMinimumShares"/> is lower than 2 or greater than <paramref name="numberOfShares"/>.
    /// </exception>
    Shares<TNumber> MakeShares(TNumber numberOfMinimumShares, TNumber numberOfShares, Secret<TNumber> secret, int securityLevel);

    /// <summary>
    /// Generates a shamir pool using the provided <paramref name="secret"/> and returns the share points.
    /// </summary>
    /// <param name="numberOfMinimumShares">Minimum number of shared secrets for reconstruction</param>
    /// <param name="numberOfShares">Maximum number of shared secrets</param>
    /// <param name="secret">secret text as <see cref="Secret{TNumber}"/> or see cref="string"/></param>
    /// <returns>A <see cref="Shares{TNumber}"/> object</returns>
    /// <exception cref="T:System.ArgumentOutOfRangeException"><paramref name="numberOfMinimumShares"/> is lower than 2 or greater than <paramref name="numberOfShares"/>.</exception>
    Shares<TNumber> MakeShares(TNumber numberOfMinimumShares, TNumber numberOfShares, Secret<TNumber> secret);
}