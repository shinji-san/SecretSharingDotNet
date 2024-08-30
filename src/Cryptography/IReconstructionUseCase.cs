namespace SecretSharingDotNet.Cryptography;

/// <summary>
/// Interface for the Shamir's Secret Sharing algorithm implementation for reconstructing the secret.
/// </summary>
/// <typeparam name="TNumber"></typeparam>
public interface IReconstructionUseCase<TNumber>
{
    /// <summary>
    /// Recovers the secret from the given <paramref name="shares"/> (points with x and y on the polynomial)
    /// </summary>
    /// <param name="shares">Shares represented by <see cref="string"/> and separated by newline.</param>
    /// <returns>Re-constructed secret</returns>
    Secret<TNumber> Reconstruction(string shares);

    /// <summary>
    /// Recovers the secret from the given <paramref name="shares"/> (points with x and y on the polynomial)
    /// </summary>
    /// <param name="shares">Shares represented by <see cref="string"/> array.</param>
    /// <returns>Re-constructed secret</returns>
    Secret<TNumber> Reconstruction(string[] shares);

    /// <summary>
    /// Recovers the secret from the given <paramref name="shares"/> (points with x and y on the polynomial)
    /// </summary>
    /// <param name="shares">For details <see cref="Shares{TNumber}"/></param>
    /// <returns>Re-constructed secret</returns>
    Secret<TNumber> Reconstruction(Shares<TNumber> shares);

    /// <summary>
    /// Recovers the secret from the given <paramref name="shares"/> (points with x and y on the polynomial)
    /// </summary>
    /// <param name="shares">Two or more shares represented by a set of <see cref="FinitePoint{TNumber}"/></param>
    /// <returns>Re-constructed secret</returns>
    /// <exception cref="T:System.ArgumentNullException"><paramref name="shares"/> is <see langword="null"/>.</exception>
    /// <exception cref="T:System.ArgumentOutOfRangeException">The length of <paramref name="shares"/> is lower than 2.</exception>
    Secret<TNumber> Reconstruction(FinitePoint<TNumber>[] shares);
}