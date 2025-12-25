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
    /// <param name="shares">For details <see cref="Shares{TNumber}"/></param>
    /// <returns>Re-constructed secret</returns>
    Secret<TNumber> Reconstruction(Shares<TNumber> shares);
}