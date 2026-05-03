namespace SecretSharingDotNet.Cryptography;

using System;

/// <summary>
/// Interface for the Shamir's Secret Sharing algorithm implementation for reconstructing the secret.
/// </summary>
/// <typeparam name="TNumber"></typeparam>
public interface IReconstructionUseCase<TNumber> : IDisposable
{
    /// <summary>
    /// Recovers the secret from the given <paramref name="shares"/> (points with x and y on the polynomial)
    /// </summary>
    /// <param name="shares">For details <see cref="Shares{TNumber}"/></param>
    /// <returns>Re-constructed secret</returns>
    /// <exception cref="ArgumentNullException"><paramref name="shares"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentOutOfRangeException">
    /// <paramref name="shares"/> contains fewer than two entries.
    /// </exception>
    /// <exception cref="ArgumentException">
    /// <paramref name="shares"/> contains entries with duplicate share indices, or has no maximum y-value.
    /// </exception>
    /// <exception cref="ObjectDisposedException">The implementation has been disposed.</exception>
    Secret<TNumber> Reconstruction(Shares<TNumber> shares);
}