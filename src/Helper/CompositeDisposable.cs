#if NET6_0_OR_GREATER
namespace SecretSharingDotNet.Helper;

using System;
using System.Collections.Concurrent;

/// <summary>
/// Manages a composite collection of <see cref="IDisposable"/> objects,
/// ensuring all contained disposables are disposed together.
/// </summary>
public sealed class CompositeDisposable : IDisposable
{
    private readonly ConcurrentBag<IDisposable> disposables = new();
    private bool disposed;

    /// <summary>
    /// Finalizes an instance of the <see cref="CompositeDisposable"/> class.
    /// </summary>
    ~CompositeDisposable()
    {
        this.Dispose(false);
    }

    /// <summary>
    /// Adds a disposable object to the composite collection of disposables.
    /// </summary>
    /// <param name="disposable">The disposable object to add.</param>
    /// <exception cref="ObjectDisposedException">Thrown when the composite disposable has already been disposed.</exception>
    public void Add(IDisposable disposable)
    {
        ArgumentNullException.ThrowIfNull(disposable);
        if (this.disposed)
        {
            throw new ObjectDisposedException(nameof(CompositeDisposable));
        }

        this.disposables.Add(disposable);
    }

    /// <summary>
    /// Clears and disposes all disposable objects contained within the composite collection.
    /// </summary>
    public void Clear()
    {
        foreach (var disposable in this.disposables)
        {
            disposable.Dispose();
        }
        
        this.disposables.Clear();
    }

    /// <summary>
    /// Disposes the composite collection of disposables, releasing all managed resources.
    /// </summary>
    public void Dispose()
    {
        this.Dispose(true);
        GC.SuppressFinalize(this);
    }

    /// <summary>
    /// Disposes the composite collection of disposables, releasing all managed resources.
    /// </summary>
    /// <param name="disposing">Indicates whether the method call comes from a Dispose method (true) or from a finalizer (false).</param>
    private void Dispose(bool disposing)
    {
        if (this.disposed)
        {
            return;
        }
        
        if (disposing)
        {
            foreach (var disposable in this.disposables)
            {
                disposable.Dispose();
            }
        }
        
        this.disposables.Clear();
        this.disposed = true;
    }
}
#endif
