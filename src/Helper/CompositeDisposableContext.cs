#if NET6_0_OR_GREATER

namespace SecretSharingDotNet.Helper;

using System.Threading;

/// <summary>
/// Provides a context for managing a <see cref="CompositeDisposable"/> instance per thread.
/// </summary>
public static class CompositeDisposableContext
{
    /// <summary>
    /// Provides a thread-local instance of <see cref="CompositeDisposable"/> that represents
    /// the current context for managing disposable resources within the thread.
    /// </summary>
    public static ThreadLocal<CompositeDisposable> Current { get; } = new ThreadLocal<CompositeDisposable>();

    /// <summary>
    /// Sets the current thread's <see cref="CompositeDisposable"/> instance.
    /// </summary>
    /// <param name="compositeDisposable">The <see cref="CompositeDisposable"/> instance to set for the current thread.</param>
    public static void SetCurrent(CompositeDisposable compositeDisposable)
    {
        Current.Value = compositeDisposable;
    }
}

#endif