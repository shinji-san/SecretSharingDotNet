#if NET6_0_OR_GREATER

namespace SecretSharingDotNet.Helper;

using System;
using System.Collections.Concurrent;

public sealed class Scope : IDisposable
{
    private readonly ConcurrentDictionary<Type, object> services = new();
    private bool disposed;

    ~Scope()
    {
        this.Dispose(false);
    }

    public T GetScopedSingleton<T>() where T : class, new()
    {
        var type = typeof(T);
        if (this.services.TryGetValue(type, out object service))
        {
            return service as T;
        }

        var newService = new T();
        this.services.TryAdd(type, newService);
        return newService;
    }

    public void Dispose()
    {
        this.Dispose(true);
        GC.SuppressFinalize(this);
    }

    private void Dispose(bool disposing)
    {
        if (this.disposed)
        {
            return;
        }

        if (disposing)
        {
            foreach (IDisposable service in this.services.Values)
            {
                service?.Dispose();
            }
        }

        this.disposed = true;
    }
}
#endif
