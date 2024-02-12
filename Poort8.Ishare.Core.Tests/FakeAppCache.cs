using LazyCache;
using Microsoft.Extensions.Caching.Memory;

namespace Poort8.Ishare.Core.Tests;

internal class FakeAppCache : IAppCache
{
    public ICacheProvider CacheProvider => throw new NotImplementedException();

    public CacheDefaults DefaultCachePolicy => throw new NotImplementedException();

    public void Add<T>(string key, T item, MemoryCacheEntryOptions policy)
    {
        throw new NotImplementedException();
    }

    public T Get<T>(string key)
    {
        throw new NotImplementedException();
    }

    public Task<T> GetAsync<T>(string key)
    {
        throw new NotImplementedException();
    }

    public T GetOrAdd<T>(string key, Func<ICacheEntry, T> addItemFactory)
    {
        throw new NotImplementedException();
    }

    public T GetOrAdd<T>(string key, Func<ICacheEntry, T> addItemFactory, MemoryCacheEntryOptions policy)
    {
        throw new NotImplementedException();
    }

    public Task<T> GetOrAddAsync<T>(string key, Func<ICacheEntry, Task<T>> addItemFactory)
    {
        throw new NotImplementedException();
    }

    public Task<T> GetOrAddAsync<T>(string key, Func<ICacheEntry, Task<T>> addItemFactory, MemoryCacheEntryOptions policy)
    {
        throw new NotImplementedException();
    }

    public void Remove(string key)
    {
        throw new NotImplementedException();
    }

    public bool TryGetValue<T>(string key, out T value)
    {
        throw new NotImplementedException();
    }
}
