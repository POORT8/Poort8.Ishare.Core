using Microsoft.IdentityModel.Tokens;
using System.Collections.Concurrent;

namespace Poort8.Ishare.Core;

public class TokenReplayCache : ITokenReplayCache
{
    private readonly ConcurrentDictionary<string, DateTimeOffset> _cache;

    public TokenReplayCache()
    {
        _cache = new ConcurrentDictionary<string, DateTimeOffset>();
    }

    public bool TryAdd(string key, DateTime expiresOn)
    {
        return _cache.TryAdd(key, expiresOn);
    }

    public bool TryFind(string key)
    {
        CleanUpExpiredTokens();

        if (_cache.TryGetValue(key, out var expiresOn))
        {
            if (DateTimeOffset.UtcNow <= expiresOn) return true;

            _cache.TryRemove(key, out _);
        }

        return false;
    }

    private void CleanUpExpiredTokens()
    {
        foreach (var key in _cache)
        {
            if (DateTimeOffset.UtcNow > key.Value)
            {
                _cache.TryRemove(key.Key, out _);
            }
        }
    }
}
