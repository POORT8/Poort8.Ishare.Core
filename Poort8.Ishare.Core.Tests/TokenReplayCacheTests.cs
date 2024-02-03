using FluentAssertions;

namespace Poort8.Ishare.Core.Tests;

public class TokenReplayCacheTests
{
    private readonly TokenReplayCache _tokenReplayCache;

    public TokenReplayCacheTests()
    {
        _tokenReplayCache = new TokenReplayCache();
    }

    [Fact]
    public void TryAddSameJtiShouldFail()
    {
        var jti = Guid.NewGuid().ToString();

        var firstTime = _tokenReplayCache.TryAdd(jti, DateTime.UtcNow.AddMinutes(1));
        firstTime.Should().BeTrue();
        firstTime = _tokenReplayCache.TryFind(jti);
        firstTime.Should().BeTrue();

        var secondsTime = _tokenReplayCache.TryAdd(jti, DateTime.UtcNow.AddMinutes(1));
        secondsTime.Should().BeFalse();
        secondsTime = _tokenReplayCache.TryFind(jti);
        secondsTime.Should().BeTrue();
    }

    [Fact]
    public void TryAddSameJtiShouldSucceedWhenJtiExpires()
    {
        var jti = Guid.NewGuid().ToString();

        var firstTime = _tokenReplayCache.TryAdd(jti, DateTime.UtcNow.AddMinutes(-1));
        firstTime.Should().BeTrue();
        firstTime = _tokenReplayCache.TryFind(jti);
        firstTime.Should().BeFalse();

        var secondsTime = _tokenReplayCache.TryAdd(jti, DateTime.UtcNow.AddMinutes(1));
        secondsTime.Should().BeTrue();
        secondsTime = _tokenReplayCache.TryFind(jti);
        secondsTime.Should().BeTrue();
    }

    [Fact]
    public void TryAddDifferentJtiShouldSucceed()
    {
        var jti1 = Guid.NewGuid().ToString();
        var jti2 = Guid.NewGuid().ToString();

        var firstTime = _tokenReplayCache.TryAdd(jti1, DateTime.UtcNow.AddMinutes(1));
        firstTime.Should().BeTrue();
        firstTime = _tokenReplayCache.TryFind(jti1);
        firstTime.Should().BeTrue();

        var secondsTime = _tokenReplayCache.TryAdd(jti2, DateTime.UtcNow.AddMinutes(1));
        secondsTime.Should().BeTrue();
        secondsTime = _tokenReplayCache.TryFind(jti2);
        secondsTime.Should().BeTrue();
    }

    [Fact]
    public void TryFindNonExistingJtiShouldReturnFalse()
    {
        var jti = Guid.NewGuid().ToString();

        var result = _tokenReplayCache.TryFind(jti);
        result.Should().BeFalse();
    }
}
