using Xunit;

namespace Weldap.Tests;

public class RateLimiterTests
{
    private readonly FakeClock _clock = new();
    private readonly RateLimiter _limiter;

    public RateLimiterTests() => _limiter = new RateLimiter(_clock);

    private void Fail(string uun, int times = 1)
    {
        for (var i = 0; i < times; i++) _limiter.RecordFailure(uun);
    }

    [Fact]
    public void Constants() =>
        Assert.Equal((5, TimeSpan.FromMinutes(5), TimeSpan.FromMinutes(5)), (RateLimiter.MaxFailures, RateLimiter.Window, RateLimiter.Lockout));

    [Theory]
    [InlineData(0, false)]
    [InlineData(1, false)]
    [InlineData(2, false)]
    [InlineData(3, false)]
    [InlineData(4, false)]
    [InlineData(5, true)]
    [InlineData(6, true)]
    [InlineData(10, true)]
    [InlineData(50, true)]
    public void Blocks_from_the_fifth_failure(int failures, bool blocked)
    {
        Fail("alice", failures);
        Assert.Equal(blocked, _limiter.IsBlocked("alice"));
    }

    [Theory]
    [InlineData(0, true)]
    [InlineData(1, true)]
    [InlineData(60, true)]
    [InlineData(75, true)]  // first and fifth exactly one window apart: still inside
    [InlineData(76, false)]
    [InlineData(120, false)]
    [InlineData(3600, false)]
    public void Only_failures_inside_the_window_count(int secondsApart, bool blocked)
    {
        for (var i = 0; i < 5; i++)
        {
            if (i > 0) _clock.UtcNow += TimeSpan.FromSeconds(secondsApart);
            _limiter.RecordFailure("alice");
        }
        Assert.Equal(blocked, _limiter.IsBlocked("alice"));
    }

    [Theory]
    [InlineData(0, true)]
    [InlineData(1, true)]
    [InlineData(299, true)]
    [InlineData(300, false)]
    [InlineData(301, false)]
    [InlineData(86400, false)]
    public void Lockout_lasts_five_minutes(int secondsLater, bool blocked)
    {
        Fail("alice", 5);
        _clock.UtcNow += TimeSpan.FromSeconds(secondsLater);
        Assert.Equal(blocked, _limiter.IsBlocked("alice"));
    }

    [Fact]
    public void Lockout_boundary_to_the_tick()
    {
        Fail("alice", 5);
        _clock.UtcNow += RateLimiter.Lockout - TimeSpan.FromTicks(1);
        Assert.True(_limiter.IsBlocked("alice"));
        _clock.UtcNow += TimeSpan.FromTicks(1);
        Assert.False(_limiter.IsBlocked("alice"));
    }

    [Fact]
    public void After_a_lockout_the_count_starts_again()
    {
        Fail("alice", 5);
        _clock.UtcNow += RateLimiter.Lockout;
        Assert.False(_limiter.IsBlocked("alice"));
        Fail("alice", 4);
        Assert.False(_limiter.IsBlocked("alice"));
        Fail("alice");
        Assert.True(_limiter.IsBlocked("alice"));
    }

    [Fact]
    public void Failures_during_a_lockout_do_not_extend_it_beyond_a_new_count()
    {
        Fail("alice", 5);
        _clock.UtcNow += TimeSpan.FromMinutes(4);
        Fail("alice"); // one failure after the block: count restarted, block unchanged
        _clock.UtcNow += TimeSpan.FromMinutes(1);
        Assert.False(_limiter.IsBlocked("alice"));
    }

    [Fact]
    public void Success_clears_failures()
    {
        Fail("alice", 4);
        _limiter.RecordSuccess("alice");
        Fail("alice", 4);
        Assert.False(_limiter.IsBlocked("alice"));
    }

    [Fact]
    public void Success_clears_a_block()
    {
        Fail("alice", 5);
        _limiter.RecordSuccess("alice");
        Assert.False(_limiter.IsBlocked("alice"));
        Assert.Equal(0, _limiter.Tracked);
    }

    [Fact]
    public void Success_for_an_unknown_name_is_harmless()
    {
        _limiter.RecordSuccess("nobody");
        Assert.Equal(0, _limiter.Tracked);
    }

    [Fact]
    public void Names_are_independent_and_case_sensitive()
    {
        Fail("alice", 5);
        Assert.True(_limiter.IsBlocked("alice"));
        Assert.False(_limiter.IsBlocked("bob"));
        Assert.False(_limiter.IsBlocked("Alice"));
        Fail("bob", 4);
        Assert.False(_limiter.IsBlocked("bob"));
    }

    [Fact]
    public void Checking_does_not_track_a_name()
    {
        Assert.False(_limiter.IsBlocked("alice"));
        Assert.Equal(0, _limiter.Tracked);
    }

    [Fact]
    public void An_expired_block_is_forgotten_when_checked()
    {
        Fail("alice", 5);
        Assert.Equal(1, _limiter.Tracked);
        _clock.UtcNow += RateLimiter.Lockout;
        Assert.False(_limiter.IsBlocked("alice"));
        Assert.Equal(0, _limiter.Tracked);
    }

    [Fact]
    public void Idle_entries_are_pruned_once_the_table_is_large()
    {
        for (var i = 0; i < 1500; i++) _limiter.RecordFailure($"u{i}");
        Assert.InRange(_limiter.Tracked, 1000, 1500);
        _clock.UtcNow += RateLimiter.Window + TimeSpan.FromSeconds(1);
        _limiter.RecordFailure("fresh");
        Assert.Equal(1, _limiter.Tracked);
    }

    [Fact]
    public void Below_1000_entries_nothing_is_pruned()
    {
        for (var i = 0; i < 998; i++) _limiter.RecordFailure($"u{i}");
        _clock.UtcNow += TimeSpan.FromHours(1);
        _limiter.RecordFailure("fresh");
        Assert.Equal(999, _limiter.Tracked);
    }

    [Fact]
    public void Pruning_keeps_recent_failures_and_live_blocks()
    {
        Fail("blocked", 5);
        Fail("recent", 2);
        for (var i = 0; i < 1200; i++) _limiter.RecordFailure($"u{i}");
        _clock.UtcNow += TimeSpan.FromMinutes(4);
        Fail("recent2");
        _clock.UtcNow += TimeSpan.FromMinutes(1) + TimeSpan.FromSeconds(1);
        // Now: the 1200 and "recent" are idle (> window), "blocked" has just expired, "recent2" is 61 s old.
        Fail("trigger");
        Assert.Equal(2, _limiter.Tracked); // recent2 + trigger
        Assert.False(_limiter.IsBlocked("blocked"));
    }

    [Fact]
    public void Pruning_never_drops_a_block_that_is_still_running()
    {
        for (var i = 0; i < 1200; i++) _limiter.RecordFailure($"u{i}");
        _clock.UtcNow += TimeSpan.FromMinutes(2);
        Fail("blocked", 5); // blocked until +7 min
        _clock.UtcNow += TimeSpan.FromMinutes(3) + TimeSpan.FromSeconds(1);
        Fail("trigger"); // the 1200 are idle now; the block is not
        Assert.Equal(2, _limiter.Tracked);
        Assert.True(_limiter.IsBlocked("blocked"));
    }

    [Fact]
    public void Random_names_cannot_grow_the_table_without_bound()
    {
        for (var round = 0; round < 20; round++)
        {
            for (var i = 0; i < 500; i++) _limiter.RecordFailure($"r{round}-{i}");
            _clock.UtcNow += RateLimiter.Window + TimeSpan.FromSeconds(1);
        }
        Assert.InRange(_limiter.Tracked, 0, 1500);
    }

    [Fact]
    public void Concurrent_use_is_safe()
    {
        var clock = new SystemClock();
        var limiter = new RateLimiter(clock);
        Parallel.For(0, 4000, i =>
        {
            limiter.RecordFailure($"u{i % 50}");
            limiter.IsBlocked($"u{(i + 1) % 50}");
            if (i % 7 == 0) limiter.RecordSuccess($"u{(i + 3) % 50}");
        });
        Assert.InRange(limiter.Tracked, 0, 50);
    }
}
