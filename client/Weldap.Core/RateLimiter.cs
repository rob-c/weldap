namespace Weldap;

/// <summary>
/// SR-8: after <see cref="MaxFailures"/> failed sign-ins for one UUN within <see cref="Window"/>,
/// refuse that UUN locally for <see cref="Lockout"/> without contacting the server.
/// </summary>
public sealed class RateLimiter(IClock clock)
{
    public const int MaxFailures = 5;
    public static readonly TimeSpan Window = TimeSpan.FromMinutes(5);
    public static readonly TimeSpan Lockout = TimeSpan.FromMinutes(5);

    private readonly Dictionary<string, State> _byUun = new(StringComparer.Ordinal);
    private readonly Lock _lock = new();

    private sealed class State
    {
        public readonly Queue<DateTimeOffset> Failures = new();
        // "Not blocked" is a time in the distant past, not a null: a plain non-nullable compare against it
        // (never a nullable one, which the compiler lowers to a hidden HasValue branch) decides IsBlocked.
        public DateTimeOffset BlockedUntil = DateTimeOffset.MinValue;
    }

    public bool IsBlocked(string uun)
    {
        lock (_lock)
        {
            if (!_byUun.TryGetValue(uun, out var s)) return false;
            if (clock.UtcNow < s.BlockedUntil) return true;
            // Not blocked now: drop the entry once it has nothing live left (a lapsed block clears its failures).
            if (s.Failures.Count == 0) _byUun.Remove(uun);
            return false;
        }
    }

    public void RecordFailure(string uun)
    {
        lock (_lock)
        {
            var now = clock.UtcNow;
            if (!_byUun.TryGetValue(uun, out var s)) _byUun[uun] = s = new State();
            while (s.Failures.Count > 0 && now - s.Failures.Peek() > Window) s.Failures.Dequeue();
            s.Failures.Enqueue(now);
            if (s.Failures.Count >= MaxFailures)
            {
                s.BlockedUntil = now + Lockout;
                s.Failures.Clear();
            }
            Prune(now);
        }
    }

    public void RecordSuccess(string uun)
    {
        lock (_lock) _byUun.Remove(uun);
    }

    /// <summary>How many UUNs are tracked (tests check the table stays bounded).</summary>
    internal int Tracked
    {
        get
        {
            lock (_lock) return _byUun.Count;
        }
    }

    // Bound memory: drop idle entries so a stream of random names can't grow the table.
    private void Prune(DateTimeOffset now)
    {
        if (_byUun.Count < 1000) return;
        foreach (var key in _byUun.Where(kv =>
                     now >= kv.Value.BlockedUntil
                     && (kv.Value.Failures.Count == 0 || now - kv.Value.Failures.Last() > Window))
                     .Select(kv => kv.Key).ToList())
            _byUun.Remove(key);
    }
}
