using System;
using System.Collections.Concurrent;

namespace ZTalk.Server.Services
{
    /// <summary>
    /// Thread-safe authentication rate limiter and brute-force lockout guard
    /// keyed by both username and client IP address.
    /// </summary>
    public class AuthRateLimiter
    {
        private readonly int _maxFailures;
        private readonly TimeSpan _lockoutDuration;
        private readonly ConcurrentDictionary<string, AttemptState> _states
            = new ConcurrentDictionary<string, AttemptState>(StringComparer.OrdinalIgnoreCase);

        public AuthRateLimiter(int maxFailures = 5, int lockoutMinutes = 5)
        {
            _maxFailures = Math.Max(1, maxFailures);
            _lockoutDuration = TimeSpan.FromMinutes(Math.Max(1, lockoutMinutes));
        }

        public bool IsLockedOut(string username, string remoteIp, out TimeSpan remaining)
        {
            remaining = TimeSpan.Zero;
            DateTime now = DateTime.UtcNow;

            TimeSpan userRem;
            if (!string.IsNullOrWhiteSpace(username) && CheckKeyLocked("user:" + username, now, out userRem))
            {
                remaining = userRem;
                return true;
            }

            TimeSpan ipRem;
            if (!string.IsNullOrWhiteSpace(remoteIp) && CheckKeyLocked("ip:" + remoteIp, now, out ipRem))
            {
                remaining = ipRem;
                return true;
            }

            return false;
        }

        public void RecordFailure(string username, string remoteIp)
        {
            DateTime now = DateTime.UtcNow;
            if (!string.IsNullOrWhiteSpace(username))
                IncrementKey("user:" + username, now);
            if (!string.IsNullOrWhiteSpace(remoteIp))
                IncrementKey("ip:" + remoteIp, now);

            if (_states.Count > 2048)
                PruneExpired(now);
        }

        public void RecordSuccess(string username, string remoteIp)
        {
            AttemptState ignored;
            if (!string.IsNullOrWhiteSpace(username))
                _states.TryRemove("user:" + username, out ignored);
            if (!string.IsNullOrWhiteSpace(remoteIp))
                _states.TryRemove("ip:" + remoteIp, out ignored);
        }

        private bool CheckKeyLocked(string key, DateTime now, out TimeSpan remaining)
        {
            remaining = TimeSpan.Zero;
            AttemptState state;
            if (!_states.TryGetValue(key, out state))
                return false;

            lock (state)
            {
                if (state.LockedUntilUtc.HasValue)
                {
                    if (state.LockedUntilUtc.Value > now)
                    {
                        remaining = state.LockedUntilUtc.Value - now;
                        return true;
                    }

                    // Lockout expired -> reset
                    state.FailureCount = 0;
                    state.LockedUntilUtc = null;
                }
                return false;
            }
        }

        private void IncrementKey(string key, DateTime now)
        {
            var state = _states.GetOrAdd(key, _ => new AttemptState());
            lock (state)
            {
                // Reset counter if window has passed since last failure
                if (state.LastFailureUtc.HasValue && (now - state.LastFailureUtc.Value) > _lockoutDuration)
                {
                    state.FailureCount = 0;
                    state.LockedUntilUtc = null;
                }

                state.FailureCount++;
                state.LastFailureUtc = now;

                if (state.FailureCount >= _maxFailures)
                {
                    state.LockedUntilUtc = now + _lockoutDuration;
                }
            }
        }

        private void PruneExpired(DateTime now)
        {
            foreach (var kvp in _states)
            {
                bool expired;
                lock (kvp.Value)
                {
                    expired = (!kvp.Value.LockedUntilUtc.HasValue || kvp.Value.LockedUntilUtc.Value <= now)
                        && (!kvp.Value.LastFailureUtc.HasValue || (now - kvp.Value.LastFailureUtc.Value) > _lockoutDuration);
                }

                if (expired)
                {
                    AttemptState removed;
                    _states.TryRemove(kvp.Key, out removed);
                }
            }
        }

        private sealed class AttemptState
        {
            public int FailureCount;
            public DateTime? LastFailureUtc;
            public DateTime? LockedUntilUtc;
        }
    }
}
