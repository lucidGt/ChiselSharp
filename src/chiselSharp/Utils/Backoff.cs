using System;

namespace ChiselSharp.Utils
{
    /// <summary>
    /// Exponential backoff with jitter for reconnect logic.
    /// Matches chisel's jpillora/backoff behavior.
    /// </summary>
    public class Backoff
    {
        private readonly Random _random = new Random();
        private int _attempt;
        private readonly TimeSpan _minDelay;
        private readonly TimeSpan _maxDelay;
        private readonly int _maxAttempts; // -1 = infinite

        public Backoff(TimeSpan minDelay, TimeSpan maxDelay, int maxAttempts = -1)
        {
            _minDelay = minDelay;
            _maxDelay = maxDelay;
            _maxAttempts = maxAttempts;
            _attempt = 0;
        }

        /// <summary>
        /// Returns the next backoff delay, or null if max attempts reached.
        /// </summary>
        public TimeSpan? NextDelay()
        {
            if (_maxAttempts >= 0 && _attempt >= _maxAttempts)
                return null;

            _attempt++;

            // Exponential: minDelay * 2^(attempt-1)
            double exponential = _minDelay.TotalMilliseconds * Math.Pow(2, _attempt - 1);
            double capped = Math.Min(exponential, _maxDelay.TotalMilliseconds);

            // Add jitter: 50% to 100% of the capped value
            double jitter = capped * (0.5 + _random.NextDouble() * 0.5);

            return TimeSpan.FromMilliseconds(jitter);
        }

        /// <summary>
        /// Force an immediate retry by short-circuiting the current delay.
        /// </summary>
        public void ShortCircuit()
        {
            _attempt = 0;
        }

        /// <summary>
        /// Reset the attempt counter.
        /// </summary>
        public void Reset()
        {
            _attempt = 0;
        }

        public int AttemptCount
        {
            get { return _attempt; }
        }
    }
}
