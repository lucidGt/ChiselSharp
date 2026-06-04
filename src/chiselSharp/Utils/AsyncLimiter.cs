using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace ChiselSharp.Utils
{
    internal sealed class AsyncLimiter
    {
        private readonly object _syncRoot = new object();
        private readonly Queue<TaskCompletionSource<IDisposable>> _waiters =
            new Queue<TaskCompletionSource<IDisposable>>();
        private int _available;

        public AsyncLimiter(int limit)
        {
            if (limit <= 0)
                throw new ArgumentOutOfRangeException("limit");
            _available = limit;
        }

        public Task<IDisposable> EnterAsync()
        {
            IDisposable lease;
            if (TryEnter(out lease))
                return Compat.FromResult(lease);

            lock (_syncRoot)
            {
                if (_available > 0)
                {
                    _available--;
                    return Compat.FromResult<IDisposable>(new Releaser(this));
                }

                var waiter = new TaskCompletionSource<IDisposable>();
                _waiters.Enqueue(waiter);
                return waiter.Task;
            }
        }

        public bool TryEnter(out IDisposable lease)
        {
            lock (_syncRoot)
            {
                if (_available <= 0)
                {
                    lease = null;
                    return false;
                }

                _available--;
                lease = new Releaser(this);
                return true;
            }
        }

        private void Release()
        {
            TaskCompletionSource<IDisposable> waiter = null;
            lock (_syncRoot)
            {
                if (_waiters.Count > 0)
                {
                    waiter = _waiters.Dequeue();
                }
                else
                {
                    _available++;
                }
            }

            if (waiter != null)
                waiter.TrySetResult(new Releaser(this));
        }

        private sealed class Releaser : IDisposable
        {
            private AsyncLimiter _owner;

            public Releaser(AsyncLimiter owner)
            {
                _owner = owner;
            }

            public void Dispose()
            {
                AsyncLimiter owner = _owner;
                if (owner == null)
                    return;
                _owner = null;
                owner.Release();
            }
        }
    }
}
