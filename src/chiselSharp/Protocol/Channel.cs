using System;
using System.Collections.Concurrent;
using System.Threading;
using System.Threading.Tasks;

namespace ChiselSharp.Protocol
{
    public class Channel : IDisposable
    {
        public uint Id { get; private set; }
        public bool IsOpen { get; private set; }

        private readonly BlockingCollection<byte[]> _receiveQueue;
        private readonly Multiplexer _mux;
        private readonly CancellationTokenSource _cts;

        // For channel open signaling
        private readonly TaskCompletionSource<bool> _openTcs;

        public Channel(uint id, Multiplexer mux)
        {
            Id = id;
            _mux = mux;
            _receiveQueue = new BlockingCollection<byte[]>(new ConcurrentQueue<byte[]>());
            _cts = new CancellationTokenSource();
            _openTcs = new TaskCompletionSource<bool>();
            IsOpen = true;
        }

        /// <summary>
        /// Wait for channel to be acknowledged as open.
        /// </summary>
        public Task WaitForOpen()
        {
            return _openTcs.Task;
        }

        /// <summary>
        /// Signal that the channel has been acknowledged.
        /// </summary>
        internal void SignalOpen()
        {
            _openTcs.TrySetResult(true);
        }

        /// <summary>
        /// Send data on this channel.
        /// </summary>
        public async Task SendAsync(byte[] data)
        {
            if (!IsOpen) throw new InvalidOperationException("Channel is closed");
            await _mux.SendFrameAsync(Frame.CreateData(Id, data));
        }

        /// <summary>
        /// Receive data from this channel. Blocks until data available or channel closed.
        /// Returns null if channel is closed.
        /// </summary>
        public byte[] Receive(CancellationToken cancellationToken = default(CancellationToken))
        {
            try
            {
                using (var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _cts.Token))
                {
                    byte[] data;
                    if (_receiveQueue.TryTake(out data, Timeout.Infinite, linkedCts.Token))
                        return data;
                }
            }
            catch (OperationCanceledException) { }
            return null;
        }

        /// <summary>
        /// Try to receive data without blocking. Returns null if no data.
        /// </summary>
        public byte[] TryReceive()
        {
            byte[] data;
            if (_receiveQueue.TryTake(out data, 0))
                return data;
            return null;
        }

        /// <summary>
        /// Enqueue received data from the multiplexer.
        /// </summary>
        internal void EnqueueData(byte[] data)
        {
            if (IsOpen)
                _receiveQueue.Add(data);
        }

        /// <summary>
        /// Close this channel.
        /// </summary>
        public async Task CloseAsync()
        {
            if (!IsOpen) return;
            IsOpen = false;
            _cts.Cancel();
            await _mux.SendFrameAsync(Frame.CreateFin(Id));
            _receiveQueue.CompleteAdding();
        }

        /// <summary>
        /// Force close (used when RST received).
        /// </summary>
        internal void ForceClose()
        {
            IsOpen = false;
            _cts.Cancel();
            _receiveQueue.CompleteAdding();
        }

        public void Dispose()
        {
            IsOpen = false;
            _cts.Cancel();
            _cts.Dispose();
            _receiveQueue.Dispose();
        }
    }
}
