using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using ChiselSharp.Utils;

namespace ChiselSharp.Protocol
{
    public class Multiplexer : IDisposable
    {
        private readonly Stream _stream; // usually WebSocketFrameStream
        private readonly SessionCrypto _crypto;
        private readonly ConcurrentDictionary<uint, Channel> _channels;
        private uint _nextChannelId;
        private readonly object _nextIdLock = new object();
        private readonly CancellationTokenSource _cts;
        private Task _readLoopTask;
        private readonly bool _isServer;

        public bool IsConnected { get; private set; }

        public event Action<uint, Frame> FrameReceived; // channelId, frame

        public Multiplexer(Stream stream, SessionCrypto crypto, bool isServer = false)
        {
            if (stream == null) throw new ArgumentNullException("stream");
            _stream = stream;
            if (crypto == null) throw new ArgumentNullException("crypto");
            _crypto = crypto;
            _isServer = isServer;
            _channels = new ConcurrentDictionary<uint, Channel>();
            _cts = new CancellationTokenSource();

            // Use separate ID ranges to avoid collisions when both sides open channels:
            // Server starts at 2, client starts at 1. Each increments by 2.
            _nextChannelId = isServer ? 2u : 1u;

            // Channel 0 is always the control channel
            var controlChannel = new Channel(0, this);
            controlChannel.SignalOpen(); // Always open
            _channels[0] = controlChannel;
        }

        /// <summary>
        /// Get the control channel (channel 0).
        /// </summary>
        public Channel ControlChannel
        {
            get
            {
                Channel ch;
                _channels.TryGetValue(0, out ch);
                return ch;
            }
        }

        /// <summary>
        /// Start the read loop. Must be called after construction.
        /// </summary>
        public void Start()
        {
            IsConnected = true;
            _readLoopTask = Compat.Run((Func<Task>)ReadLoop);
        }

        /// <summary>
        /// Open a new channel. Returns the channel (not yet acknowledged).
        /// </summary>
        public Channel OpenChannel()
        {
            uint id;
            lock (_nextIdLock)
            {
                id = _nextChannelId;
                _nextChannelId += 2; // separate server (even) / client (odd) ID spaces
            }

            var channel = new Channel(id, this);
            _channels[id] = channel;
            return channel;
        }

        /// <summary>
        /// Accept an incoming channel from a SYN frame with the given channel ID.
        /// Creates and registers a local channel with the same ID so that DATA
        /// frames from the peer are routed correctly.
        /// </summary>
        public Channel AcceptChannel(uint channelId)
        {
            return _channels.GetOrAdd(channelId, id => new Channel(id, this));
        }

        /// <summary>
        /// Send a frame over the encrypted stream.
        /// </summary>
        public async Task SendFrameAsync(Frame frame)
        {
            byte[] encoded = frame.Encode();
            byte[] encrypted = _crypto.Encrypt(encoded);

            // Write: [encrypted_length(4)] [encrypted_data]
            byte[] lengthPrefix = new byte[4];
            lengthPrefix[0] = (byte)((encrypted.Length >> 24) & 0xFF);
            lengthPrefix[1] = (byte)((encrypted.Length >> 16) & 0xFF);
            lengthPrefix[2] = (byte)((encrypted.Length >> 8) & 0xFF);
            lengthPrefix[3] = (byte)(encrypted.Length & 0xFF);

            byte[] packet = new byte[4 + encrypted.Length];
            Buffer.BlockCopy(lengthPrefix, 0, packet, 0, 4);
            Buffer.BlockCopy(encrypted, 0, packet, 4, encrypted.Length);

            await _stream.WriteAsync(packet, 0, packet.Length);
            await _stream.FlushAsync();
        }

        /// <summary>
        /// Send a plaintext (unencrypted) message. Used during handshake before crypto is set up.
        /// </summary>
        public async Task SendRawAsync(byte[] data)
        {
            // Write: [length(4)] [data] - no encryption
            byte[] lengthPrefix = new byte[4];
            lengthPrefix[0] = (byte)((data.Length >> 24) & 0xFF);
            lengthPrefix[1] = (byte)((data.Length >> 16) & 0xFF);
            lengthPrefix[2] = (byte)((data.Length >> 8) & 0xFF);
            lengthPrefix[3] = (byte)(data.Length & 0xFF);

            byte[] packet = new byte[4 + data.Length];
            Buffer.BlockCopy(lengthPrefix, 0, packet, 0, 4);
            Buffer.BlockCopy(data, 0, packet, 4, data.Length);

            await _stream.WriteAsync(packet, 0, packet.Length);
            await _stream.FlushAsync();
        }

        /// <summary>
        /// Receive a raw (unencrypted) message. Used during handshake.
        /// Returns null if connection closed.
        /// </summary>
        public async Task<byte[]> ReceiveRawAsync()
        {
            // Read 4-byte length
            byte[] lenBuf = new byte[4];
            int read = await ReadExactAsync(lenBuf, 0, 4);
            if (read < 4) return null;

            int length = (lenBuf[0] << 24) | (lenBuf[1] << 16) | (lenBuf[2] << 8) | lenBuf[3];
            if (length < 0 || length > 1024 * 1024) // 1MB max
                return null;

            byte[] data = new byte[length];
            read = await ReadExactAsync(data, 0, length);
            if (read < length) return null;

            return data;
        }

        private async Task ReadLoop()
        {
            try
            {
                while (!_cts.Token.IsCancellationRequested && IsConnected)
                {
                    // Read length prefix (4 bytes)
                    byte[] lenBuf = new byte[4];
                    int read = await ReadExactAsync(lenBuf, 0, 4);
                    if (read < 4)
                    {
                        IsConnected = false;
                        break;
                    }

                    int encryptedLen = (lenBuf[0] << 24) | (lenBuf[1] << 16) | (lenBuf[2] << 8) | lenBuf[3];
                    if (encryptedLen <= 0 || encryptedLen > 1024 * 1024)
                    {
                        IsConnected = false;
                        break;
                    }

                    // Read encrypted data
                    byte[] encrypted = new byte[encryptedLen];
                    read = await ReadExactAsync(encrypted, 0, encryptedLen);
                    if (read < encryptedLen)
                    {
                        IsConnected = false;
                        break;
                    }

                    // Decrypt
                    byte[] decrypted = _crypto.Decrypt(encrypted);
                    if (decrypted == null)
                    {
                        // Auth failed - connection compromised
                        IsConnected = false;
                        break;
                    }

                    // Decode frame
                    int consumed;
                    Frame frame = Frame.Decode(decrypted, 0, decrypted.Length, out consumed);
                    if (frame == null) continue;

                    // Route to channel
                    Channel channel;
                    if (_channels.TryGetValue(frame.ChannelId, out channel))
                    {
                        if ((frame.Flags & FrameFlags.DATA) != 0)
                        {
                            channel.EnqueueData(frame.Payload);
                        }
                        else if ((frame.Flags & FrameFlags.FIN) != 0)
                        {
                            channel.ForceClose();
                            Channel removed;
                            _channels.TryRemove(frame.ChannelId, out removed);
                        }
                        else if ((frame.Flags & FrameFlags.RST) != 0)
                        {
                            channel.ForceClose();
                            Channel removed;
                            _channels.TryRemove(frame.ChannelId, out removed);
                        }
                        else if ((frame.Flags & FrameFlags.ACK) != 0)
                        {
                            channel.SignalOpen();
                        }
                    }

                    // Fire event for SYN frames (new channel requests)
                    if ((frame.Flags & FrameFlags.SYN) != 0)
                    {
                        if (FrameReceived != null)
                            FrameReceived.Invoke(frame.ChannelId, frame);
                    }
                }
            }
            catch (Exception)
            {
                IsConnected = false;
            }
        }

        private async Task<int> ReadExactAsync(byte[] buffer, int offset, int count)
        {
            int totalRead = 0;
            while (totalRead < count)
            {
                int read = await _stream.ReadAsync(buffer, offset + totalRead, count - totalRead);
                if (read == 0) break;
                totalRead += read;
            }
            return totalRead;
        }

        public void Disconnect()
        {
            IsConnected = false;
            _cts.Cancel();

            foreach (var kvp in _channels)
            {
                kvp.Value.ForceClose();
            }
            _channels.Clear();
        }

        public void Dispose()
        {
            Disconnect();
            _cts.Dispose();
            _crypto.Dispose();
        }
    }
}
