using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using ChiselSharp.Utils;

namespace ChiselSharp.SSH
{
    /// <summary>
    /// Represents an open SSH channel with state tracking.
    /// </summary>
    internal class SshChannel
    {
        public const uint DefaultWindowSize = 4194304; // 4MB
        public const uint DefaultMaxPacket = 32768;

        public uint LocalId { get; set; }        // Our channel number
        public uint RemoteId { get; set; }       // Peer's channel number
        public string Type { get; set; }         // "session", "direct-tcpip"
        public bool IsOpen { get; set; }
        public uint RemoteWindow { get; set; }   // Peer's window remaining
        public uint LocalWindow { get; set; }    // Our window remaining
        public uint RemoteMaxPacket { get; set; }
        public object SyncRoot { get; private set; }

        // Data received from peer, queued for reading
        public BlockingCollection<byte[]> IncomingData { get; private set; }

        // Event for incoming data notification
        public TaskCompletionSource<bool> OpenConfirmationTcs { get; set; }
        public TaskCompletionSource<bool> WindowAdjustTcs { get; set; }

        public SshChannel(uint localId, string type)
        {
            LocalId = localId;
            RemoteId = 0;
            Type = type;
            IsOpen = false;
            RemoteWindow = DefaultWindowSize;
            LocalWindow = DefaultWindowSize;
            RemoteMaxPacket = DefaultMaxPacket;
            SyncRoot = new object();
            IncomingData = new BlockingCollection<byte[]>(new ConcurrentQueue<byte[]>());
            OpenConfirmationTcs = new TaskCompletionSource<bool>();
        }
    }

    /// <summary>
    /// High-level SSH connection handling on top of SshTransport.
    /// Provides password authentication, channel management, and data I/O.
    /// </summary>
    public class SshConnection : IDisposable
    {
        private readonly SshTransport _transport;
        private readonly Dictionary<uint, SshChannel> _channels;
        private readonly object _channelsLock = new object();
        private uint _nextLocalId;
        private readonly object _idLock = new object();

        private Task _readLoopTask;
        private CancellationTokenSource _readLoopCts;
        private bool _disposed;
        private const int ChannelOpenTimeoutMs = 30000;
        public bool IsClosed { get; private set; }

        // Event for incoming channel open requests (from server)
        public event Action<uint, string, byte[]> IncomingChannelOpen;

        // Event for incoming channel requests (env, exec, shell, etc.)
        public event Action<uint, string, byte[], bool> IncomingChannelRequest;

        /// <summary>
        /// Create an SSH connection over an established encrypted transport.
        /// </summary>
        public SshConnection(SshTransport transport)
        {
            if (transport == null)
                throw new ArgumentNullException("transport");
            if (!transport.IsEncrypted)
                throw new InvalidOperationException("Transport must be encrypted before creating SshConnection");

            _transport = transport;
            _channels = new Dictionary<uint, SshChannel>();
            _nextLocalId = 1;
            _readLoopCts = new CancellationTokenSource();
            IsClosed = false;
            // Read loop started after authentication succeeds
        }

        /// <summary>
        /// Start the background read loop. Must be called after authentication completes.
        /// </summary>
        public void StartReadLoop()
        {
            if (_readLoopTask == null)
            {
                _readLoopTask = Compat.Run((Func<Task>)ReadLoopAsync);
            }
        }

        // ===================== Authentication =====================

        /// <summary>
        /// Send ssh-userauth service request and authenticate with password.
        /// </summary>
        public async Task AuthenticateAsync(string user, string password)
        {
            if (!_transport.IsEncrypted)
                throw new InvalidOperationException("Transport must be encrypted before authentication");

            // 1. Service request: "ssh-userauth"
            byte[] serviceReq = BuildServiceRequest("ssh-userauth");
            await _transport.SendPacketAsync(serviceReq);

            byte[] serviceResp = await _transport.ReceivePacketAsync();
            if (serviceResp == null || serviceResp.Length < 1 ||
                serviceResp[0] != SshMsg.SSH_MSG_SERVICE_ACCEPT)
            {
                throw new Exception("Server rejected service request");
            }

            // 2. Password authentication request
            byte[] authReq = BuildPasswordAuthRequest(user, password);
            await _transport.SendPacketAsync(authReq);

            // 3. Process response(s)
            while (true)
            {
                byte[] authResp = await _transport.ReceivePacketAsync();
                if (authResp == null || authResp.Length == 0)
                    throw new Exception("Server disconnected during authentication");

                byte msgType = authResp[0];

                if (msgType == SshMsg.SSH_MSG_USERAUTH_SUCCESS)
                {
                    return; // Authenticated
                }
                else if (msgType == SshMsg.SSH_MSG_USERAUTH_FAILURE)
                {
                    int offset = 1;
                    string methods = SshWire.ReadString(authResp, ref offset);
                    bool partialSuccess = (offset < authResp.Length && authResp[offset] == 1);
                    throw new Exception("Authentication failed. Supported methods: " + methods +
                        (partialSuccess ? " (partial success)" : ""));
                }
                else if (msgType == SshMsg.SSH_MSG_USERAUTH_BANNER)
                {
                    // Banner message, continue reading
                    continue;
                }
                else if (msgType == SshMsg.SSH_MSG_DISCONNECT)
                {
                    int offset = 1;
                    uint reason = SshWire.ReadUint32(authResp, ref offset);
                    string msg = SshWire.ReadString(authResp, ref offset);
                    throw new Exception("Server disconnected: reason=" + reason + " message=" + msg);
                }
                else
                {
                    // Unexpected message during auth
                    continue;
                }
            }
        }

        /// <summary>
        /// Send an SSH global request and wait for its reply. Call this before
        /// StartReadLoop(), otherwise the background reader may consume the reply.
        /// </summary>
        public async Task<byte[]> SendGlobalRequestAsync(string requestName, bool wantReply, byte[] requestData)
        {
            if (_readLoopTask != null)
                throw new InvalidOperationException("Global requests with replies must be sent before the read loop starts");

            byte[] payload = BuildGlobalRequest(requestName, wantReply, requestData);
            await _transport.SendPacketAsync(payload);

            if (!wantReply)
                return null;

            while (true)
            {
                byte[] response = await _transport.ReceivePacketAsync();
                if (response == null || response.Length == 0)
                    throw new Exception("Server disconnected while waiting for global request reply");

                byte msgType = response[0];
                if (msgType == SshMsg.SSH_MSG_REQUEST_SUCCESS)
                {
                    byte[] data = new byte[response.Length - 1];
                    if (data.Length > 0)
                        Buffer.BlockCopy(response, 1, data, 0, data.Length);
                    return data;
                }

                if (msgType == SshMsg.SSH_MSG_REQUEST_FAILURE)
                {
                    string message = "";
                    if (response.Length > 1)
                        message = Encoding.UTF8.GetString(response, 1, response.Length - 1);
                    throw new Exception("Global request '" + requestName + "' failed" +
                        (message.Length > 0 ? ": " + message : ""));
                }

                if (msgType == SshMsg.SSH_MSG_IGNORE || msgType == SshMsg.SSH_MSG_DEBUG)
                    continue;

                if (msgType == SshMsg.SSH_MSG_DISCONNECT)
                    throw new Exception("Server disconnected while waiting for global request reply");
            }
        }

        private static byte[] BuildGlobalRequest(string requestName, bool wantReply, byte[] requestData)
        {
            byte[] nameBytes = Encoding.UTF8.GetBytes(requestName ?? "");
            int dataLen = requestData != null ? requestData.Length : 0;
            byte[] payload = new byte[1 + 4 + nameBytes.Length + 1 + dataLen];
            int offset = 0;

            payload[offset++] = SshMsg.SSH_MSG_GLOBAL_REQUEST;

            byte[] nameLen = SshWire.EncodeUint32((uint)nameBytes.Length);
            Buffer.BlockCopy(nameLen, 0, payload, offset, 4); offset += 4;
            Buffer.BlockCopy(nameBytes, 0, payload, offset, nameBytes.Length); offset += nameBytes.Length;

            payload[offset++] = wantReply ? (byte)1 : (byte)0;

            if (dataLen > 0)
                Buffer.BlockCopy(requestData, 0, payload, offset, dataLen);

            return payload;
        }

        private static byte[] BuildServiceRequest(string serviceName)
        {
            byte[] nameBytes = Encoding.UTF8.GetBytes(serviceName);
            byte[] payload = new byte[1 + 4 + nameBytes.Length];
            payload[0] = SshMsg.SSH_MSG_SERVICE_REQUEST;
            byte[] lenBytes = SshWire.EncodeUint32((uint)nameBytes.Length);
            Buffer.BlockCopy(lenBytes, 0, payload, 1, 4);
            Buffer.BlockCopy(nameBytes, 0, payload, 5, nameBytes.Length);
            return payload;
        }

        private static byte[] BuildPasswordAuthRequest(string user, string password)
        {
            byte[] userBytes = Encoding.UTF8.GetBytes(user ?? "");
            byte[] passBytes = Encoding.UTF8.GetBytes(password ?? "");
            byte[] serviceBytes = Encoding.UTF8.GetBytes("ssh-connection");
            byte[] methodBytes = Encoding.UTF8.GetBytes("password");

            // Format: SSH_MSG_USERAUTH_REQUEST (1) + string user + string "ssh-connection" + string "password" + bool FALSE + string password
            int totalLen = 1 + 4 + userBytes.Length + 4 + serviceBytes.Length + 4 + methodBytes.Length + 1 + 4 + passBytes.Length;
            byte[] payload = new byte[totalLen];
            int offset = 0;

            payload[offset++] = SshMsg.SSH_MSG_USERAUTH_REQUEST;

            // user name
            byte[] ulen = SshWire.EncodeUint32((uint)userBytes.Length);
            Buffer.BlockCopy(ulen, 0, payload, offset, 4); offset += 4;
            Buffer.BlockCopy(userBytes, 0, payload, offset, userBytes.Length); offset += userBytes.Length;

            // service name
            byte[] slen = SshWire.EncodeUint32((uint)serviceBytes.Length);
            Buffer.BlockCopy(slen, 0, payload, offset, 4); offset += 4;
            Buffer.BlockCopy(serviceBytes, 0, payload, offset, serviceBytes.Length); offset += serviceBytes.Length;

            // method name
            byte[] mlen = SshWire.EncodeUint32((uint)methodBytes.Length);
            Buffer.BlockCopy(mlen, 0, payload, offset, 4); offset += 4;
            Buffer.BlockCopy(methodBytes, 0, payload, offset, methodBytes.Length); offset += methodBytes.Length;

            // bool FALSE (password method uses FALSE + plaintext)
            payload[offset++] = 0;

            // password
            byte[] plen = SshWire.EncodeUint32((uint)passBytes.Length);
            Buffer.BlockCopy(plen, 0, payload, offset, 4); offset += 4;
            Buffer.BlockCopy(passBytes, 0, payload, offset, passBytes.Length); offset += passBytes.Length;

            return payload;
        }

        // ===================== Channel Management =====================

        /// <summary>
        /// Open a "session" channel. Used for config exchange with chisel server.
        /// </summary>
        public async Task<uint> OpenSessionChannelAsync()
        {
            return await OpenChannelAsync("session", null);
        }

        /// <summary>
        /// Open a "direct-tcpip" channel for TCP forwarding.
        /// </summary>
        public async Task<uint> OpenDirectTcpipAsync(string host, int port, string originAddr, int originPort)
        {
            byte[] extra = BuildDirectTcpipExtra(host, port, originAddr, originPort);
            return await OpenChannelAsync("direct-tcpip", extra);
        }

        /// <summary>
        /// Open a native chisel data channel. Chisel uses channel type
        /// "chisel" and stores the target address string in ExtraData.
        /// </summary>
        public async Task<uint> OpenChiselAsync(string remote)
        {
            byte[] extra = Encoding.UTF8.GetBytes(remote ?? "");
            return await OpenChannelAsync("chisel", extra);
        }

        private async Task<uint> OpenChannelAsync(string channelType, byte[] typeSpecificData)
        {
            uint localId;
            lock (_idLock)
            {
                localId = _nextLocalId++;
            }

            var channel = new SshChannel(localId, channelType);

            lock (_channelsLock)
            {
                _channels[localId] = channel;
            }

            // Build SSH_MSG_CHANNEL_OPEN
            byte[] typeBytes = Encoding.UTF8.GetBytes(channelType);
            int payloadLen = 1 + 4 + typeBytes.Length + 4 + 4 + 4; // msg + type_str + sender + window + max_pkt
            if (typeSpecificData != null)
                payloadLen += typeSpecificData.Length;

            byte[] payload = new byte[payloadLen];
            int offset = 0;

            payload[offset++] = SshMsg.SSH_MSG_CHANNEL_OPEN;

            // channel type string
            byte[] tlen = SshWire.EncodeUint32((uint)typeBytes.Length);
            Buffer.BlockCopy(tlen, 0, payload, offset, 4); offset += 4;
            Buffer.BlockCopy(typeBytes, 0, payload, offset, typeBytes.Length); offset += typeBytes.Length;

            // sender channel
            byte[] idBytes = SshWire.EncodeUint32(localId);
            Buffer.BlockCopy(idBytes, 0, payload, offset, 4); offset += 4;

            // initial window size
            byte[] winBytes = SshWire.EncodeUint32(SshChannel.DefaultWindowSize);
            Buffer.BlockCopy(winBytes, 0, payload, offset, 4); offset += 4;

            // maximum packet size
            byte[] maxBytes = SshWire.EncodeUint32(SshChannel.DefaultMaxPacket);
            Buffer.BlockCopy(maxBytes, 0, payload, offset, 4); offset += 4;

            if (typeSpecificData != null)
            {
                Buffer.BlockCopy(typeSpecificData, 0, payload, offset, typeSpecificData.Length);
            }

            try
            {
                await _transport.SendPacketAsync(payload);
            }
            catch
            {
                RemoveChannel(localId);
                throw;
            }

            // Wait for confirmation (handled by read loop)
            Task completed = await Compat.WhenAny(
                channel.OpenConfirmationTcs.Task,
                Compat.Delay(ChannelOpenTimeoutMs));
            if (completed != channel.OpenConfirmationTcs.Task)
            {
                RemoveChannel(localId);
                throw new TimeoutException("Timed out opening channel: " + channelType);
            }

            await channel.OpenConfirmationTcs.Task;

            return localId;
        }

        private static byte[] BuildDirectTcpipExtra(string host, int port, string originAddr, int originPort)
        {
            byte[] hostBytes = Encoding.UTF8.GetBytes(host);
            byte[] originBytes = Encoding.UTF8.GetBytes(originAddr ?? "");

            // host_to_connect + port + originator_ip + originator_port
            int total = 4 + hostBytes.Length + 4 + 4 + originBytes.Length + 4;
            byte[] data = new byte[total];
            int offset = 0;

            // host_to_connect
            byte[] hlen = SshWire.EncodeUint32((uint)hostBytes.Length);
            Buffer.BlockCopy(hlen, 0, data, offset, 4); offset += 4;
            Buffer.BlockCopy(hostBytes, 0, data, offset, hostBytes.Length); offset += hostBytes.Length;

            // port_to_connect
            byte[] pbytes = SshWire.EncodeUint32((uint)port);
            Buffer.BlockCopy(pbytes, 0, data, offset, 4); offset += 4;

            // originator_ip
            byte[] olen = SshWire.EncodeUint32((uint)originBytes.Length);
            Buffer.BlockCopy(olen, 0, data, offset, 4); offset += 4;
            Buffer.BlockCopy(originBytes, 0, data, offset, originBytes.Length); offset += originBytes.Length;

            // originator_port
            byte[] opbytes = SshWire.EncodeUint32((uint)originPort);
            Buffer.BlockCopy(opbytes, 0, data, offset, 4); offset += 4;

            return data;
        }

        /// <summary>
        /// Send an environment variable on a channel (SSH_MSG_CHANNEL_REQUEST "env").
        /// Used by chisel to pass remote specifications.
        /// </summary>
        public async Task SendEnvRequestAsync(uint localChannelId, string name, string value)
        {
            SshChannel channel = FindChannel(localChannelId);
            if (channel == null)
                throw new InvalidOperationException("Channel not found: " + localChannelId);

            byte[] nameBytes = Encoding.UTF8.GetBytes(name);
            byte[] valueBytes = Encoding.UTF8.GetBytes(value ?? "");

            // SSH_MSG_CHANNEL_REQUEST + recipient + "env" + want_reply(1) + var_name + var_value
            int len = 1 + 4 + 4 + Encoding.UTF8.GetBytes("env").Length + 1 + 4 + nameBytes.Length + 4 + valueBytes.Length;
            byte[] payload = new byte[len];
            int offset = 0;

            payload[offset++] = SshMsg.SSH_MSG_CHANNEL_REQUEST;

            // recipient channel (remote ID)
            byte[] rid = SshWire.EncodeUint32(channel.RemoteId);
            Buffer.BlockCopy(rid, 0, payload, offset, 4); offset += 4;

            // "env"
            byte[] reqBytes = Encoding.UTF8.GetBytes("env");
            byte[] rlen = SshWire.EncodeUint32((uint)reqBytes.Length);
            Buffer.BlockCopy(rlen, 0, payload, offset, 4); offset += 4;
            Buffer.BlockCopy(reqBytes, 0, payload, offset, reqBytes.Length); offset += reqBytes.Length;

            // want_reply = 1
            payload[offset++] = 1;

            // variable name
            byte[] nlen = SshWire.EncodeUint32((uint)nameBytes.Length);
            Buffer.BlockCopy(nlen, 0, payload, offset, 4); offset += 4;
            Buffer.BlockCopy(nameBytes, 0, payload, offset, nameBytes.Length); offset += nameBytes.Length;

            // variable value
            byte[] vlen = SshWire.EncodeUint32((uint)valueBytes.Length);
            Buffer.BlockCopy(vlen, 0, payload, offset, 4); offset += 4;
            Buffer.BlockCopy(valueBytes, 0, payload, offset, valueBytes.Length); offset += valueBytes.Length;

            await _transport.SendPacketAsync(payload);
        }

        /// <summary>
        /// Send an "exec" channel request.
        /// </summary>
        public async Task SendExecRequestAsync(uint localChannelId, string command)
        {
            SshChannel channel = FindChannel(localChannelId);
            if (channel == null)
                throw new InvalidOperationException("Channel not found: " + localChannelId);

            byte[] cmdBytes = Encoding.UTF8.GetBytes(command ?? "");

            int len = 1 + 4 + 4 + Encoding.UTF8.GetBytes("exec").Length + 1 + 4 + cmdBytes.Length;
            byte[] payload = new byte[len];
            int offset = 0;

            payload[offset++] = SshMsg.SSH_MSG_CHANNEL_REQUEST;

            byte[] rid = SshWire.EncodeUint32(channel.RemoteId);
            Buffer.BlockCopy(rid, 0, payload, offset, 4); offset += 4;

            byte[] reqBytes = Encoding.UTF8.GetBytes("exec");
            byte[] rlen = SshWire.EncodeUint32((uint)reqBytes.Length);
            Buffer.BlockCopy(rlen, 0, payload, offset, 4); offset += 4;
            Buffer.BlockCopy(reqBytes, 0, payload, offset, reqBytes.Length); offset += reqBytes.Length;

            // want_reply = 1
            payload[offset++] = 1;

            byte[] clen = SshWire.EncodeUint32((uint)cmdBytes.Length);
            Buffer.BlockCopy(clen, 0, payload, offset, 4); offset += 4;
            Buffer.BlockCopy(cmdBytes, 0, payload, offset, cmdBytes.Length); offset += cmdBytes.Length;

            await _transport.SendPacketAsync(payload);
        }

        /// <summary>
        /// Write data on an open channel (SSH_MSG_CHANNEL_DATA).
        /// </summary>
        public async Task SendChannelDataAsync(uint localChannelId, byte[] data)
        {
            if (data == null)
                throw new ArgumentNullException("data");
            await SendChannelDataAsync(localChannelId, data, 0, data.Length);
        }

        public async Task SendChannelDataAsync(uint localChannelId, byte[] data, int offset, int count)
        {
            SshChannel channel = FindChannel(localChannelId);
            if (channel == null)
                throw new InvalidOperationException("Channel not found: " + localChannelId);

            if (!channel.IsOpen)
                throw new InvalidOperationException("Channel " + localChannelId + " is not open");

            if (data == null)
                throw new ArgumentNullException("data");
            if (offset < 0 || count < 0 || offset + count > data.Length)
                throw new ArgumentOutOfRangeException("count");
            if (count == 0)
                return;

            int position = offset;
            int remaining = count;

            while (remaining > 0)
            {
                int chunk = await ReserveSendWindowAsync(channel, remaining);
                byte[] payload = new byte[1 + 4 + 4 + chunk];
                int payloadOffset = 0;

                payload[payloadOffset++] = SshMsg.SSH_MSG_CHANNEL_DATA;

                byte[] rid = SshWire.EncodeUint32(channel.RemoteId);
                Buffer.BlockCopy(rid, 0, payload, payloadOffset, 4); payloadOffset += 4;

                byte[] dlen = SshWire.EncodeUint32((uint)chunk);
                Buffer.BlockCopy(dlen, 0, payload, payloadOffset, 4); payloadOffset += 4;
                Buffer.BlockCopy(data, position, payload, payloadOffset, chunk);

                await _transport.SendPacketAsync(payload);

                position += chunk;
                remaining -= chunk;
            }
        }

        /// <summary>
        /// Send EOF on a channel.
        /// </summary>
        public async Task SendChannelEofAsync(uint localChannelId)
        {
            SshChannel channel = FindChannel(localChannelId);
            if (channel == null)
                throw new InvalidOperationException("Channel not found: " + localChannelId);

            byte[] payload = new byte[1 + 4];
            payload[0] = SshMsg.SSH_MSG_CHANNEL_EOF;
            byte[] rid = SshWire.EncodeUint32(channel.RemoteId);
            Buffer.BlockCopy(rid, 0, payload, 1, 4);

            await _transport.SendPacketAsync(payload);
        }

        /// <summary>
        /// Send close on a channel.
        /// </summary>
        public async Task CloseChannelAsync(uint localChannelId)
        {
            SshChannel channel;
            lock (_channelsLock)
            {
                _channels.TryGetValue(localChannelId, out channel);
                _channels.Remove(localChannelId);
            }

            if (channel != null)
            {
                lock (channel.SyncRoot)
                {
                    channel.IsOpen = false;
                    if (channel.WindowAdjustTcs != null)
                        channel.WindowAdjustTcs.TrySetResult(true);
                }
                try { channel.IncomingData.CompleteAdding(); } catch { }

                if (channel.RemoteId != 0)
                {
                    byte[] payload = new byte[1 + 4];
                    payload[0] = SshMsg.SSH_MSG_CHANNEL_CLOSE;
                    byte[] rid = SshWire.EncodeUint32(channel.RemoteId);
                    Buffer.BlockCopy(rid, 0, payload, 1, 4);

                    await _transport.SendPacketAsync(payload);
                }
            }
        }

        /// <summary>
        /// Receive data from a channel. Returns null if channel is closed.
        /// </summary>
        public byte[] ReceiveChannelData(uint localChannelId, int timeoutMs = -1)
        {
            SshChannel channel = FindChannel(localChannelId);
            if (channel == null)
                return null;

            try
            {
                byte[] data;
                if (timeoutMs >= 0)
                {
                    if (channel.IncomingData.TryTake(out data, timeoutMs))
                    {
                        AdjustLocalWindow(channel, data.Length);
                        return data;
                    }
                    return null;
                }
                else
                {
                    data = channel.IncomingData.Take();
                    AdjustLocalWindow(channel, data.Length);
                    return data;
                }
            }
            catch (InvalidOperationException)
            {
                // Collection is complete (channel closed)
                return null;
            }
        }

        // ===================== Read Loop =====================

        private async Task ReadLoopAsync()
        {
            CancellationToken token = _readLoopCts.Token;

            try
            {
                while (!token.IsCancellationRequested)
                {
                    byte[] payload = await _transport.ReceivePacketAsync();
                    if (payload == null || payload.Length == 0)
                        break;

                    byte msgType = payload[0];

                    switch (msgType)
                    {
                        case SshMsg.SSH_MSG_CHANNEL_OPEN:
                            HandleChannelOpen(payload);
                            break;

                        case SshMsg.SSH_MSG_CHANNEL_OPEN_CONFIRMATION:
                            HandleChannelOpenConfirmation(payload);
                            break;

                        case SshMsg.SSH_MSG_CHANNEL_OPEN_FAILURE:
                            HandleChannelOpenFailure(payload);
                            break;

                        case SshMsg.SSH_MSG_CHANNEL_DATA:
                            HandleChannelData(payload);
                            break;

                        case SshMsg.SSH_MSG_CHANNEL_EOF:
                            HandleChannelEof(payload);
                            break;

                        case SshMsg.SSH_MSG_CHANNEL_CLOSE:
                            HandleChannelClose(payload);
                            break;

                        case SshMsg.SSH_MSG_CHANNEL_WINDOW_ADJUST:
                            HandleWindowAdjust(payload);
                            break;

                        case SshMsg.SSH_MSG_CHANNEL_REQUEST:
                            HandleChannelRequest(payload);
                            break;

                        case SshMsg.SSH_MSG_CHANNEL_SUCCESS:
                        case SshMsg.SSH_MSG_CHANNEL_FAILURE:
                            // Channel request response (used for env/exec)
                            // Not critical to handle for basic operation
                            break;

                        case SshMsg.SSH_MSG_GLOBAL_REQUEST:
                            HandleGlobalRequest(payload);
                            break;

                        case SshMsg.SSH_MSG_REQUEST_FAILURE:
                            // Global request failure, ignore
                            break;

                        case SshMsg.SSH_MSG_DISCONNECT:
                            Logger.Debug("SSH disconnect received");
                            _readLoopCts.Cancel();
                            break;

                        case SshMsg.SSH_MSG_IGNORE:
                        case SshMsg.SSH_MSG_DEBUG:
                            // Ignore
                            break;

                        default:
                            Logger.Debug("Unhandled SSH message type: " + msgType);
                            break;
                    }
                }
            }
            catch (OperationCanceledException)
            {
                // Normal shutdown
            }
            catch (Exception ex)
            {
                Logger.Debug("SSH read loop error: " + ex.Message);
            }

            // Mark all channels as closed
            lock (_channelsLock)
            {
                foreach (var kvp in _channels.Values)
                {
                    lock (kvp.SyncRoot)
                    {
                        kvp.IsOpen = false;
                        if (kvp.WindowAdjustTcs != null)
                            kvp.WindowAdjustTcs.TrySetResult(true);
                    }
                    kvp.OpenConfirmationTcs.TrySetException(new Exception("SSH connection closed"));
                    try { kvp.IncomingData.CompleteAdding(); } catch { }
                }
                _channels.Clear();
            }
            IsClosed = true;
        }

        // ===================== Message Handlers =====================

        private void HandleChannelOpen(byte[] payload)
        {
            try
            {
                int offset = 1;
                string channelType = SshWire.ReadString(payload, ref offset);
                uint senderChannel = SshWire.ReadUint32(payload, ref offset);
                uint windowSize = SshWire.ReadUint32(payload, ref offset);
                uint maxPacket = SshWire.ReadUint32(payload, ref offset);

                // Read type-specific data (if any)
                byte[] extra = null;
                if (offset < payload.Length)
                {
                    extra = new byte[payload.Length - offset];
                    Buffer.BlockCopy(payload, offset, extra, 0, extra.Length);
                }

                Logger.Debug("Incoming channel open: type=" + channelType +
                    " sender=" + senderChannel + " window=" + windowSize);

                // Assign a local channel ID
                uint localId;
                lock (_idLock)
                {
                    localId = _nextLocalId++;
                }

                var channel = new SshChannel(localId, channelType);
                channel.RemoteId = senderChannel;
                channel.RemoteWindow = windowSize;
                channel.RemoteMaxPacket = maxPacket > 0 ? maxPacket : SshChannel.DefaultMaxPacket;
                channel.IsOpen = true;

                lock (_channelsLock)
                {
                    _channels[localId] = channel;
                }

                // Send confirmation
                byte[] confirm = BuildChannelOpenConfirm(
                    senderChannel,
                    localId,
                    SshChannel.DefaultWindowSize,
                    SshChannel.DefaultMaxPacket);
                // Fire-and-forget: send confirmation packet
                Task unused = _transport.SendPacketAsync(confirm);

                // Notify listener
                var handler = IncomingChannelOpen;
                if (handler != null)
                {
                    handler(localId, channelType, extra);
                }
            }
            catch (Exception ex)
            {
                Logger.Debug("Error handling channel open: " + ex.Message);
            }
        }

        private void HandleGlobalRequest(byte[] payload)
        {
            try
            {
                int offset = 1;
                string requestType = SshWire.ReadString(payload, ref offset);
                bool wantReply = offset < payload.Length && payload[offset++] == 1;

                if (!wantReply)
                    return;

                if (requestType == "ping")
                {
                    Task unused = SendGlobalRequestReplyAsync(true, Encoding.UTF8.GetBytes("pong"));
                }
                else
                {
                    Task unused = SendGlobalRequestReplyAsync(false, null);
                }
            }
            catch (Exception ex)
            {
                Logger.Debug("Error handling global request: " + ex.Message);
            }
        }

        private async Task SendGlobalRequestReplyAsync(bool ok, byte[] data)
        {
            byte msg = ok ? SshMsg.SSH_MSG_REQUEST_SUCCESS : SshMsg.SSH_MSG_REQUEST_FAILURE;
            int dataLen = data != null ? data.Length : 0;
            byte[] payload = new byte[1 + dataLen];
            payload[0] = msg;
            if (dataLen > 0)
                Buffer.BlockCopy(data, 0, payload, 1, dataLen);
            await _transport.SendPacketAsync(payload);
        }

        private void HandleChannelOpenConfirmation(byte[] payload)
        {
            int offset = 1;
            uint recipientChannel = SshWire.ReadUint32(payload, ref offset);
            uint senderChannel = SshWire.ReadUint32(payload, ref offset);
            uint windowSize = SshWire.ReadUint32(payload, ref offset);
            uint maxPacket = SshWire.ReadUint32(payload, ref offset);

            SshChannel channel = FindChannel(recipientChannel);
            if (channel != null)
            {
                lock (channel.SyncRoot)
                {
                    channel.RemoteId = senderChannel;
                    channel.RemoteWindow = windowSize;
                    channel.RemoteMaxPacket = maxPacket > 0 ? maxPacket : SshChannel.DefaultMaxPacket;
                    channel.IsOpen = true;
                    if (channel.WindowAdjustTcs != null)
                        channel.WindowAdjustTcs.TrySetResult(true);
                }
                channel.OpenConfirmationTcs.TrySetResult(true);
            }
        }

        private void HandleChannelOpenFailure(byte[] payload)
        {
            int offset = 1;
            uint recipientChannel = SshWire.ReadUint32(payload, ref offset);
            uint reasonCode = SshWire.ReadUint32(payload, ref offset);
            string description = SshWire.ReadString(payload, ref offset);

            SshChannel channel = FindChannel(recipientChannel);
            if (channel != null)
            {
                RemoveChannel(recipientChannel);
                channel.OpenConfirmationTcs.TrySetException(
                    new Exception("Channel open failed: reason=" + reasonCode + " desc=" + description));
            }
        }

        private void HandleChannelData(byte[] payload)
        {
            int offset = 1;
            uint recipientChannel = SshWire.ReadUint32(payload, ref offset);
            byte[] data = SshWire.ReadBytes(payload, ref offset);

            SshChannel channel = FindChannel(recipientChannel);
            if (channel != null && channel.IsOpen)
            {
                lock (channel.SyncRoot)
                {
                    if (channel.LocalWindow >= data.Length)
                        channel.LocalWindow -= (uint)data.Length;
                    else
                        channel.LocalWindow = 0;
                }
                try { channel.IncomingData.Add(data); } catch (InvalidOperationException) { }
            }
        }

        private void HandleChannelEof(byte[] payload)
        {
            int offset = 1;
            uint recipientChannel = SshWire.ReadUint32(payload, ref offset);

            SshChannel channel = FindChannel(recipientChannel);
            if (channel != null)
            {
                try { channel.IncomingData.CompleteAdding(); } catch { }
            }
        }

        private void HandleChannelClose(byte[] payload)
        {
            int offset = 1;
            uint recipientChannel = SshWire.ReadUint32(payload, ref offset);

            SshChannel channel;
            lock (_channelsLock)
            {
                _channels.TryGetValue(recipientChannel, out channel);
                _channels.Remove(recipientChannel);
            }

            if (channel != null)
            {
                lock (channel.SyncRoot)
                {
                    channel.IsOpen = false;
                    if (channel.WindowAdjustTcs != null)
                        channel.WindowAdjustTcs.TrySetResult(true);
                }
                try { channel.IncomingData.CompleteAdding(); } catch { }

                // Send close response
                if (channel.RemoteId != 0)
                {
                    byte[] closePayload = new byte[1 + 4];
                    closePayload[0] = SshMsg.SSH_MSG_CHANNEL_CLOSE;
                    byte[] rid = SshWire.EncodeUint32(channel.RemoteId);
                    Buffer.BlockCopy(rid, 0, closePayload, 1, 4);
                    Task unused = _transport.SendPacketAsync(closePayload);
                }
            }
        }

        private void HandleWindowAdjust(byte[] payload)
        {
            int offset = 1;
            uint recipientChannel = SshWire.ReadUint32(payload, ref offset);
            uint bytesToAdd = SshWire.ReadUint32(payload, ref offset);

            SshChannel channel = FindChannel(recipientChannel);
            if (channel != null)
            {
                lock (channel.SyncRoot)
                {
                    ulong newWindow = (ulong)channel.RemoteWindow + bytesToAdd;
                    channel.RemoteWindow = newWindow > uint.MaxValue ? uint.MaxValue : (uint)newWindow;
                    if (channel.WindowAdjustTcs != null)
                        channel.WindowAdjustTcs.TrySetResult(true);
                }
            }
        }

        private void HandleChannelRequest(byte[] payload)
        {
            try
            {
                int offset = 1;
                uint recipientChannel = SshWire.ReadUint32(payload, ref offset);
                string requestType = SshWire.ReadString(payload, ref offset);
                bool wantReply = (payload[offset++] == 1);

                byte[] requestData = null;
                if (offset < payload.Length)
                {
                    requestData = new byte[payload.Length - offset];
                    Buffer.BlockCopy(payload, offset, requestData, 0, requestData.Length);
                }

                var handler = IncomingChannelRequest;
                if (handler != null)
                {
                    handler(recipientChannel, requestType, requestData, wantReply);
                }
            }
            catch (Exception ex)
            {
                Logger.Debug("Error handling channel request: " + ex.Message);
            }
        }

        /// <summary>
        /// Send SSH_MSG_CHANNEL_SUCCESS for a channel request.
        /// </summary>
        public async Task SendChannelRequestSuccessAsync(uint localChannelId)
        {
            SshChannel channel = FindChannel(localChannelId);
            if (channel == null) return;

            byte[] payload = new byte[1 + 4];
            payload[0] = SshMsg.SSH_MSG_CHANNEL_SUCCESS;
            byte[] rid = SshWire.EncodeUint32(channel.RemoteId);
            Buffer.BlockCopy(rid, 0, payload, 1, 4);
            await _transport.SendPacketAsync(payload);
        }

        /// <summary>
        /// Send SSH_MSG_CHANNEL_FAILURE for a channel request.
        /// </summary>
        public async Task SendChannelRequestFailureAsync(uint localChannelId)
        {
            SshChannel channel = FindChannel(localChannelId);
            if (channel == null) return;

            byte[] payload = new byte[1 + 4];
            payload[0] = SshMsg.SSH_MSG_CHANNEL_FAILURE;
            byte[] rid = SshWire.EncodeUint32(channel.RemoteId);
            Buffer.BlockCopy(rid, 0, payload, 1, 4);
            await _transport.SendPacketAsync(payload);
        }

        // ===================== Helpers =====================

        private async Task<int> ReserveSendWindowAsync(SshChannel channel, int desiredBytes)
        {
            while (true)
            {
                Task waitTask = null;
                lock (channel.SyncRoot)
                {
                    if (!channel.IsOpen)
                        throw new InvalidOperationException("Channel " + channel.LocalId + " is not open");

                    uint maxPacket = channel.RemoteMaxPacket > 0
                        ? channel.RemoteMaxPacket
                        : SshChannel.DefaultMaxPacket;
                    uint allowed = channel.RemoteWindow < maxPacket
                        ? channel.RemoteWindow
                        : maxPacket;

                    if (allowed > 0)
                    {
                        int allowedInt = allowed > int.MaxValue ? int.MaxValue : (int)allowed;
                        int chunk = desiredBytes < allowedInt ? desiredBytes : allowedInt;
                        channel.RemoteWindow -= (uint)chunk;
                        return chunk;
                    }

                    if (channel.WindowAdjustTcs == null || channel.WindowAdjustTcs.Task.IsCompleted)
                        channel.WindowAdjustTcs = new TaskCompletionSource<bool>();
                    waitTask = channel.WindowAdjustTcs.Task;
                }

                await waitTask;
            }
        }

        private void AdjustLocalWindow(SshChannel channel, int bytesConsumed)
        {
            if (channel == null || bytesConsumed <= 0)
                return;

            bool shouldSend = false;
            lock (channel.SyncRoot)
            {
                if (channel.RemoteId == 0)
                    return;

                ulong newWindow = (ulong)channel.LocalWindow + (uint)bytesConsumed;
                channel.LocalWindow = newWindow > uint.MaxValue ? uint.MaxValue : (uint)newWindow;
                shouldSend = channel.IsOpen;
            }

            if (shouldSend)
            {
                Task unused = SendChannelWindowAdjustAsync(channel, (uint)bytesConsumed);
            }
        }

        private async Task SendChannelWindowAdjustAsync(SshChannel channel, uint bytesToAdd)
        {
            if (channel == null || bytesToAdd == 0)
                return;

            uint remoteId;
            lock (channel.SyncRoot)
            {
                if (channel.RemoteId == 0)
                    return;
                remoteId = channel.RemoteId;
            }

            byte[] payload = new byte[1 + 4 + 4];
            payload[0] = SshMsg.SSH_MSG_CHANNEL_WINDOW_ADJUST;
            byte[] rid = SshWire.EncodeUint32(remoteId);
            Buffer.BlockCopy(rid, 0, payload, 1, 4);
            byte[] add = SshWire.EncodeUint32(bytesToAdd);
            Buffer.BlockCopy(add, 0, payload, 5, 4);
            await _transport.SendPacketAsync(payload);
        }

        private void RemoveChannel(uint localId)
        {
            SshChannel channel;
            lock (_channelsLock)
            {
                _channels.TryGetValue(localId, out channel);
                _channels.Remove(localId);
            }

            if (channel == null)
                return;

            lock (channel.SyncRoot)
            {
                channel.IsOpen = false;
                if (channel.WindowAdjustTcs != null)
                    channel.WindowAdjustTcs.TrySetResult(true);
            }
            try { channel.IncomingData.CompleteAdding(); } catch { }
        }

        private static byte[] BuildChannelOpenConfirm(uint recipientChannel, uint senderChannel,
                                                       uint windowSize, uint maxPacket)
        {
            byte[] payload = new byte[1 + 4 + 4 + 4 + 4];
            payload[0] = SshMsg.SSH_MSG_CHANNEL_OPEN_CONFIRMATION;
            int offset = 1;

            byte[] rc = SshWire.EncodeUint32(recipientChannel);
            Buffer.BlockCopy(rc, 0, payload, offset, 4); offset += 4;

            byte[] sc = SshWire.EncodeUint32(senderChannel);
            Buffer.BlockCopy(sc, 0, payload, offset, 4); offset += 4;

            byte[] ws = SshWire.EncodeUint32(windowSize);
            Buffer.BlockCopy(ws, 0, payload, offset, 4); offset += 4;

            byte[] mp = SshWire.EncodeUint32(maxPacket);
            Buffer.BlockCopy(mp, 0, payload, offset, 4); offset += 4;

            return payload;
        }

        private SshChannel FindChannel(uint localId)
        {
            lock (_channelsLock)
            {
                SshChannel ch;
                _channels.TryGetValue(localId, out ch);
                return ch;
            }
        }

        // ===================== IDisposable =====================

        public void Dispose()
        {
            if (!_disposed)
            {
                _disposed = true;
                if (_readLoopCts != null)
                {
                    _readLoopCts.Cancel();
                    _readLoopCts.Dispose();
                    _readLoopCts = null;
                }
                IsClosed = true;

                lock (_channelsLock)
                {
                    foreach (var ch in _channels.Values)
                    {
                        ch.IsOpen = false;
                        try { ch.IncomingData.CompleteAdding(); } catch { }
                    }
                    _channels.Clear();
                }
            }
        }
    }
}
