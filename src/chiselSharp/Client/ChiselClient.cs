using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using ChiselSharp.Settings;
using ChiselSharp.SSH;
using ChiselSharp.Transport;
using ChiselSharp.Utils;

namespace ChiselSharp.Client
{
    public class ChiselClient
    {
        private readonly Config _config;
        private WebSocketFrameStream _webSocketStream;
        private SshTransport _sshTransport;
        private SshConnection _sshConn;
        private CancellationTokenSource _cts;
        private readonly List<RemoteSpec> _parsedRemotes;
        private bool _running;
        private Backoff _backoff;
        private readonly Dictionary<int, TcpListener> _listeners = new Dictionary<int, TcpListener>();
        private readonly object _listenersLock = new object();
        private const int PipeDrainTimeoutMs = 2000;
        private const int MaxConcurrentForwardChannels = 32;
        private readonly AsyncLimiter _forwardChannelLimiter =
            new AsyncLimiter(MaxConcurrentForwardChannels);

        // Raw WebSocket stream for SSH transport.

        public ChiselClient(Config config)
        {
            _config = config;
            _parsedRemotes = new List<RemoteSpec>();
            foreach (string raw in _config.Remotes)
            {
                var spec = RemoteParser.Parse(raw);
                if (spec != null) _parsedRemotes.Add(spec);
                else Logger.Warn("Invalid remote: " + raw);
            }
            _backoff = new Backoff(TimeSpan.FromMilliseconds(100), _config.MaxRetryInterval, _config.MaxRetryCount);
        }

        public async Task RunAsync()
        {
            _running = true;
            _cts = new CancellationTokenSource();
            Logger.Info("chiselSharp client (C# port of chisel)");

            while (_running && !_cts.Token.IsCancellationRequested)
            {
                try { await ConnectAndServeAsync(); _backoff.Reset(); }
                catch (Exception ex) { Logger.Debug("Connection error: " + ex.Message); }

                if (!_running || _cts.Token.IsCancellationRequested) break;
                TimeSpan? delay = _backoff.NextDelay();
                if (!delay.HasValue) { Logger.Info("Max retry count reached."); break; }
                Logger.Info("Reconnecting in " + delay.Value.TotalSeconds.ToString("F1") + "s...");
                try { await Compat.Delay(delay.Value, _cts.Token); } catch (TaskCanceledException) { break; }
            }
        }

        private async Task ConnectAndServeAsync()
        {
            CleanupConnection();

            // 1. WebSocket connect with "chisel-v3" subprotocol
            if (_config.TlsSkipVerify)
                ServicePointManager.ServerCertificateValidationCallback = (s, c, ch, e) => true;

            string serverUrl = _config.ServerUrl;
            if (!serverUrl.StartsWith("ws://") && !serverUrl.StartsWith("wss://"))
            {
                if (serverUrl.StartsWith("https://")) serverUrl = "wss://" + serverUrl.Substring(8);
                else if (serverUrl.StartsWith("http://")) serverUrl = "ws://" + serverUrl.Substring(7);
                else serverUrl = "ws://" + serverUrl;
            }

            Logger.Debug("Connecting to " + serverUrl);
            _webSocketStream = await WebSocketFrameStream.ConnectAsync(
                new Uri(serverUrl),
                _config.Headers,
                "chisel-v3",
                _config.TlsSkipVerify);

            // 2. SSH handshake over raw WebSocket (one msg = one SSH packet)
            _sshTransport = new SshTransport(_webSocketStream);
            await _sshTransport.HandshakeAsync();

            string fingerprint = _sshTransport.ServerHostKey != null ? _sshTransport.ServerHostKey.Fingerprint : null;
            Logger.Debug("Server fingerprint: " + fingerprint);

            if (!string.IsNullOrEmpty(_config.Fingerprint) && _config.Fingerprint != fingerprint)
                throw new Exception("Fingerprint mismatch! Expected " + _config.Fingerprint + ", got " + fingerprint);

            // 3. SSH authentication
            _sshConn = new SshConnection(_sshTransport);

            string au = "", ap = "";
            if (!string.IsNullOrEmpty(_config.Auth))
            {
                string[] p = _config.Auth.Split(new[] { ':' }, 2);
                au = p[0]; ap = p.Length > 1 ? p[1] : "";
            }
            await _sshConn.AuthenticateAsync(au, ap);
            Logger.Debug("SSH authenticated");

            // 4. Send native chisel configuration as a global SSH request.
            _sshConn.IncomingChannelOpen += OnIncomingChannel;
            await _sshConn.SendGlobalRequestAsync("config", true, BuildNativeConfigPayload());
            _sshConn.StartReadLoop();

            // 5. Set up tunnels

            foreach (var spec in _parsedRemotes)
            {
                if (spec.IsReverse)
                {
                    Logger.Info("Reverse tunnel ready: " + spec);
                }
                else if (!spec.IsStdio)
                {
                    StartForwardListener(spec);
                }
            }

            Logger.Info("Connected to " + serverUrl);

            while (_running && !_cts.Token.IsCancellationRequested &&
                   _webSocketStream != null &&
                   _webSocketStream.IsOpen)
            {
                await Compat.Delay(500);
            }
        }

        private byte[] BuildNativeConfigPayload()
        {
            var config = Json.NewObject();
            var remotes = Json.NewArray();

            config["Version"] = "1.10.1";
            foreach (var spec in _parsedRemotes)
                remotes.Add(BuildNativeRemote(spec));
            config["Remotes"] = remotes;

            return Encoding.UTF8.GetBytes(Json.Serialize(config));
        }

        private Dictionary<string, object> BuildNativeRemote(RemoteSpec spec)
        {
            var remote = Json.NewObject();
            bool udp = spec.Protocol == TunnelProtocol.UDP;
            string proto = udp ? "udp" : "tcp";

            string localHost = spec.LocalHost ?? "";
            int localPort = spec.LocalPort;
            if (spec.IsSocks)
            {
                if (string.IsNullOrEmpty(localHost) || localHost == "0.0.0.0")
                    localHost = "127.0.0.1";
                if (localPort <= 0)
                    localPort = 1080;
            }
            else if (!spec.IsStdio && string.IsNullOrEmpty(localHost))
            {
                localHost = "0.0.0.0";
            }

            remote["LocalHost"] = spec.IsStdio ? "" : localHost;
            remote["LocalPort"] = spec.IsStdio || localPort <= 0 ? "" : localPort.ToString();
            remote["LocalProto"] = proto;
            remote["RemoteHost"] = spec.IsSocks ? "" : (spec.RemoteHost ?? "127.0.0.1");
            remote["RemotePort"] = spec.IsSocks || spec.RemotePort <= 0 ? "" : spec.RemotePort.ToString();
            remote["RemoteProto"] = proto;
            remote["Socks"] = spec.IsSocks;
            remote["Reverse"] = spec.IsReverse;
            remote["Stdio"] = spec.IsStdio;

            return remote;
        }

        private void OnIncomingChannel(uint localChannelId, string channelType, byte[] payload)
        {
            if (channelType == "chisel")
            {
                string remote = payload != null ? Encoding.UTF8.GetString(payload) : "";
                if (remote == "socks")
                {
                    Logger.Debug("Reverse SOCKS channel");
                    Task unused = HandleSocksChannel(localChannelId);
                    return;
                }

                string targetHost;
                int targetPort;
                if (TryParseHostPort(remote, out targetHost, out targetPort))
                {
                    Logger.Debug("Reverse channel: " + targetHost + ":" + targetPort);
                    Task unused = HandleReverseChannelAsync(localChannelId, targetHost, targetPort);
                }
                else
                {
                    Logger.Debug("Unsupported chisel channel target: " + remote);
                    Task unused = _sshConn.CloseChannelAsync(localChannelId);
                }
            }
            else if (channelType == "forwarded-tcpip" || channelType == "direct-tcpip")
            {
                int offset = 0;
                string targetHost = SshWire.ReadString(payload, ref offset);
                uint targetPort = SshWire.ReadUint32(payload, ref offset);
                Logger.Debug("Reverse channel: " + targetHost + ":" + targetPort);
                Task unused = HandleReverseChannelAsync(localChannelId, targetHost, (int)targetPort);
            }
        }

        private async Task HandleReverseChannelAsync(uint channelId, string host, int port)
        {
            uint closeError = 0;
            try
            {
                var client = new TcpClient();
                client.NoDelay = true;
                await Compat.ConnectTcpAsync(client, host, port);
                var ns = client.GetStream();
                await PipeSshToTcp(channelId, ns);
                try { client.Close(); } catch { }
            }
            catch (Exception ex)
            {
                Logger.Debug("Reverse channel error: " + ex.Message);
                closeError = channelId;
            }
            if (closeError > 0)
                try { await _sshConn.CloseChannelAsync(closeError); } catch { }
        }

        private void StartForwardListener(RemoteSpec spec)
        {
            try
            {
                var listener = new TcpListener(IPAddress.Any, spec.LocalPort);
                listener.Start(1024);
                lock (_listenersLock) { _listeners[spec.LocalPort] = listener; }
                Logger.Info("Forward: " + spec.LocalHost + ":" + spec.LocalPort + " -> " + spec.RemoteHost + ":" + spec.RemotePort);
                Task unused = AcceptForwardLoop(listener, spec);
            }
            catch (SocketException ex)
            {
                if (ex.SocketErrorCode == SocketError.AddressAlreadyInUse)
                {
                    spec.LocalPort++;
                    StartForwardListener(spec);
                }
                else throw;
            }
        }

        private async Task AcceptForwardLoop(TcpListener listener, RemoteSpec spec)
        {
            while (_running && !_cts.Token.IsCancellationRequested)
            {
                try
                {
                    var tcpClient = await Compat.AcceptTcpClientAsync(listener);
                    tcpClient.NoDelay = true;
                    Logger.Debug("Accepted local forward connection for " + spec);
                    Task unused = HandleForwardConnectionAsync(tcpClient, spec);
                }
                catch (ObjectDisposedException) { break; }
                catch (Exception ex) { Logger.Debug("Accept error: " + ex.Message); }
            }
        }

        private async Task HandleForwardConnectionAsync(TcpClient tcpClient, RemoteSpec spec)
        {
            IDisposable permit = null;
            try
            {
                permit = await _forwardChannelLimiter.EnterAsync();
                Logger.Debug("Opening chisel channel for " + spec);
                uint channelId = await _sshConn.OpenChiselAsync(BuildChiselRemote(spec));
                Logger.Debug("Chisel channel opened: " + channelId);
                var ns = tcpClient.GetStream();
                await PipeSshToTcp(channelId, ns);
            }
            catch (Exception ex) { Logger.Debug("Forward conn error: " + ex.Message); }
            finally
            {
                if (permit != null)
                    permit.Dispose();
                try { tcpClient.Close(); } catch { }
            }
        }

        private static string BuildChiselRemote(RemoteSpec spec)
        {
            if (spec.IsSocks)
                return "socks";

            string remote = (spec.RemoteHost ?? "127.0.0.1") + ":" + spec.RemotePort;
            if (spec.Protocol == TunnelProtocol.UDP)
                remote += "/udp";
            return remote;
        }

        private static bool TryParseHostPort(string remote, out string host, out int port)
        {
            host = null;
            port = 0;
            if (string.IsNullOrEmpty(remote))
                return false;

            if (remote.EndsWith("/udp", StringComparison.OrdinalIgnoreCase) ||
                remote.EndsWith("/tcp", StringComparison.OrdinalIgnoreCase))
            {
                remote = remote.Substring(0, remote.Length - 4);
            }

            int colon = remote.LastIndexOf(':');
            if (colon <= 0 || colon >= remote.Length - 1)
                return false;

            int parsedPort;
            if (!int.TryParse(remote.Substring(colon + 1), out parsedPort))
                return false;

            host = remote.Substring(0, colon);
            port = parsedPort;
            return true;
        }

        private async Task HandleSocksChannel(uint channelId)
        {
            TcpClient tcpClient = null;
            ChannelStream channelStream = null;
            bool sendFailureReply = false;

            try
            {
                channelStream = new ChannelStream(_sshConn, channelId);
                SocksConnectRequest request = await ReadSocksConnectRequest(channelStream);
                if (request != null)
                {
                    tcpClient = new TcpClient();
                    tcpClient.NoDelay = true;
                    await Compat.ConnectTcpAsync(tcpClient, request.Host, request.Port);
                    await WriteSocksReply(channelStream, 0);

                    NetworkStream tcpStream = tcpClient.GetStream();
                    Task fromChannel = PipeStreamToTcp(channelStream, tcpStream);
                    Task fromTcp = PipeTcpToSsh(tcpStream, channelId);
                    await WaitForPipeTasks(fromChannel, fromTcp, delegate { try { tcpStream.Close(); } catch { } });
                }
            }
            catch (Exception ex)
            {
                Logger.Debug("SOCKS channel error: " + ex.Message);
                sendFailureReply = channelStream != null;
            }

            if (sendFailureReply)
            {
                try { await WriteSocksReply(channelStream, 5); } catch { }
            }

            if (tcpClient != null)
            {
                try { tcpClient.Close(); } catch { }
            }
            if (channelStream != null)
            {
                try { channelStream.Dispose(); } catch { }
            }
            if (_sshConn != null)
            {
                try { await _sshConn.CloseChannelAsync(channelId); } catch { }
            }
        }

        private async Task<SocksConnectRequest> ReadSocksConnectRequest(Stream stream)
        {
            byte[] header = new byte[2];
            if (!await ReadExactAsync(stream, header, 0, header.Length))
                return null;
            if (header[0] != 5)
                return null;

            byte[] methods = new byte[header[1]];
            if (!await ReadExactAsync(stream, methods, 0, methods.Length))
                return null;
            await stream.WriteAsync(new byte[] { 5, 0 }, 0, 2);

            byte[] req = new byte[4];
            if (!await ReadExactAsync(stream, req, 0, req.Length))
                return null;
            if (req[0] != 5 || req[1] != 1)
            {
                await WriteSocksReply(stream, 7);
                return null;
            }

            string host;
            if (req[3] == 1)
            {
                byte[] addr = new byte[4];
                if (!await ReadExactAsync(stream, addr, 0, addr.Length))
                    return null;
                host = new IPAddress(addr).ToString();
            }
            else if (req[3] == 3)
            {
                byte[] len = new byte[1];
                if (!await ReadExactAsync(stream, len, 0, 1))
                    return null;
                byte[] name = new byte[len[0]];
                if (!await ReadExactAsync(stream, name, 0, name.Length))
                    return null;
                host = Encoding.ASCII.GetString(name);
            }
            else if (req[3] == 4)
            {
                byte[] addr = new byte[16];
                if (!await ReadExactAsync(stream, addr, 0, addr.Length))
                    return null;
                host = new IPAddress(addr).ToString();
            }
            else
            {
                await WriteSocksReply(stream, 8);
                return null;
            }

            byte[] portBytes = new byte[2];
            if (!await ReadExactAsync(stream, portBytes, 0, portBytes.Length))
                return null;

            return new SocksConnectRequest
            {
                Host = host,
                Port = (portBytes[0] << 8) | portBytes[1]
            };
        }

        private static async Task WriteSocksReply(Stream stream, byte reply)
        {
            byte[] response = new byte[] { 5, reply, 0, 1, 0, 0, 0, 0, 0, 0 };
            await stream.WriteAsync(response, 0, response.Length);
        }

        private static async Task<bool> ReadExactAsync(Stream stream, byte[] buffer, int offset, int count)
        {
            int total = 0;
            while (total < count)
            {
                int read = await stream.ReadAsync(buffer, offset + total, count - total);
                if (read == 0)
                    return false;
                total += read;
            }
            return true;
        }

        private async Task PipeStreamToTcp(Stream source, NetworkStream dest)
        {
            byte[] buf = new byte[32768];
            try
            {
                while (true)
                {
                    int read = await source.ReadAsync(buf, 0, buf.Length);
                    if (read == 0)
                        break;
                    await dest.WriteAsync(buf, 0, read);
                }
            }
            catch
            {
                // Connection closed or error
            }
        }

        private async Task PipeTcpToSsh(NetworkStream stream, uint channelId)
        {
            byte[] buf = new byte[32768];
            try
            {
                while (true)
                {
                    int read = await stream.ReadAsync(buf, 0, buf.Length);
                    if (read == 0)
                        break;
                    await _sshConn.SendChannelDataAsync(channelId, buf, 0, read);
                }
            }
            catch
            {
                // Connection closed or error
            }

            try { await _sshConn.SendChannelEofAsync(channelId); } catch { }
        }

        private class SocksConnectRequest
        {
            public string Host;
            public int Port;
        }

        private async Task PipeSshToTcp(uint channelId, NetworkStream tcpStream)
        {
            Task readTask = PipeChannelToTcp(channelId, tcpStream);
            Task writeTask = PipeTcpToSsh(tcpStream, channelId);
            await WaitForPipeTasks(readTask, writeTask, delegate { try { tcpStream.Close(); } catch { } });
            try { await _sshConn.CloseChannelAsync(channelId); } catch { }
        }

        private async Task PipeChannelToTcp(uint channelId, NetworkStream tcpStream)
        {
            try
            {
                while (true)
                {
                    byte[] data = await _sshConn.ReceiveChannelDataAsync(channelId);
                    if (data == null)
                        break;
                    await tcpStream.WriteAsync(data, 0, data.Length);
                }
            }
            catch
            {
                // Connection closed or error
            }
        }

        private static async Task WaitForPipeTasks(Task first, Task second)
        {
            await WaitForPipeTasks(first, second, null);
        }

        private static async Task WaitForPipeTasks(Task first, Task second, Action closeTransport)
        {
            Task all = Compat.WhenAll(first, second);
            await Compat.WhenAny(first, second);
            if (closeTransport != null)
                closeTransport();

            Task done = await Compat.WhenAny(all, Compat.Delay(PipeDrainTimeoutMs));
            if (done == all)
            {
                try { await all; } catch { }
            }
        }

        private class ChannelStream : Stream, IAsyncCompatStream
        {
            private readonly SshConnection _connection;
            private readonly uint _channelId;
            private byte[] _buffer;
            private int _bufferOffset;
            private bool _disposed;

            public ChannelStream(SshConnection connection, uint channelId)
            {
                _connection = connection;
                _channelId = channelId;
            }

            public override bool CanRead { get { return true; } }
            public override bool CanWrite { get { return true; } }
            public override bool CanSeek { get { return false; } }
            public override long Length { get { throw new NotSupportedException(); } }
            public override long Position
            {
                get { throw new NotSupportedException(); }
                set { throw new NotSupportedException(); }
            }

            public override int Read(byte[] buffer, int offset, int count)
            {
                if (_disposed)
                    return 0;

                if (_buffer != null && _bufferOffset < _buffer.Length)
                {
                    int available = _buffer.Length - _bufferOffset;
                    int copy = count < available ? count : available;
                    Buffer.BlockCopy(_buffer, _bufferOffset, buffer, offset, copy);
                    _bufferOffset += copy;
                    if (_bufferOffset >= _buffer.Length)
                    {
                        _buffer = null;
                        _bufferOffset = 0;
                    }
                    return copy;
                }

                byte[] data = _connection.ReceiveChannelData(_channelId);
                if (data == null || data.Length == 0)
                    return 0;

                int toCopy = count < data.Length ? count : data.Length;
                Buffer.BlockCopy(data, 0, buffer, offset, toCopy);
                if (toCopy < data.Length)
                {
                    _buffer = data;
                    _bufferOffset = toCopy;
                }
                return toCopy;
            }

#if NET40
            public Task<int> ReadAsync(byte[] buffer, int offset, int count, System.Threading.CancellationToken cancellationToken)
#else
            public override Task<int> ReadAsync(byte[] buffer, int offset, int count, System.Threading.CancellationToken cancellationToken)
#endif
            {
                return ReadAsyncCore(buffer, offset, count);
            }

            private async Task<int> ReadAsyncCore(byte[] buffer, int offset, int count)
            {
                if (_disposed)
                    return 0;

                if (_buffer != null && _bufferOffset < _buffer.Length)
                    return Read(buffer, offset, count);

                byte[] data = await _connection.ReceiveChannelDataAsync(_channelId);
                if (data == null || data.Length == 0)
                    return 0;

                int toCopy = count < data.Length ? count : data.Length;
                Buffer.BlockCopy(data, 0, buffer, offset, toCopy);
                if (toCopy < data.Length)
                {
                    _buffer = data;
                    _bufferOffset = toCopy;
                }
                return toCopy;
            }

            public override void Write(byte[] buffer, int offset, int count)
            {
                WriteAsync(buffer, offset, count, System.Threading.CancellationToken.None).GetAwaiter().GetResult();
            }

#if NET40
            public Task WriteAsync(byte[] buffer, int offset, int count, System.Threading.CancellationToken cancellationToken)
#else
            public override Task WriteAsync(byte[] buffer, int offset, int count, System.Threading.CancellationToken cancellationToken)
#endif
            {
                return _connection.SendChannelDataAsync(_channelId, buffer, offset, count);
            }

            public override void Flush() { }

#if NET40
            public Task FlushAsync(System.Threading.CancellationToken cancellationToken) { return Compat.FromResult(); }
#else
            public override Task FlushAsync(System.Threading.CancellationToken cancellationToken) { return Compat.FromResult(); }
#endif

            public Task<int> ReadAsyncCompat(byte[] buffer, int offset, int count, System.Threading.CancellationToken cancellationToken)
            {
                return ReadAsync(buffer, offset, count, cancellationToken);
            }

            public Task WriteAsyncCompat(byte[] buffer, int offset, int count, System.Threading.CancellationToken cancellationToken)
            {
                return WriteAsync(buffer, offset, count, cancellationToken);
            }

            public Task FlushAsyncCompat(System.Threading.CancellationToken cancellationToken)
            {
                return Compat.FromResult();
            }

            public override long Seek(long offset, SeekOrigin origin) { throw new NotSupportedException(); }
            public override void SetLength(long value) { throw new NotSupportedException(); }

            protected override void Dispose(bool disposing)
            {
                _disposed = true;
                _buffer = null;
                base.Dispose(disposing);
            }
        }

        private sealed class AsyncLimiter
        {
            private readonly object _syncRoot = new object();
            private readonly Queue<TaskCompletionSource<IDisposable>> _waiters =
                new Queue<TaskCompletionSource<IDisposable>>();
            private int _available;

            public AsyncLimiter(int limit)
            {
                _available = limit;
            }

            public Task<IDisposable> EnterAsync()
            {
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

        private void CleanupConnection()
        {
            lock (_listenersLock)
            {
                foreach (var kvp in _listeners) try { kvp.Value.Stop(); } catch { }
                _listeners.Clear();
            }
            if (_sshConn != null) { try { _sshConn.Dispose(); } catch { } _sshConn = null; }
            if (_sshTransport != null) { try { _sshTransport.Dispose(); } catch { } _sshTransport = null; }
            if (_webSocketStream != null) { try { _webSocketStream.Dispose(); } catch { } _webSocketStream = null; }
        }

        public void Stop()
        {
            _running = false;
            if (_cts != null) { _cts.Cancel(); _cts.Dispose(); _cts = null; }
            CleanupConnection();
        }
    }

}
