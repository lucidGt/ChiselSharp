using System;
using System.Net;
using System.Net.Sockets;
using System.Threading.Tasks;
using ChiselSharp.Protocol;
using ChiselSharp.Settings;
using ChiselSharp.Utils;

namespace ChiselSharp.Tunnels
{
    public class TcpTunnel : IDisposable
    {
        private readonly Multiplexer _mux;
        private readonly RemoteSpec _spec;
        private readonly bool _isServer;
        private readonly bool _isReverse;
        private TcpListener _listener;
        private bool _disposed;

        public TcpTunnel(Multiplexer mux, RemoteSpec spec, bool isServer, bool isReverse)
        {
            _mux = mux;
            _spec = spec;
            _isServer = isServer;
            _isReverse = isReverse;
        }

        /// <summary>
        /// Start the tunnel. Behavior depends on mode:
        ///
        /// Forward tunnel (3000:google.com:80):
        ///   - Client (shouldListen=true):  listens on localhost:3000, accepts TCP connections,
        ///                                   opens channels, sends SYN frames to server
        ///   - Server (shouldListen=false): waits for SYN frames, connects to google.com:80,
        ///                                   sends ACK, pipes data
        ///
        /// Reverse tunnel (R:2222:localhost:22):
        ///   - Server (shouldListen=true):  listens on :2222, accepts TCP connections,
        ///                                   opens channels, sends SYN frames to client
        ///   - Client (shouldListen=false): waits for SYN frames, connects to localhost:22,
        ///                                   sends ACK, pipes data
        /// </summary>
        public async Task StartAsync()
        {
            bool shouldListen = false;

            if (_isServer && _isReverse)
                shouldListen = true;  // Server listens for reverse tunnels
            else if (!_isServer && !_isReverse)
                shouldListen = true;  // Client listens for forward tunnels
            else
                shouldListen = false; // Connecting side: wait for SYN frames

            if (shouldListen)
            {
                // LISTEN side: accept TCP connections, open channels, send SYN per connection
                await StartListening();
            }
            else
            {
                // CONNECT side: subscribe to FrameReceived, wait for SYN frames from peer
                _mux.FrameReceived += OnFrameReceived;
                Logger.Debug("TcpTunnel waiting for SYN frames: " + _spec.RemoteHost + ":" + _spec.RemotePort);
            }
        }

        private void OnFrameReceived(uint channelId, Frame frame)
        {
            // Multiplexer only fires FrameReceived for SYN frames, but check anyway for safety
            if ((frame.Flags & FrameFlags.SYN) != 0)
            {
                var json = frame.GetJsonPayload();
                if (json == null) return;

                try
                {
                    var payload = Json.Parse(json);
                    string type = Json.GetString(payload, "type");

                    if (type == "tcp")
                    {
                        string remoteHost = Json.GetString(payload, "remoteHost");
                        int remotePort = Json.GetInt(payload, "remotePort", 0);

                        // Filter: only process SYNs that match this tunnel's target host:port.
                        // Without this check, ALL tunnels would try to handle every TCP SYN frame.
                        if (remoteHost == _spec.RemoteHost && remotePort == _spec.RemotePort)
                        {
                            Logger.Debug("Received TCP SYN for " + remoteHost + ":" + remotePort + " on channel " + channelId);

                            // Register the incoming channel locally so DATA frames are routed correctly
                            var channel = _mux.AcceptChannel(channelId);

                            // Connect to destination, send ACK, and pipe data
                            Task unused = HandleChannelAsync(channel, remoteHost, remotePort);
                        }
                    }
                }
                catch (Exception ex)
                {
                    Logger.Debug("SYN handling error: " + ex.Message);
                }
            }
        }

        private Task StartListening()
        {
            string localHost = _spec.LocalHost;
            int port = _spec.LocalPort;

            IPAddress bindAddress;
            if (!IPAddress.TryParse(localHost, out bindAddress))
            {
                bindAddress = IPAddress.Any;
            }

            try
            {
                _listener = new TcpListener(bindAddress, port);
                _listener.Start(1024);
                Logger.Info("TcpTunnel listening on " + bindAddress + ":" + port);

                Task unused = AcceptLoop();
            }
            catch (SocketException ex)
            {
                if (ex.SocketErrorCode == SocketError.AddressAlreadyInUse)
                {
                    Logger.Warn("Port " + port + " already in use, trying next port...");
                    port++;
                    _listener = new TcpListener(bindAddress, port);
                    _listener.Start(1024);
                    Task unused = AcceptLoop();
                    Logger.Info("Using port " + port + " instead");
                }
                else
                {
                    throw;
                }
            }

            return Compat.FromResult();
        }

        private async Task AcceptLoop()
        {
            while (!_disposed)
            {
                try
                {
                    // AcceptTcpClientAsync is not available in .NET 4.5, so use Task.Run
                    var client = await Compat.Run(() => _listener.AcceptTcpClient());
                    Logger.Debug("Accepted new TCP connection on " + _spec.LocalHost + ":" + _spec.LocalPort);
                    Task unused = HandleClientAsync(client);
                }
                catch (ObjectDisposedException) { break; }
                catch (Exception ex)
                {
                    Logger.Debug("Accept error: " + ex.Message);
                }
            }
        }

        /// <summary>
        /// Called on the LISTEN side when a new TCP client connects to the local port.
        /// Opens a new channel, sends SYN with destination info, waits for ACK, then pipes data.
        /// Each TCP connection gets its own channel.
        /// </summary>
        private async Task HandleClientAsync(TcpClient client)
        {
            try
            {
                // Open a new channel for this connection
                var channel = _mux.OpenChannel();

                // Send SYN with destination info so the peer knows where to connect
                var synPayload = Json.NewObject();
                synPayload["type"] = "tcp";
                synPayload["remoteHost"] = _spec.RemoteHost;
                synPayload["remotePort"] = _spec.RemotePort;
                synPayload["isReverse"] = _spec.IsReverse;

                await _mux.SendFrameAsync(Frame.CreateSyn(channel.Id, Json.Serialize(synPayload)));

                // Wait for ACK from peer indicating the channel is ready
                await channel.WaitForOpen();

                // Bidirectional pipe: TCP client <-> channel
                var clientStream = client.GetStream();
                var task1 = PipeClientToChannel(clientStream, channel);
                var task2 = PipeChannelToClient(channel, clientStream);

                await Compat.WhenAny(task1, task2);
            }
            catch (Exception ex)
            {
                Logger.Debug("Client handler error: " + ex.Message);
            }
            finally
            {
                try { client.Close(); } catch { }
            }
        }

        /// <summary>
        /// Called on the CONNECT side when a SYN frame arrives from the peer.
        /// Connects to the target host:port, sends ACK, then pipes data.
        /// </summary>
        private async Task HandleChannelAsync(Channel channel, string remoteHost, int remotePort)
        {
            TcpClient tcpClient = null;
            try
            {
                // Connect to the actual destination
                tcpClient = new TcpClient();
                await Compat.Run(() => tcpClient.Connect(remoteHost, remotePort));
                Logger.Debug("Connected to target " + remoteHost + ":" + remotePort);

                // Send ACK to signal the peer that the channel is accepted and ready
                await _mux.SendFrameAsync(Frame.CreateAck(channel.Id));

                // Bidirectional pipe: target TCP <-> channel
                var stream = tcpClient.GetStream();
                var task1 = PipeClientToChannel(stream, channel);
                var task2 = PipeChannelToClient(channel, stream);

                await Compat.WhenAny(task1, task2);
            }
            catch (Exception ex)
            {
                Logger.Debug("Channel handler error: " + ex.Message);
            }
            finally
            {
                if (tcpClient != null)
                {
                    try { tcpClient.Close(); } catch { }
                }
            }
        }

        private async Task PipeClientToChannel(NetworkStream stream, Channel channel)
        {
            byte[] buf = new byte[8192];
            try
            {
                while (true)
                {
                    int read = await stream.ReadAsync(buf, 0, buf.Length);
                    if (read == 0) break;

                    byte[] data = new byte[read];
                    Buffer.BlockCopy(buf, 0, data, 0, read);
                    await channel.SendAsync(data);
                }
            }
            catch { }

            // Close channel after local read completes (outside finally for C# 5.0 compat -
            // cannot await in catch/finally blocks)
            try { await channel.CloseAsync(); } catch { }
        }

        private async Task PipeChannelToClient(Channel channel, NetworkStream stream)
        {
            try
            {
                while (true)
                {
                    byte[] data = channel.Receive();
                    if (data == null) break;
                    await stream.WriteAsync(data, 0, data.Length);
                }
            }
            catch { }
        }

        public void Dispose()
        {
            if (!_disposed)
            {
                _disposed = true;
                _mux.FrameReceived -= OnFrameReceived;

                try { if (_listener != null) _listener.Stop(); } catch { }
            }
        }
    }
}
