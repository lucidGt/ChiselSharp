using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Threading.Tasks;
using ChiselSharp.Protocol;
using ChiselSharp.Settings;
using ChiselSharp.Proxy;
using ChiselSharp.Utils;

namespace ChiselSharp.Tunnels
{
    public class TunnelManager
    {
        private readonly Config _config;
        private readonly Multiplexer _mux;
        private readonly bool _isServer;
        private readonly List<TcpTunnel> _tcpTunnels = new List<TcpTunnel>();
        private readonly List<UdpTunnel> _udpTunnels = new List<UdpTunnel>();
        private readonly object _lock = new object();
        private Socks5Proxy _socks5Proxy;
        private bool _stopped;

        public TunnelManager(Config config, Multiplexer mux, bool isServer)
        {
            if (config == null) throw new ArgumentNullException("config");
            _config = config;
            _mux = mux;
            _isServer = isServer;
        }

        /// <summary>
        /// Create a tunnel from a parsed remote spec.
        /// For forward tunnels on the client: listen locally, connect to server.
        /// For forward tunnels on the server: wait for channel open, connect to remote.
        /// For reverse tunnels: reversed logic.
        /// </summary>
        public async Task CreateTunnelAsync(RemoteSpec spec)
        {
            if (spec.IsSocks)
            {
                await CreateSocksTunnel(spec);
                return;
            }

            if (spec.IsStdio)
            {
                await CreateStdioTunnel(spec);
                return;
            }

            if (spec.Protocol == TunnelProtocol.UDP)
            {
                await CreateUdpTunnel(spec);
                return;
            }

            await CreateTcpTunnel(spec);
        }

        private async Task CreateTcpTunnel(RemoteSpec spec)
        {
            if (_isServer)
            {
                if (spec.IsReverse)
                {
                    // Reverse tunnel: server listens on LocalPort, sends to client via channel
                    var tunnel = new TcpTunnel(_mux, spec, isServer: true, isReverse: true);
                    lock (_lock) { _tcpTunnels.Add(tunnel); }
                    await tunnel.StartAsync();
                    Logger.Info("Reverse TCP tunnel: listening on " + spec.LocalHost + ":" + spec.LocalPort);
                }
                else
                {
                    // Forward tunnel on server: wait for SYN channel from client, connect to RemoteHost:RemotePort
                    var tunnel = new TcpTunnel(_mux, spec, isServer: true, isReverse: false);
                    lock (_lock) { _tcpTunnels.Add(tunnel); }
                    await tunnel.StartAsync();
                }
            }
            else
            {
                // Client side
                if (spec.IsReverse)
                {
                    // Reverse tunnel on client: wait for SYN channel, connect to RemoteHost:RemotePort
                    var tunnel = new TcpTunnel(_mux, spec, isServer: false, isReverse: true);
                    lock (_lock) { _tcpTunnels.Add(tunnel); }
                    await tunnel.StartAsync();
                }
                else
                {
                    // Forward tunnel: listen on LocalPort, send to server via channel
                    var tunnel = new TcpTunnel(_mux, spec, isServer: false, isReverse: false);
                    lock (_lock) { _tcpTunnels.Add(tunnel); }
                    await tunnel.StartAsync();
                    Logger.Info("Forward TCP tunnel: " + spec.LocalHost + ":" + spec.LocalPort
                        + " -> " + spec.RemoteHost + ":" + spec.RemotePort);
                }
            }
        }

        private async Task CreateUdpTunnel(RemoteSpec spec)
        {
            var tunnel = new UdpTunnel(_mux, spec, _isServer);
            lock (_lock) { _udpTunnels.Add(tunnel); }
            await tunnel.StartAsync();
            Logger.Info("UDP tunnel: " + spec.LocalHost + ":" + spec.LocalPort
                + " <-> " + spec.RemoteHost + ":" + spec.RemotePort);
        }

        private Task CreateSocksTunnel(RemoteSpec spec)
        {
            if (spec.IsReverse)
            {
                // Reverse SOCKS: server listens, client handles SOCKS5
                if (_isServer)
                {
                    var listener = new TcpListener(IPAddress.Any, spec.LocalPort);
                    listener.Start(1024);
                    Task unused = AcceptReverseSocks(listener);
                    Logger.Info("Reverse SOCKS5: listening on :" + spec.LocalPort);
                }
                else
                {
                    // Client starts a SOCKS5 proxy, handles connections from server
                    _socks5Proxy = new Socks5Proxy(_mux, isReverse: true);
                    Logger.Info("Reverse SOCKS5 ready on client");
                }
            }
            else
            {
                // Forward SOCKS: client listens, server-side connects
                if (!_isServer)
                {
                    _socks5Proxy = new Socks5Proxy(_mux, isReverse: false);
                    var listener = new TcpListener(IPAddress.Parse(spec.LocalHost), spec.LocalPort);
                    listener.Start(1024);
                    Task unused = AcceptForwardSocks(listener);
                    Logger.Info("SOCKS5 proxy listening on " + spec.LocalHost + ":" + spec.LocalPort);
                }
            }

            return Compat.FromResult();
        }

        private async Task AcceptReverseSocks(TcpListener listener)
        {
            while (!_stopped)
            {
                try
                {
                    // AcceptTcpClientAsync is not available in .NET 4.5, use Task.Run
                    var client = await Compat.Run(() => listener.AcceptTcpClient());
                    Task unused = HandleReverseSocksClient(client);
                }
                catch { break; }
            }
        }

        private async Task HandleReverseSocksClient(TcpClient client)
        {
            try
            {
                // Open a channel to the client for this SOCKS connection
                var channel = _mux.OpenChannel();

                // Send SYN with SOCKS info
                var synPayload = Json.NewObject();
                synPayload["type"] = "socks";
                synPayload["direction"] = "reverse";
                await _mux.SendFrameAsync(Frame.CreateSyn(channel.Id, Json.Serialize(synPayload)));

                // Wait for ACK
                await channel.WaitForOpen();

                // Pipe: SOCKS client <-> channel
                var clientStream = client.GetStream();
                await Compat.WhenAll(
                    PipeAsync(clientStream, channel),
                    PipeChannelAsync(channel, clientStream)
                );
            }
            catch (Exception ex)
            {
                Logger.Debug("Reverse SOCKS client error: " + ex.Message);
            }
            finally
            {
                try { client.Close(); } catch { }
            }
        }

        private async Task AcceptForwardSocks(TcpListener listener)
        {
            while (!_stopped)
            {
                try
                {
                    // AcceptTcpClientAsync is not available in .NET 4.5, use Task.Run
                    var client = await Compat.Run(() => listener.AcceptTcpClient());
                    Task unused = _socks5Proxy.HandleConnectionAsync(client);
                }
                catch { break; }
            }
        }

        public void StartSocks5Server(string host, int port)
        {
            // Direct SOCKS5 on server (--socks5 flag without tunnel)
            _socks5Proxy = new Socks5Proxy(null, isReverse: false);
            var listener = new TcpListener(IPAddress.Parse(host), port);
            listener.Start(1024);
            Task unused = AcceptDirectSocks(listener);
            Logger.Info("SOCKS5 server listening on " + host + ":" + port);
        }

        private async Task AcceptDirectSocks(TcpListener listener)
        {
            while (!_stopped)
            {
                try
                {
                    // AcceptTcpClientAsync is not available in .NET 4.5, use Task.Run
                    var client = await Compat.Run(() => listener.AcceptTcpClient());
                    Task unused = _socks5Proxy.HandleDirectConnectionAsync(client);
                }
                catch { break; }
            }
        }

        private async Task CreateStdioTunnel(RemoteSpec spec)
        {
            // stdio: pipe stdin/stdout to remote host:port
            var channel = _mux.OpenChannel();

            var synPayload = Json.NewObject();
            synPayload["type"] = "tcp";
            synPayload["remoteHost"] = spec.RemoteHost;
            synPayload["remotePort"] = spec.RemotePort;
            await _mux.SendFrameAsync(Frame.CreateSyn(channel.Id, Json.Serialize(synPayload)));
            await channel.WaitForOpen();

            // Pipe stdin -> channel, channel -> stdout
            var stdinStream = Console.OpenStandardInput();
            var stdoutStream = Console.OpenStandardOutput();

            Task unused = Compat.WhenAll(
                PipeStreamToChannel(stdinStream, channel),
                PipeChannelToStream(channel, stdoutStream)
            );
        }

        public Multiplexer Mux { get { return _mux; } }

        // ---- Pipe helpers ----

        public static async Task PipeAsync(NetworkStream source, Channel dest)
        {
            byte[] buf = new byte[8192];
            try
            {
                while (true)
                {
                    int read = await source.ReadAsync(buf, 0, buf.Length);
                    if (read == 0) break;

                    byte[] data = new byte[read];
                    Buffer.BlockCopy(buf, 0, data, 0, read);
                    await dest.SendAsync(data);
                }
            }
            catch { }
        }

        public static async Task PipeChannelAsync(Channel source, NetworkStream dest)
        {
            try
            {
                while (true)
                {
                    byte[] data = source.Receive();
                    if (data == null) break;
                    await dest.WriteAsync(data, 0, data.Length);
                }
            }
            catch { }
        }

        private async Task PipeStreamToChannel(System.IO.Stream source, Channel dest)
        {
            byte[] buf = new byte[8192];
            try
            {
                while (true)
                {
                    int read = await source.ReadAsync(buf, 0, buf.Length);
                    if (read == 0) break;

                    byte[] data = new byte[read];
                    Buffer.BlockCopy(buf, 0, data, 0, read);
                    await dest.SendAsync(data);
                }
            }
            catch { }
        }

        private async Task PipeChannelToStream(Channel source, System.IO.Stream dest)
        {
            try
            {
                while (true)
                {
                    byte[] data = source.Receive();
                    if (data == null) break;
                    await dest.WriteAsync(data, 0, data.Length);
                    await dest.FlushAsync();
                }
            }
            catch { }
        }

        public void Stop()
        {
            _stopped = true;
            lock (_lock)
            {
                foreach (var t in _tcpTunnels)
                    t.Dispose();
                _tcpTunnels.Clear();

                foreach (var u in _udpTunnels)
                    u.Dispose();
                _udpTunnels.Clear();
            }
        }
    }
}
