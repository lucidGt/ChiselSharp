using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using ChiselSharp.Protocol;
using ChiselSharp.Settings;
using ChiselSharp.SSH;
using ChiselSharp.Tunnels;
using ChiselSharp.Transport;
using ChiselSharp.Utils;

namespace ChiselSharp.Server
{
    public class ChiselServer
    {
        private readonly Config _config;
        private TcpListener _tcpListener;
        private readonly List<ServerSession> _sessions = new List<ServerSession>();
        private readonly object _sessionsLock = new object();
        private CancellationTokenSource _cts;
        private TunnelManager _tunnelManager;
        private byte[] _serverKey;
        private byte[] _hostKeyCspBlob;
        private string _fingerprint;
        private AuthFile _authFile;

        public Config Config { get { return _config; } }
        public string Fingerprint { get { return _fingerprint; } }

        public ChiselServer(Config config)
        {
            if (config == null) throw new ArgumentNullException("config");
            _config = config;
        }

        public Task StartAsync()
        {
            _cts = new CancellationTokenSource();

            // Generate server key for fingerprint identification
            _serverKey = CryptoUtils.GenerateServerKey(_config.Key);
            _fingerprint = CryptoUtils.ComputeFingerprint(_serverKey);

            // Generate SSH RSA host key for SSH-based sessions
            _hostKeyCspBlob = SshTransport.GenerateHostKey();

            Logger.Info("chiselSharp server (C# port of chisel)");
            Logger.Info("Fingerprint: " + _fingerprint);

            // Load auth file if configured
            if (!string.IsNullOrEmpty(_config.AuthFile))
            {
                _authFile = AuthFile.Load(_config.AuthFile);
                Logger.Info("Auth file loaded: " + _config.AuthFile);
            }

            // .NET 4.0 has no HttpListener WebSocket APIs, so chiselSharp uses
            // its own HTTP upgrade parser on top of TcpListener.
            string listenHost = _config.Host;
            if (string.IsNullOrEmpty(listenHost) || listenHost == "0.0.0.0")
                listenHost = "0.0.0.0";
            IPAddress bindAddress = ResolveListenAddress(listenHost);
            _tcpListener = new TcpListener(bindAddress, _config.Port);
            _tcpListener.Start(1024);
            Logger.Info("Server listening on ws://" + listenHost + ":" + _config.Port + "/");
            Task unused = AcceptTcpLoop();

            // Start server-side tunnel manager if reverse listeners are needed.
            // SOCKS5 is handled per SSH "chisel" channel, matching native chisel.
            if (_config.Reverse)
            {
                _tunnelManager = new TunnelManager(_config, null, true);
            }
            if (_config.Socks5)
                Logger.Info("SOCKS5 channel support enabled");

            return Compat.FromResult();
        }

        private async Task AcceptTcpLoop()
        {
            while (!_cts.IsCancellationRequested)
            {
                try
                {
                    TcpClient client = await Compat.AcceptTcpClientAsync(_tcpListener);
                    client.NoDelay = true;
                    Task unused = HandleTcpClientAsync(client);
                }
                catch (ObjectDisposedException)
                {
                    break;
                }
                catch (InvalidOperationException)
                {
                    break;
                }
                catch (Exception ex)
                {
                    Logger.Debug("TCP accept error: " + ex.Message);
                }
            }
        }

        private async Task HandleTcpClientAsync(TcpClient client)
        {
            try
            {
                WebSocketFrameStream stream = await WebSocketFrameStream.AcceptAsync(client, "chisel-v3");
                if (stream == null)
                {
                    try { client.Close(); } catch { }
                    return;
                }

                ServerSession session = new ServerSession(this, stream, _hostKeyCspBlob);
                RegisterSession(session);
                Task unused = session.HandleAsync();
            }
            catch (Exception ex)
            {
                Logger.Debug("TCP request error: " + ex.Message);
                try { client.Close(); } catch { }
            }
        }

        private static IPAddress ResolveListenAddress(string listenHost)
        {
            if (string.IsNullOrEmpty(listenHost) || listenHost == "+" || listenHost == "0.0.0.0")
                return IPAddress.Any;
            if (listenHost == "localhost")
                return IPAddress.Loopback;

            IPAddress parsed;
            if (IPAddress.TryParse(listenHost, out parsed))
                return parsed;

            IPAddress[] addresses = Dns.GetHostAddresses(listenHost);
            return addresses.Length > 0 ? addresses[0] : IPAddress.Any;
        }

        private void RegisterSession(ServerSession session)
        {
            lock (_sessionsLock)
            {
                _sessions.Add(session);
            }

            session.Disconnected += () =>
            {
                lock (_sessionsLock)
                {
                    _sessions.Remove(session);
                }
            };
        }

        public TunnelManager TunnelManager
        {
            get { return _tunnelManager; }
        }

        public byte[] ServerKey
        {
            get { return _serverKey; }
        }

        public AuthFile AuthManager
        {
            get { return _authFile; }
        }

        public void Stop()
        {
            if (_cts != null) _cts.Cancel();

            lock (_sessionsLock)
            {
                foreach (ServerSession session in _sessions.ToArray())
                {
                    session.Dispose();
                }
                _sessions.Clear();
            }

            if (_tunnelManager != null)
                _tunnelManager.Stop();

            if (_tcpListener != null)
            {
                try { _tcpListener.Stop(); } catch { }
            }
        }
    }
}
