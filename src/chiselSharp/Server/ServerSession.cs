using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using ChiselSharp.Protocol;
using ChiselSharp.Settings;
using ChiselSharp.SSH;
using ChiselSharp.Transport;
using ChiselSharp.Utils;

namespace ChiselSharp.Server
{
    public class ServerSession : IDisposable
    {
        private readonly ChiselServer _server;
        private readonly System.IO.Stream _acceptedStream;
        private readonly byte[] _hostKeyCspBlob;

        private System.IO.Stream _stream;
        private SshTransport _transport;
        private SshConnection _connection;
        private bool _disposed;
        private const int PipeDrainTimeoutMs = 2000;

        private uint _sessionChannelId;
        private Dictionary<string, string> _envVars;
        private string _userName;
        private List<RemoteSpec> _configuredRemotes;

        // Reverse tunnel listeners
        private List<TcpListener> _listeners;
        private object _listenersLock;

        public event Action Disconnected;

        public ServerSession(ChiselServer server, System.IO.Stream acceptedStream, byte[] hostKeyCspBlob)
        {
            _server = server;
            _acceptedStream = acceptedStream;
            _hostKeyCspBlob = hostKeyCspBlob;
            _sessionChannelId = 0;
            _envVars = new Dictionary<string, string>();
            _configuredRemotes = new List<RemoteSpec>();
            _listeners = new List<TcpListener>();
            _listenersLock = new object();
        }

        public async Task HandleAsync()
        {
            try
            {
                // Use raw WebSocket messages as SSH packets.
                _stream = _acceptedStream;

                // 1. SSH transport handshake (server mode)
                _transport = new SshTransport(_stream);
                await _transport.HandshakeAsServerAsync(_hostKeyCspBlob);

                // 2. Handle authentication (service request + password auth)
                await HandleAuthAsync();

                // 3. Native chisel sends remotes as a global "config" request.
                _configuredRemotes = await ReceiveNativeConfigAsync();

                // 4. Create SSH connection for channel management
                _connection = new SshConnection(_transport);
                _connection.IncomingChannelOpen += OnChannelOpen;
                _connection.IncomingChannelRequest += OnChannelRequest;
                _connection.StartReadLoop();

                // 5. Create configured reverse tunnels; forward tunnels are
                // handled by incoming direct-tcpip channels.
                CreateConfiguredRemotes(_configuredRemotes);

                Logger.Info("Client connected (" + (_userName ?? "unknown") + ")");

                // 6. Keep-alive loop until disconnected
                while (_connection != null && !_connection.IsClosed)
                {
                    await Compat.Delay(500);
                }
            }
            catch (Exception ex)
            {
                Logger.Debug("Session error: " + ex.Message);
            }
            finally
            {
                Dispose();
            }
        }

        // ===================== Authentication =====================

        private async Task HandleAuthAsync()
        {
            // Receive SSH_MSG_SERVICE_REQUEST
            byte[] payload = await _transport.ReceivePacketAsync();
            if (payload == null || payload.Length == 0 ||
                payload[0] != SshMsg.SSH_MSG_SERVICE_REQUEST)
            {
                throw new Exception("Expected SSH_MSG_SERVICE_REQUEST");
            }

            int offset = 1;
            string serviceName = SshWire.ReadString(payload, ref offset);

            // Send SSH_MSG_SERVICE_ACCEPT
            byte[] serviceBytes = Encoding.UTF8.GetBytes(serviceName);
            byte[] accept = new byte[1 + 4 + serviceBytes.Length];
            accept[0] = SshMsg.SSH_MSG_SERVICE_ACCEPT;
            byte[] lenBytes = SshWire.EncodeUint32((uint)serviceBytes.Length);
            Buffer.BlockCopy(lenBytes, 0, accept, 1, 4);
            Buffer.BlockCopy(serviceBytes, 0, accept, 5, serviceBytes.Length);
            await _transport.SendPacketAsync(accept);

            // Process auth requests
            while (true)
            {
                payload = await _transport.ReceivePacketAsync();
                if (payload == null || payload.Length == 0)
                {
                    throw new Exception("Client disconnected during authentication");
                }

                byte msgType = payload[0];

                if (msgType == SshMsg.SSH_MSG_USERAUTH_REQUEST)
                {
                    offset = 1;
                    string user = SshWire.ReadString(payload, ref offset);
                    string service = SshWire.ReadString(payload, ref offset);
                    string method = SshWire.ReadString(payload, ref offset);

                    if (method == "password")
                    {
                        bool hasOldPassword = (payload[offset++] == 1);
                        string password = SshWire.ReadString(payload, ref offset);

                        bool authOk = ValidateUser(user, password);

                        if (authOk)
                        {
                            _userName = user;
                            await _transport.SendPacketAsync(
                                new byte[] { SshMsg.SSH_MSG_USERAUTH_SUCCESS });
                            return;
                        }
                        else
                        {
                            byte[] failPayload = BuildUserauthFailure();
                            await _transport.SendPacketAsync(failPayload);
                            throw new Exception("Authentication failed for user: " + user);
                        }
                    }
                    else
                    {
                        // Unsupported method
                        byte[] failPayload = BuildUserauthFailure();
                        await _transport.SendPacketAsync(failPayload);
                    }
                }
                else if (msgType == SshMsg.SSH_MSG_USERAUTH_BANNER)
                {
                    // Banner from client, ignore
                    continue;
                }
                else if (msgType == SshMsg.SSH_MSG_DISCONNECT)
                {
                    throw new Exception("Client disconnected during authentication");
                }
                else
                {
                    // Ignore other messages
                    continue;
                }
            }
        }

        private bool ValidateUser(string user, string password)
        {
            if (_server.AuthManager != null)
            {
                return _server.AuthManager.ValidateUser(user, password);
            }
            else if (!string.IsNullOrEmpty(_server.Config.Auth))
            {
                return (_server.Config.Auth == user + ":" + password);
            }
            else
            {
                return true; // No auth configured
            }
        }

        private static byte[] BuildUserauthFailure()
        {
            // SSH_MSG_USERAUTH_FAILURE + string "password" + bool partial_success
            byte[] methodsBytes = Encoding.UTF8.GetBytes("password");
            byte[] payload = new byte[1 + 4 + methodsBytes.Length + 1];
            payload[0] = SshMsg.SSH_MSG_USERAUTH_FAILURE;
            byte[] lenBytes = SshWire.EncodeUint32((uint)methodsBytes.Length);
            Buffer.BlockCopy(lenBytes, 0, payload, 1, 4);
            Buffer.BlockCopy(methodsBytes, 0, payload, 5, methodsBytes.Length);
            payload[5 + methodsBytes.Length] = 0; // partial_success = false
            return payload;
        }

        // ===================== Native chisel config =====================

        private async Task<List<RemoteSpec>> ReceiveNativeConfigAsync()
        {
            byte[] payload = await _transport.ReceivePacketAsync();
            if (payload == null || payload.Length == 0 ||
                payload[0] != SshMsg.SSH_MSG_GLOBAL_REQUEST)
            {
                throw new Exception("Expected SSH global config request");
            }

            int offset = 1;
            string requestType = SshWire.ReadString(payload, ref offset);
            bool wantReply = offset < payload.Length && payload[offset++] == 1;
            byte[] requestData = new byte[payload.Length - offset];
            if (requestData.Length > 0)
                Buffer.BlockCopy(payload, offset, requestData, 0, requestData.Length);

            if (requestType != "config")
            {
                if (wantReply)
                    await SendGlobalRequestReplyAsync(false, "expecting config request");
                throw new Exception("Expected config request, got " + requestType);
            }

            List<RemoteSpec> remotes = null;
            Exception decodeError = null;
            try
            {
                remotes = DecodeNativeConfig(requestData);
            }
            catch (Exception ex)
            {
                decodeError = ex;
            }

            if (decodeError != null)
            {
                if (wantReply)
                    await SendGlobalRequestReplyAsync(false, decodeError.Message);
                throw decodeError;
            }

            if (wantReply)
                await SendGlobalRequestReplyAsync(true, null);
            return remotes;
        }

        private async Task SendGlobalRequestReplyAsync(bool ok, string message)
        {
            byte msg = ok ? SshMsg.SSH_MSG_REQUEST_SUCCESS : SshMsg.SSH_MSG_REQUEST_FAILURE;
            byte[] data = string.IsNullOrEmpty(message) ? new byte[0] : Encoding.UTF8.GetBytes(message);
            byte[] payload = new byte[1 + data.Length];
            payload[0] = msg;
            if (data.Length > 0)
                Buffer.BlockCopy(data, 0, payload, 1, data.Length);
            await _transport.SendPacketAsync(payload);
        }

        private List<RemoteSpec> DecodeNativeConfig(byte[] data)
        {
            var config = Json.FromBytes(data);
            if (config == null)
                throw new Exception("invalid config");

            object remotesObj;
            if (!config.TryGetValue("Remotes", out remotesObj) || remotesObj == null)
                return new List<RemoteSpec>();

            var remotes = new List<RemoteSpec>();
            IEnumerable enumerable = remotesObj as IEnumerable;
            if (enumerable == null)
                throw new Exception("invalid config remotes");

            foreach (object item in enumerable)
            {
                var remoteObj = item as Dictionary<string, object>;
                if (remoteObj == null)
                    throw new Exception("invalid remote config");
                remotes.Add(DecodeNativeRemote(remoteObj));
            }

            return remotes;
        }

        private RemoteSpec DecodeNativeRemote(Dictionary<string, object> obj)
        {
            bool socks = GetNativeBool(obj, "Socks");
            bool stdio = GetNativeBool(obj, "Stdio");
            string proto = GetNativeString(obj, "RemoteProto");
            if (string.IsNullOrEmpty(proto))
                proto = GetNativeString(obj, "LocalProto");
            if (string.IsNullOrEmpty(proto))
                proto = "tcp";

            var spec = new RemoteSpec();
            spec.IsReverse = GetNativeBool(obj, "Reverse");
            spec.IsSocks = socks;
            spec.IsStdio = stdio;
            spec.Protocol = proto.Equals("udp", StringComparison.OrdinalIgnoreCase)
                ? TunnelProtocol.UDP
                : TunnelProtocol.TCP;

            spec.LocalHost = GetNativeString(obj, "LocalHost");
            spec.LocalPort = GetNativePort(obj, "LocalPort");
            spec.RemoteHost = GetNativeString(obj, "RemoteHost");
            spec.RemotePort = GetNativePort(obj, "RemotePort");

            if (socks)
            {
                if (string.IsNullOrEmpty(spec.LocalHost) || spec.LocalHost == "0.0.0.0")
                    spec.LocalHost = "127.0.0.1";
                if (spec.LocalPort <= 0)
                    spec.LocalPort = 1080;
            }
            else
            {
                if (string.IsNullOrEmpty(spec.LocalHost))
                    spec.LocalHost = "0.0.0.0";
                if (string.IsNullOrEmpty(spec.RemoteHost))
                    spec.RemoteHost = "127.0.0.1";
            }

            return spec;
        }

        private static string GetNativeString(Dictionary<string, object> obj, string key)
        {
            object value;
            if (!obj.TryGetValue(key, out value) || value == null)
                return "";
            return value.ToString();
        }

        private static bool GetNativeBool(Dictionary<string, object> obj, string key)
        {
            object value;
            if (!obj.TryGetValue(key, out value) || value == null)
                return false;
            if (value is bool)
                return (bool)value;
            bool parsed;
            return bool.TryParse(value.ToString(), out parsed) && parsed;
        }

        private static int GetNativePort(Dictionary<string, object> obj, string key)
        {
            string value = GetNativeString(obj, key);
            int port;
            return int.TryParse(value, out port) ? port : 0;
        }

        // ===================== Session Channel Handling =====================

        private void OnChannelOpen(uint localId, string channelType, byte[] extra)
        {
            if (channelType == "session")
            {
                _sessionChannelId = localId;
                Logger.Debug("Session channel opened: " + localId);
            }
            else if (channelType == "direct-tcpip")
            {
                // Forward tunnel: client wants us to connect to a target host:port
                Task unused = HandleDirectTcpipChannel(localId, extra);
            }
            else if (channelType == "chisel")
            {
                Task unused = HandleChiselChannel(localId, extra);
            }
        }

        private void OnChannelRequest(uint localChannelId, string requestType,
                                      byte[] data, bool wantReply)
        {
            try
            {
                if (requestType == "env")
                {
                    int offset = 0;
                    string varName = SshWire.ReadString(data, ref offset);
                    string varValue = SshWire.ReadString(data, ref offset);

                    lock (_envVars)
                    {
                        _envVars[varName] = varValue;
                    }

                    Logger.Debug("Env: " + varName + "=" + varValue);

                    if (wantReply)
                    {
                        Task unused =
                            _connection.SendChannelRequestSuccessAsync(localChannelId);
                    }
                }
                else if (requestType == "exec" || requestType == "shell")
                {
                    if (wantReply)
                    {
                        Task unused =
                            _connection.SendChannelRequestSuccessAsync(localChannelId);
                    }

                }
                else
                {
                    if (wantReply)
                    {
                        Task unused =
                            _connection.SendChannelRequestFailureAsync(localChannelId);
                    }
                }
            }
            catch (Exception ex)
            {
                Logger.Debug("Channel request error: " + ex.Message);
            }
        }

        // ===================== Remote Parsing =====================

        private void CreateConfiguredRemotes(List<RemoteSpec> remotes)
        {
            int remoteCount = 0;

            foreach (RemoteSpec spec in remotes)
            {
                if (spec == null)
                    continue;

                if (spec.IsReverse && !_server.Config.Reverse)
                {
                    Logger.Warn("Remote '" + spec +
                        "' denied: reverse tunnels not enabled");
                    continue;
                }

                if (_server.AuthManager != null &&
                    !_server.AuthManager.Validate(_userName, null, spec))
                {
                    Logger.Warn("Remote '" + spec +
                        "' denied by auth rules");
                    continue;
                }

                CreateSshTunnel(spec);
                remoteCount++;
                Logger.Info("Tunnel created: " + spec);
            }

            Logger.Info(remoteCount + " remotes configured");
        }

        private void ParseAndCreateRemotes()
        {
            string remotesStr = null;

            lock (_envVars)
            {
                // Try common env var names used by chisel clients
                string[] varNames = new string[]
                {
                    "REMOTE_SPECS",
                    "CHISEL_REMOTE_SPECS",
                    "SSH_REMOTE_SPECS",
                    "CHISEL_REMOTES",
                    "REMOTES"
                };

                foreach (string name in varNames)
                {
                    string val;
                    if (_envVars.TryGetValue(name, out val))
                    {
                        if (!string.IsNullOrEmpty(val))
                        {
                            remotesStr = val;
                            break;
                        }
                    }
                }

                // If not found, look for numbered env vars
                if (remotesStr == null)
                {
                    int index = 0;
                    while (true)
                    {
                        string individualRemote;
                        bool found = _envVars.TryGetValue(
                            "CHISEL_REMOTE_" + index, out individualRemote);
                        if (!found)
                        {
                            found = _envVars.TryGetValue(
                                "REMOTE_" + index, out individualRemote);
                        }
                        if (!found)
                            break;

                        if (!string.IsNullOrEmpty(individualRemote))
                        {
                            if (remotesStr == null)
                                remotesStr = individualRemote;
                            else
                                remotesStr = remotesStr + "," + individualRemote;
                        }
                        index++;
                    }
                }
            }

            if (string.IsNullOrEmpty(remotesStr))
            {
                Logger.Debug("No remotes configured via SSH");
                return;
            }

            string[] parts = remotesStr.Split(',');
            int remoteCount = 0;

            foreach (string part in parts)
            {
                string trimmed = part.Trim();
                if (string.IsNullOrEmpty(trimmed))
                    continue;

                RemoteSpec spec = RemoteParser.Parse(trimmed);
                if (spec != null)
                {
                    // Enforce --reverse flag on server
                    if (spec.IsReverse && !_server.Config.Reverse)
                    {
                        Logger.Warn("Remote '" + trimmed +
                            "' denied: reverse tunnels not enabled");
                        continue;
                    }

                    if (_server.AuthManager != null &&
                        !_server.AuthManager.Validate(_userName, null, spec))
                    {
                        Logger.Warn("Remote '" + trimmed +
                            "' denied by auth rules");
                        continue;
                    }

                    CreateSshTunnel(spec);
                    remoteCount++;
                    Logger.Info("Tunnel created: " + spec);
                }
                else
                {
                    Logger.Warn("Invalid remote: " + trimmed);
                }
            }

            Logger.Info(remoteCount + " remotes configured");
        }

        private void CreateSshTunnel(RemoteSpec spec)
        {
            if (spec.IsReverse)
            {
                StartReverseTunnel(spec);
            }
            // Forward tunnels are handled reactively via IncomingChannelOpen
            // for "direct-tcpip" channel type. No server-side setup needed.
        }

        // ===================== Reverse Tunnels =====================

        private void StartReverseTunnel(RemoteSpec spec)
        {
            try
            {
                string bindHost = spec.LocalHost;
                if (string.IsNullOrEmpty(bindHost) || bindHost == "0.0.0.0")
                {
                    bindHost = "0.0.0.0";
                }

                IPAddress bindAddress;
                if (!IPAddress.TryParse(bindHost, out bindAddress))
                {
                    bindAddress = IPAddress.Any;
                }

                TcpListener listener = new TcpListener(bindAddress, spec.LocalPort);
                listener.Start(1024);

                lock (_listenersLock)
                {
                    _listeners.Add(listener);
                }

                Logger.Info("Reverse tunnel listening on " +
                    bindHost + ":" + spec.LocalPort);

                Task unused = AcceptReverseLoop(listener, spec);
            }
            catch (Exception ex)
            {
                Logger.Error("Failed to start reverse tunnel on port " +
                    spec.LocalPort + ": " + ex.Message);
            }
        }

        private async Task AcceptReverseLoop(TcpListener listener, RemoteSpec spec)
        {
            while (!_disposed)
            {
                try
                {
                    TcpClient client = await Compat.AcceptTcpClientAsync(listener);
                    client.NoDelay = true;
                    Task unused = HandleReverseConnection(client, spec);
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
                    Logger.Debug("Reverse accept error: " + ex.Message);
                    break;
                }
            }
        }

        private async Task HandleReverseConnection(TcpClient tcpClient, RemoteSpec spec)
        {
            uint channelId = 0;
            try
            {
                if (_connection == null)
                {
                    try { tcpClient.Close(); } catch { }
                    return;
                }

                channelId = await _connection.OpenChiselAsync(BuildChiselRemote(spec));

                // Bidirectional pipe between TCP connection and SSH channel
                NetworkStream stream = tcpClient.GetStream();
                Task task1 = PipeTcpToSsh(stream, channelId);
                Task task2 = PipeSshToTcp(channelId, stream);
                await WaitForPipeTasks(task1, task2, delegate { try { stream.Close(); } catch { } });
            }
            catch (Exception ex)
            {
                Logger.Debug("Reverse tunnel connection error: " + ex.Message);
            }
            finally
            {
                try { tcpClient.Close(); } catch { }
                if (channelId != 0 && _connection != null)
                {
                    Task unused = _connection.CloseChannelAsync(channelId);
                }
            }
        }

        // ===================== Forward Tunnels =====================

        private async Task HandleDirectTcpipChannel(uint localChannelId, byte[] extra)
        {
            TcpClient tcpClient = null;
            try
            {
                if (extra == null || extra.Length < 8)
                {
                    Logger.Warn("Invalid direct-tcpip channel open data");
                    return;
                }

                // Parse direct-tcpip extra data: host, port, originator IP, originator port
                int offset = 0;
                string host = SshWire.ReadString(extra, ref offset);
                int port = (int)SshWire.ReadUint32(extra, ref offset);

                Logger.Debug("Forward tunnel: connecting to " + host + ":" + port);

                // Connect to the target
                tcpClient = new TcpClient();
                tcpClient.NoDelay = true;
                await Compat.ConnectTcpAsync(tcpClient, host, port);

                // Bidirectional pipe between SSH channel and TCP connection
                NetworkStream stream = tcpClient.GetStream();
                Task task1 = PipeSshToTcp(localChannelId, stream);
                Task task2 = PipeTcpToSsh(stream, localChannelId);
                await WaitForPipeTasks(task1, task2, delegate { try { stream.Close(); } catch { } });
            }
            catch (Exception ex)
            {
                Logger.Debug("Forward tunnel error: " + ex.Message);
            }
            finally
            {
                if (tcpClient != null)
                {
                    try { tcpClient.Close(); } catch { }
                }
                if (_connection != null)
                {
                    Task unused = _connection.CloseChannelAsync(localChannelId);
                }
            }
        }

        private async Task HandleChiselChannel(uint localChannelId, byte[] extra)
        {
            TcpClient tcpClient = null;
            try
            {
                string remote = extra != null ? Encoding.UTF8.GetString(extra) : "";
                if (remote == "socks")
                {
                    if (!_server.Config.Socks5)
                    {
                        Logger.Debug("Denied socks request, --socks5 is not enabled");
                        return;
                    }
                    await HandleSocksChannel(localChannelId);
                    return;
                }

                string host;
                int port;
                if (!TryParseHostPort(remote, out host, out port))
                {
                    Logger.Warn("Invalid chisel channel target: " + remote);
                    return;
                }

                Logger.Debug("Forward tunnel: connecting to " + host + ":" + port);

                tcpClient = new TcpClient();
                tcpClient.NoDelay = true;
                await Compat.ConnectTcpAsync(tcpClient, host, port);

                NetworkStream stream = tcpClient.GetStream();
                Task task1 = PipeSshToTcp(localChannelId, stream);
                Task task2 = PipeTcpToSsh(stream, localChannelId);
                await WaitForPipeTasks(task1, task2, delegate { try { stream.Close(); } catch { } });
            }
            catch (Exception ex)
            {
                Logger.Debug("Chisel channel error: " + ex.Message);
            }
            finally
            {
                if (tcpClient != null)
                {
                    try { tcpClient.Close(); } catch { }
                }
                if (_connection != null)
                {
                    Task unused = _connection.CloseChannelAsync(localChannelId);
                }
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

        // ===================== Pipe Helpers =====================

        private async Task HandleSocksChannel(uint channelId)
        {
            TcpClient tcpClient = null;
            ChannelStream channelStream = null;
            bool sendFailureReply = false;
            try
            {
                channelStream = new ChannelStream(_connection, channelId);
                SocksConnectRequest request = await ReadSocksConnectRequest(channelStream);
                if (request != null)
                {
                    tcpClient = new TcpClient();
                    tcpClient.NoDelay = true;
                    await Compat.ConnectTcpAsync(tcpClient, request.Host, request.Port);
                    await WriteSocksReply(channelStream, 0);

                    NetworkStream tcpStream = tcpClient.GetStream();
                    Task task1 = PipeStreamToTcp(channelStream, tcpStream);
                    Task task2 = PipeTcpToSsh(tcpStream, channelId);
                    await WaitForPipeTasks(task1, task2, delegate { try { tcpStream.Close(); } catch { } });
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
            if (_connection != null)
            {
                Task unused = _connection.CloseChannelAsync(channelId);
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

        private static async Task WaitForPipeTasks(Task first, Task second, Action closeTransport)
        {
            await Compat.WhenAny(first, second);
            if (closeTransport != null)
                closeTransport();

            Task all = Compat.WhenAll(first, second);
            Task done = await Compat.WhenAny(all, Compat.Delay(PipeDrainTimeoutMs));
            if (done == all)
            {
                try { await all; } catch { }
            }
        }

        private class SocksConnectRequest
        {
            public string Host;
            public int Port;
        }

        private async Task PipeSshToTcp(uint channelId, NetworkStream stream)
        {
            try
            {
                while (true)
                {
                    byte[] data = await _connection.ReceiveChannelDataAsync(channelId);
                    if (data == null)
                        break;
                    await stream.WriteAsync(data, 0, data.Length);
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

                    await _connection.SendChannelDataAsync(channelId, buf, 0, read);
                }
            }
            catch
            {
                // Connection closed or error
            }
            try
            {
                await _connection.SendChannelEofAsync(channelId);
            }
            catch
            {
                // Channel may already be closed
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

        // ===================== IDisposable =====================

        public void Dispose()
        {
            if (_disposed)
                return;
            _disposed = true;

            // Stop all reverse tunnel listeners
            lock (_listenersLock)
            {
                foreach (TcpListener listener in _listeners)
                {
                    try { listener.Stop(); } catch { }
                }
                _listeners.Clear();
            }

            if (_connection != null)
            {
                _connection.Dispose();
                _connection = null;
            }

            if (_transport != null)
            {
                _transport.Dispose();
                _transport = null;
            }

            if (_stream != null)
            {
                _stream.Dispose();
                _stream = null;
            }

            try
            {
                if (Disconnected != null)
                    Disconnected();
            }
            catch { }
        }
    }
}
