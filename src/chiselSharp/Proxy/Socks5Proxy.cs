using System;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;
using ChiselSharp.Protocol;
using ChiselSharp.Utils;

namespace ChiselSharp.Proxy
{
    /// <summary>
    /// RFC 1928 SOCKS5 proxy implementation.
    /// Supports CONNECT and BIND commands.
    /// </summary>
    public class Socks5Proxy
    {
        private readonly Multiplexer _mux;
        private readonly bool _isReverse;

        private const byte SOCKS_VERSION = 0x05;
        private const byte AUTH_NONE = 0x00;
        private const byte AUTH_USERPASS = 0x02;
        private const byte AUTH_NO_ACCEPTABLE = 0xFF;

        private const byte CMD_CONNECT = 0x01;
        private const byte CMD_BIND = 0x02;
        private const byte CMD_UDP_ASSOCIATE = 0x03;

        private const byte ATYP_IPV4 = 0x01;
        private const byte ATYP_DOMAIN = 0x03;
        private const byte ATYP_IPV6 = 0x04;

        private const byte REP_SUCCESS = 0x00;
        private const byte REP_GENERAL_FAILURE = 0x01;
        private const byte REP_NOT_ALLOWED = 0x02;
        private const byte REP_NETWORK_UNREACHABLE = 0x03;
        private const byte REP_HOST_UNREACHABLE = 0x04;
        private const byte REP_CONN_REFUSED = 0x05;
        private const byte REP_CMD_NOT_SUPPORTED = 0x07;
        private const byte REP_ADDR_NOT_SUPPORTED = 0x08;
        private const int ConnectTimeoutMs = 3000;

        public Socks5Proxy(Multiplexer mux, bool isReverse)
        {
            _mux = mux;
            _isReverse = isReverse;
        }

        /// <summary>
        /// Handle a SOCKS5 connection that goes through the tunnel.
        /// </summary>
        public async Task HandleConnectionAsync(TcpClient client)
        {
            try
            {
                var stream = client.GetStream();

                // 1. Handshake - read auth methods
                byte[] handshake = new byte[2];
                int read = await stream.ReadAsync(handshake, 0, 2);
                if (read < 2 || handshake[0] != SOCKS_VERSION) { client.Close(); return; }

                int numMethods = handshake[1];
                byte[] methods = new byte[numMethods];
                read = await stream.ReadAsync(methods, 0, numMethods);
                if (read < numMethods) { client.Close(); return; }

                // Choose no-auth
                bool hasNoAuth = false;
                for (int i = 0; i < numMethods; i++)
                {
                    if (methods[i] == AUTH_NONE)
                        hasNoAuth = true;
                }

                if (hasNoAuth)
                {
                    await stream.WriteAsync(new byte[] { SOCKS_VERSION, AUTH_NONE }, 0, 2);
                }
                else
                {
                    await stream.WriteAsync(new byte[] { SOCKS_VERSION, AUTH_NO_ACCEPTABLE }, 0, 2);
                    client.Close();
                    return;
                }

                // 2. Request - read command
                byte[] reqHeader = new byte[4];
                read = await stream.ReadAsync(reqHeader, 0, 4);
                if (read < 4 || reqHeader[0] != SOCKS_VERSION) { client.Close(); return; }

                byte cmd = reqHeader[1];
                byte atyp = reqHeader[3];

                string destAddr = "";
                int destPort = 0;

                // Read destination address
                if (atyp == ATYP_IPV4)
                {
                    byte[] addr = new byte[4];
                    await stream.ReadAsync(addr, 0, 4);
                    destAddr = new IPAddress(addr).ToString();
                }
                else if (atyp == ATYP_DOMAIN)
                {
                    byte[] lenByte = new byte[1];
                    await stream.ReadAsync(lenByte, 0, 1);
                    int domainLen = lenByte[0];
                    byte[] domain = new byte[domainLen];
                    await stream.ReadAsync(domain, 0, domainLen);
                    destAddr = Encoding.ASCII.GetString(domain);
                }
                else if (atyp == ATYP_IPV6)
                {
                    byte[] addr = new byte[16];
                    await stream.ReadAsync(addr, 0, 16);
                    destAddr = new IPAddress(addr).ToString();
                }
                else
                {
                    await SendReply(stream, REP_ADDR_NOT_SUPPORTED);
                    client.Close();
                    return;
                }

                // Read destination port
                byte[] portBytes = new byte[2];
                await stream.ReadAsync(portBytes, 0, 2);
                destPort = (portBytes[0] << 8) | portBytes[1];

                // Handle command
                switch (cmd)
                {
                    case CMD_CONNECT:
                        await HandleConnect(stream, destAddr, destPort);
                        break;
                    case CMD_BIND:
                        await HandleBind(stream);
                        break;
                    case CMD_UDP_ASSOCIATE:
                        await HandleUdpAssociate(stream);
                        break;
                    default:
                        await SendReply(stream, REP_CMD_NOT_SUPPORTED);
                        client.Close();
                        break;
                }
            }
            catch (Exception ex)
            {
                Logger.Debug("SOCKS5 error: " + ex.Message);
                try { client.Close(); } catch { }
            }
        }

        /// <summary>
        /// Handle a direct SOCKS5 connection (server-side --socks5 without tunnel).
        /// </summary>
        public async Task HandleDirectConnectionAsync(TcpClient client)
        {
            try
            {
                var stream = client.GetStream();

                // Simplified handshake - just no-auth
                byte[] handshake = new byte[2];
                int read = await stream.ReadAsync(handshake, 0, 2);
                if (read < 2) { client.Close(); return; }

                int numMethods = handshake[1];
                byte[] methods = new byte[numMethods];
                await stream.ReadAsync(methods, 0, numMethods);
                await stream.WriteAsync(new byte[] { SOCKS_VERSION, AUTH_NONE }, 0, 2);

                // Request
                byte[] reqHeader = new byte[4];
                read = await stream.ReadAsync(reqHeader, 0, 4);
                if (read < 4) { client.Close(); return; }

                byte cmd = reqHeader[1];
                byte atyp = reqHeader[3];

                string destAddr = "";
                int destPort = 0;

                if (atyp == ATYP_IPV4)
                {
                    byte[] addr = new byte[4];
                    await stream.ReadAsync(addr, 0, 4);
                    destAddr = new IPAddress(addr).ToString();
                }
                else if (atyp == ATYP_DOMAIN)
                {
                    byte[] lenByte = new byte[1];
                    await stream.ReadAsync(lenByte, 0, 1);
                    int domainLen = lenByte[0];
                    byte[] domain = new byte[domainLen];
                    await stream.ReadAsync(domain, 0, domainLen);
                    destAddr = Encoding.ASCII.GetString(domain);
                }
                else if (atyp == ATYP_IPV6)
                {
                    byte[] addr = new byte[16];
                    await stream.ReadAsync(addr, 0, 16);
                    destAddr = new IPAddress(addr).ToString();
                }
                else
                {
                    await SendReply(stream, REP_ADDR_NOT_SUPPORTED);
                    client.Close();
                    return;
                }

                byte[] portBytes = new byte[2];
                await stream.ReadAsync(portBytes, 0, 2);
                destPort = (portBytes[0] << 8) | portBytes[1];

                if (cmd == CMD_CONNECT)
                {
                    await HandleConnect(stream, destAddr, destPort);
                }
                else
                {
                    await SendReply(stream, REP_CMD_NOT_SUPPORTED);
                    client.Close();
                }
            }
            catch (Exception ex)
            {
                Logger.Debug("Direct SOCKS5 error: " + ex.Message);
                try { client.Close(); } catch { }
            }
        }

        private async Task HandleConnect(NetworkStream clientStream, string destAddr, int destPort)
        {
            TcpClient destClient = null;
            Exception connectError = null;
            try
            {
                destClient = new TcpClient();
                destClient.NoDelay = true;
                await Compat.ConnectTcpAsync(destClient, destAddr, destPort, ConnectTimeoutMs);

                // Send success reply
                var destStream = destClient.GetStream();
                var localEp = (IPEndPoint)destClient.Client.LocalEndPoint;
                await SendReply(clientStream, REP_SUCCESS, localEp.Address.ToString(), localEp.Port);

                // Bidirectional pipe
                var task1 = PipeAsync(clientStream, destStream);
                var task2 = PipeAsync(destStream, clientStream);
                await Compat.WhenAny(task1, task2);

                try { destClient.Close(); } catch { }
            }
            catch (Exception ex)
            {
                Logger.Debug("SOCKS5 CONNECT error: " + ex.Message);
                connectError = ex;
            }

            // Send failure reply outside catch (C# 5.0 cannot await in catch)
            if (connectError != null)
            {
                await SendReply(clientStream, REP_HOST_UNREACHABLE);
            }
        }

        private async Task HandleBind(NetworkStream stream)
        {
            // BIND: listen on a port and wait for the remote to connect
            var listener = new TcpListener(IPAddress.Any, 0);
            listener.Start(1024);
            int bindPort = ((IPEndPoint)listener.LocalEndpoint).Port;

            // Send first reply with bind address
            await SendReply(stream, REP_SUCCESS, "0.0.0.0", bindPort);

            // Wait for connection (AcceptTcpClientAsync not available in .NET 4.5)
            var client = await Compat.Run(() => listener.AcceptTcpClient());
            listener.Stop();

            var clientStream = client.GetStream();
            var remoteEp = (IPEndPoint)client.Client.RemoteEndPoint;

            // Send second reply with connected address
            await SendReply(stream, REP_SUCCESS, remoteEp.Address.ToString(), remoteEp.Port);

            // Pipe
            var task1 = PipeAsync(stream, clientStream);
            var task2 = PipeAsync(clientStream, stream);
            await Compat.WhenAny(task1, task2);

            try { client.Close(); } catch { }
        }

        private async Task HandleUdpAssociate(NetworkStream stream)
        {
            // Create a UDP socket
            var udpClient = new UdpClient(0);
            int udpPort = ((IPEndPoint)udpClient.Client.LocalEndPoint).Port;

            await SendReply(stream, REP_SUCCESS, "0.0.0.0", udpPort);

            // Keep connection alive, handle UDP relay
            // Simplified: just keep the connection open
            byte[] buf = new byte[1];
            try
            {
                while (true)
                {
                    int read = await stream.ReadAsync(buf, 0, 1);
                    if (read == 0) break;
                }
            }
            catch { }
        }

        private async Task SendReply(NetworkStream stream, byte reply, string bindAddr = "0.0.0.0", int bindPort = 0)
        {
            byte[] replyMsg = new byte[10];
            replyMsg[0] = SOCKS_VERSION;
            replyMsg[1] = reply;
            replyMsg[2] = 0x00; // RSV
            replyMsg[3] = ATYP_IPV4;

            // Bind address (IPv4)
            byte[] addrBytes = IPAddress.Parse(bindAddr).GetAddressBytes();
            Buffer.BlockCopy(addrBytes, 0, replyMsg, 4, 4);

            // Bind port
            replyMsg[8] = (byte)((bindPort >> 8) & 0xFF);
            replyMsg[9] = (byte)(bindPort & 0xFF);

            await stream.WriteAsync(replyMsg, 0, replyMsg.Length);
        }

        private async Task PipeAsync(NetworkStream source, NetworkStream dest)
        {
            byte[] buf = new byte[8192];
            try
            {
                while (true)
                {
                    int read = await source.ReadAsync(buf, 0, buf.Length);
                    if (read == 0) break;
                    await dest.WriteAsync(buf, 0, read);
                }
            }
            catch { }
        }
    }
}
