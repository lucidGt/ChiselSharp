using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Threading.Tasks;
using ChiselSharp.Protocol;
using ChiselSharp.Settings;
using ChiselSharp.Utils;

namespace ChiselSharp.Tunnels
{
    public class UdpTunnel : IDisposable
    {
        private readonly Multiplexer _mux;
        private readonly RemoteSpec _spec;
        private readonly bool _isServer;
        private UdpClient _listener;
        private Channel _channel;
        private bool _disposed;

        // Map of source endpoints to channels
        private readonly Dictionary<string, UdpClient> _forwardClients = new Dictionary<string, UdpClient>();
        private readonly object _clientsLock = new object();

        public UdpTunnel(Multiplexer mux, RemoteSpec spec, bool isServer)
        {
            _mux = mux;
            _spec = spec;
            _isServer = isServer;
        }

        public async Task StartAsync()
        {
            // Open a channel for UDP traffic
            _channel = _mux.OpenChannel();

            var synPayload = Json.NewObject();
            synPayload["type"] = "udp";
            synPayload["remoteHost"] = _spec.RemoteHost;
            synPayload["remotePort"] = _spec.RemotePort;
            await _mux.SendFrameAsync(Frame.CreateSyn(_channel.Id, Json.Serialize(synPayload)));
            await _channel.WaitForOpen();

            // Start UDP listener on local side
            _listener = new UdpClient(_spec.LocalPort);

            // Listen for local UDP packets
            Task unused = ListenLocal();

            // Forward incoming channel data to remote UDP
            Task unused2 = ForwardRemote();
        }

        private async Task ListenLocal()
        {
            try
            {
                while (!_disposed)
                {
                    // ReceiveAsync is available in .NET 4.5
                    var result = await _listener.ReceiveAsync();

                    // Frame: [srcAddr bytes (4 or 16)] [srcPort (2)] [payload (N)]
                    byte[] srcAddr = result.RemoteEndPoint.Address.GetAddressBytes();
                    byte[] frame = new byte[srcAddr.Length + 2 + result.Buffer.Length];

                    Buffer.BlockCopy(srcAddr, 0, frame, 0, srcAddr.Length);
                    frame[srcAddr.Length] = (byte)((result.RemoteEndPoint.Port >> 8) & 0xFF);
                    frame[srcAddr.Length + 1] = (byte)(result.RemoteEndPoint.Port & 0xFF);
                    Buffer.BlockCopy(result.Buffer, 0, frame, srcAddr.Length + 2, result.Buffer.Length);

                    await _channel.SendAsync(frame);
                }
            }
            catch (Exception ex)
            {
                if (!_disposed)
                    Logger.Debug("UDP listen error: " + ex.Message);
            }
        }

        private async Task ForwardRemote()
        {
            try
            {
                while (!_disposed)
                {
                    byte[] data = _channel.Receive();
                    if (data == null) break;

                    // Parse frame: [srcAddr (4)] [srcPort (2)] [payload (N)]
                    if (data.Length < 6) continue;

                    // IPv4 address (4 bytes)
                    byte[] addrBytes = new byte[4];
                    Buffer.BlockCopy(data, 0, addrBytes, 0, 4);
                    IPAddress srcAddr = new IPAddress(addrBytes);

                    int srcPort = (data[4] << 8) | data[5];
                    byte[] payload = new byte[data.Length - 6];
                    Buffer.BlockCopy(data, 6, payload, 0, payload.Length);

                    // Forward to remote destination
                    using (var udpClient = new UdpClient())
                    {
                        await udpClient.SendAsync(payload, payload.Length, _spec.RemoteHost, _spec.RemotePort);

                        // Wait for response
                        var responseResult = await udpClient.ReceiveAsync();

                        // Send response back through channel
                        byte[] respFrame = new byte[6 + responseResult.Buffer.Length];
                        responseResult.RemoteEndPoint.Address.GetAddressBytes().CopyTo(respFrame, 0);
                        respFrame[4] = (byte)((responseResult.RemoteEndPoint.Port >> 8) & 0xFF);
                        respFrame[5] = (byte)(responseResult.RemoteEndPoint.Port & 0xFF);
                        Buffer.BlockCopy(responseResult.Buffer, 0, respFrame, 6, responseResult.Buffer.Length);

                        await _channel.SendAsync(respFrame);
                    }
                }
            }
            catch (Exception ex)
            {
                if (!_disposed)
                    Logger.Debug("UDP forward error: " + ex.Message);
            }
        }

        public void Dispose()
        {
            _disposed = true;
            try { if (_listener != null) _listener.Close(); } catch { }
            try { if (_channel != null) { var closeTask = _channel.CloseAsync(); } } catch { }
        }
    }
}
