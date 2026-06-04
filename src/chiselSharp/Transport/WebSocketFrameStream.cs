using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using ChiselSharp.Utils;

namespace ChiselSharp.Transport
{
    /// <summary>
    /// Minimal server-side WebSocket stream used when HttpListener is unavailable.
    /// Supports the binary frames used by chisel's SSH transport.
    /// </summary>
    public class WebSocketFrameStream : Stream, IAsyncCompatStream
    {
        private const string WebSocketGuid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

        private readonly Stream _stream;
        private readonly TcpClient _client;
        private readonly bool _maskWrites;
        private readonly SemaphoreSlim _writeSemaphore = new SemaphoreSlim(1, 1);
        private byte[] _readBuffer;
        private int _readBufferPos;
        private bool _disposed;

        public bool IsOpen { get; private set; }

        private WebSocketFrameStream(TcpClient client, Stream stream, bool maskWrites)
        {
            _client = client;
            _stream = stream;
            _maskWrites = maskWrites;
            IsOpen = true;
        }

        public static async Task<WebSocketFrameStream> AcceptAsync(TcpClient client, string subProtocol)
        {
            NetworkStream stream = client.GetStream();
            byte[] requestBytes = await ReadHttpRequestAsync(stream);
            if (requestBytes == null)
                return null;

            string request = Encoding.ASCII.GetString(requestBytes);
            string[] lines = request.Split(new[] { "\r\n" }, StringSplitOptions.None);
            if (lines.Length == 0 || !lines[0].StartsWith("GET ", StringComparison.OrdinalIgnoreCase))
            {
                await WriteHttpResponseAsync(stream, "HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n");
                return null;
            }

            Dictionary<string, string> headers = ParseHeaders(lines);
            string upgrade = GetHeader(headers, "upgrade");
            string key = GetHeader(headers, "sec-websocket-key");
            string protocol = GetHeader(headers, "sec-websocket-protocol");

            if (!"websocket".Equals(upgrade, StringComparison.OrdinalIgnoreCase) ||
                string.IsNullOrEmpty(key) ||
                (protocol != null && protocol.IndexOf(subProtocol, StringComparison.OrdinalIgnoreCase) < 0))
            {
                await WriteHttpResponseAsync(stream, "HTTP/1.1 426 Upgrade Required\r\nConnection: close\r\nUpgrade: websocket\r\n\r\n");
                return null;
            }

            string accept;
            using (SHA1 sha1 = SHA1.Create())
            {
                byte[] hash = sha1.ComputeHash(Encoding.ASCII.GetBytes(key.Trim() + WebSocketGuid));
                accept = Convert.ToBase64String(hash);
            }

            string response =
                "HTTP/1.1 101 Switching Protocols\r\n" +
                "Upgrade: websocket\r\n" +
                "Connection: Upgrade\r\n" +
                "Sec-WebSocket-Accept: " + accept + "\r\n" +
                "Sec-WebSocket-Protocol: " + subProtocol + "\r\n" +
                "\r\n";
            await WriteHttpResponseAsync(stream, response);
            return new WebSocketFrameStream(client, stream, false);
        }

        public static async Task<WebSocketFrameStream> ConnectAsync(
            Uri uri,
            IDictionary<string, string> headers,
            string subProtocol,
            bool tlsSkipVerify)
        {
            if (uri == null)
                throw new ArgumentNullException("uri");
            if (uri.Scheme != "ws" && uri.Scheme != "wss")
                throw new NotSupportedException("Only ws:// and wss:// URLs are supported");

            int port = uri.Port;
            if (port <= 0)
                port = uri.Scheme == "wss" ? 443 : 80;

            TcpClient client = new TcpClient();
            client.NoDelay = true;
            await Compat.ConnectTcpAsync(client, uri.Host, port);

            Stream stream = client.GetStream();
            if (uri.Scheme == "wss")
            {
                RemoteCertificateValidationCallback callback = null;
                if (tlsSkipVerify)
                    callback = delegate { return true; };
                SslStream ssl = new SslStream(stream, false, callback);
                await Task.Factory.FromAsync(
                    ssl.BeginAuthenticateAsClient(uri.Host, null, null),
                    ssl.EndAuthenticateAsClient);
                stream = ssl;
            }

            byte[] nonce = new byte[16];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(nonce);
            }
            string key = Convert.ToBase64String(nonce);
            string path = string.IsNullOrEmpty(uri.PathAndQuery) ? "/" : uri.PathAndQuery;
            string hostHeader = uri.IsDefaultPort ? uri.Host : uri.Host + ":" + port;

            StringBuilder request = new StringBuilder();
            request.Append("GET ").Append(path).Append(" HTTP/1.1\r\n");
            request.Append("Host: ").Append(hostHeader).Append("\r\n");
            request.Append("Upgrade: websocket\r\n");
            request.Append("Connection: Upgrade\r\n");
            request.Append("Sec-WebSocket-Key: ").Append(key).Append("\r\n");
            request.Append("Sec-WebSocket-Version: 13\r\n");
            if (!string.IsNullOrEmpty(subProtocol))
                request.Append("Sec-WebSocket-Protocol: ").Append(subProtocol).Append("\r\n");
            if (headers != null)
            {
                foreach (var kvp in headers)
                    request.Append(kvp.Key).Append(": ").Append(kvp.Value).Append("\r\n");
            }
            request.Append("\r\n");

            byte[] requestBytes = Encoding.ASCII.GetBytes(request.ToString());
            await stream.WriteAsync(requestBytes, 0, requestBytes.Length);
            await stream.FlushAsync();

            byte[] responseBytes = await ReadHttpRequestAsync(stream);
            if (responseBytes == null)
                throw new IOException("WebSocket server closed during handshake");

            string response = Encoding.ASCII.GetString(responseBytes);
            string[] lines = response.Split(new[] { "\r\n" }, StringSplitOptions.None);
            if (lines.Length == 0 || lines[0].IndexOf(" 101 ", StringComparison.Ordinal) < 0)
                throw new IOException("WebSocket upgrade failed: " + (lines.Length > 0 ? lines[0] : ""));

            Dictionary<string, string> responseHeaders = ParseHeaders(lines);
            string accept = GetHeader(responseHeaders, "sec-websocket-accept");
            string expectedAccept;
            using (SHA1 sha1 = SHA1.Create())
            {
                expectedAccept = Convert.ToBase64String(
                    sha1.ComputeHash(Encoding.ASCII.GetBytes(key + WebSocketGuid)));
            }
            if (!string.Equals(accept, expectedAccept, StringComparison.Ordinal))
                throw new IOException("WebSocket accept key mismatch");

            return new WebSocketFrameStream(client, stream, true);
        }

        private static async Task<byte[]> ReadHttpRequestAsync(Stream stream)
        {
            List<byte> data = new List<byte>();
            byte[] one = new byte[1];
            while (data.Count < 16384)
            {
                int n = await stream.ReadAsync(one, 0, 1);
                if (n == 0)
                    return null;
                data.Add(one[0]);
                int c = data.Count;
                if (c >= 4 && data[c - 4] == '\r' && data[c - 3] == '\n' &&
                    data[c - 2] == '\r' && data[c - 1] == '\n')
                    return data.ToArray();
            }
            return null;
        }

        private static Dictionary<string, string> ParseHeaders(string[] lines)
        {
            var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            for (int i = 1; i < lines.Length; i++)
            {
                string line = lines[i];
                if (string.IsNullOrEmpty(line))
                    break;
                int colon = line.IndexOf(':');
                if (colon <= 0)
                    continue;
                headers[line.Substring(0, colon).Trim()] = line.Substring(colon + 1).Trim();
            }
            return headers;
        }

        private static string GetHeader(Dictionary<string, string> headers, string name)
        {
            string value;
            return headers.TryGetValue(name, out value) ? value : null;
        }

        private static async Task WriteHttpResponseAsync(Stream stream, string response)
        {
            byte[] bytes = Encoding.ASCII.GetBytes(response);
            await stream.WriteAsync(bytes, 0, bytes.Length);
            await stream.FlushAsync();
        }

        public override bool CanRead { get { return true; } }
        public override bool CanWrite { get { return true; } }
        public override bool CanSeek { get { return false; } }
        public override bool CanTimeout { get { return false; } }
        public override long Length { get { throw new NotSupportedException(); } }
        public override long Position
        {
            get { throw new NotSupportedException(); }
            set { throw new NotSupportedException(); }
        }

#if NET40
        public async Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
#else
        public override async Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
#endif
        {
            ThrowIfDisposed();

            if (_readBuffer != null && _readBufferPos < _readBuffer.Length)
            {
                int available = _readBuffer.Length - _readBufferPos;
                int copy = Math.Min(count, available);
                Buffer.BlockCopy(_readBuffer, _readBufferPos, buffer, offset, copy);
                _readBufferPos += copy;
                if (_readBufferPos >= _readBuffer.Length)
                {
                    _readBuffer = null;
                    _readBufferPos = 0;
                }
                return copy;
            }

            byte[] message = await ReadMessageAsync(cancellationToken);
            if (message == null)
                return 0;

            _readBuffer = message;
            _readBufferPos = 0;

            int toCopy = Math.Min(count, message.Length);
            Buffer.BlockCopy(message, 0, buffer, offset, toCopy);
            _readBufferPos = toCopy;
            if (_readBufferPos >= _readBuffer.Length)
            {
                _readBuffer = null;
                _readBufferPos = 0;
            }
            return toCopy;
        }

        private async Task<byte[]> ReadMessageAsync(CancellationToken cancellationToken)
        {
            MemoryStream ms = null;
            while (true)
            {
                Frame frame = await ReadFrameAsync(cancellationToken);
                if (frame == null)
                    return null;

                if (frame.Opcode == 0x8)
                    return null;

                if (frame.Opcode == 0x9)
                {
                    await WriteFrameAsync(0xA, frame.Payload, cancellationToken);
                    continue;
                }

                if (frame.Opcode == 0xA)
                    continue;

                if (frame.Opcode != 0x0 && frame.Opcode != 0x1 && frame.Opcode != 0x2)
                    continue;

                if (frame.Fin && frame.Opcode != 0x0 && ms == null)
                    return frame.Payload;

                if (ms == null)
                    ms = new MemoryStream();
                ms.Write(frame.Payload, 0, frame.Payload.Length);

                if (frame.Fin)
                    return ms.ToArray();
            }
        }

        private async Task<Frame> ReadFrameAsync(CancellationToken cancellationToken)
        {
            byte[] header = new byte[2];
            int got = await ReadExactAsync(header, 0, 2, cancellationToken);
            if (got < 2)
                return null;

            bool fin = (header[0] & 0x80) != 0;
            byte opcode = (byte)(header[0] & 0x0F);
            bool masked = (header[1] & 0x80) != 0;
            ulong length = (ulong)(header[1] & 0x7F);

            if (length == 126)
            {
                byte[] ext = new byte[2];
                if (await ReadExactAsync(ext, 0, 2, cancellationToken) < 2)
                    return null;
                length = (ulong)((ext[0] << 8) | ext[1]);
            }
            else if (length == 127)
            {
                byte[] ext = new byte[8];
                if (await ReadExactAsync(ext, 0, 8, cancellationToken) < 8)
                    return null;
                length = 0;
                for (int i = 0; i < 8; i++)
                    length = (length << 8) | ext[i];
            }

            if (length > int.MaxValue)
                throw new InvalidOperationException("WebSocket frame too large");

            byte[] mask = null;
            if (masked)
            {
                mask = new byte[4];
                if (await ReadExactAsync(mask, 0, 4, cancellationToken) < 4)
                    return null;
            }

            byte[] payload = new byte[(int)length];
            if (payload.Length > 0 &&
                await ReadExactAsync(payload, 0, payload.Length, cancellationToken) < payload.Length)
                return null;

            if (masked)
            {
                for (int i = 0; i < payload.Length; i++)
                    payload[i] = (byte)(payload[i] ^ mask[i & 3]);
            }

            return new Frame { Fin = fin, Opcode = opcode, Payload = payload };
        }

        private async Task<int> ReadExactAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        {
            int total = 0;
            while (total < count)
            {
                int n = await _stream.ReadAsync(buffer, offset + total, count - total, cancellationToken);
                if (n == 0)
                    break;
                total += n;
            }
            return total;
        }

#if NET40
        public Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
#else
        public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
#endif
        {
            ThrowIfDisposed();
            return WriteFrameAsync(0x2, buffer, offset, count, cancellationToken);
        }

        public Task<int> ReadAsyncCompat(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        {
            return ReadAsync(buffer, offset, count, cancellationToken);
        }

        public Task WriteAsyncCompat(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        {
            return WriteAsync(buffer, offset, count, cancellationToken);
        }

        public Task FlushAsyncCompat(CancellationToken cancellationToken)
        {
            return Compat.FromResult();
        }

        private async Task WriteFrameAsync(byte opcode, byte[] payload, CancellationToken cancellationToken)
        {
            int length = payload != null ? payload.Length : 0;
            await WriteFrameAsync(opcode, payload, 0, length, cancellationToken);
        }

        private async Task WriteFrameAsync(byte opcode, byte[] payload, int offset, int count, CancellationToken cancellationToken)
        {
            await _writeSemaphore.WaitAsync();
            try
            {
                int headerLength = 2 + (_maskWrites ? 4 : 0);
                if (count >= 126 && count <= 65535)
                    headerLength += 2;
                else if (count > 65535)
                    headerLength += 8;

                byte[] frame = new byte[headerLength + count];
                int pos = 0;
                frame[pos++] = (byte)(0x80 | opcode);

                if (count < 126)
                {
                    frame[pos++] = (byte)(_maskWrites ? 0x80 | count : count);
                }
                else if (count <= 65535)
                {
                    frame[pos++] = (byte)(_maskWrites ? 0x80 | 126 : 126);
                    frame[pos++] = (byte)((count >> 8) & 0xFF);
                    frame[pos++] = (byte)(count & 0xFF);
                }
                else
                {
                    frame[pos++] = (byte)(_maskWrites ? 0x80 | 127 : 127);
                    ulong len = (ulong)count;
                    for (int i = 7; i >= 0; i--)
                        frame[pos++] = (byte)((len >> (i * 8)) & 0xFF);
                }

                byte[] mask = null;
                if (_maskWrites)
                {
                    mask = new byte[4];
                    using (var rng = RandomNumberGenerator.Create())
                    {
                        rng.GetBytes(mask);
                    }
                    Buffer.BlockCopy(mask, 0, frame, pos, 4);
                    pos += 4;
                }

                if (count > 0)
                {
                    if (_maskWrites)
                    {
                        for (int i = 0; i < count; i++)
                            frame[pos + i] = (byte)(payload[offset + i] ^ mask[i & 3]);
                    }
                    else
                    {
                        Buffer.BlockCopy(payload, offset, frame, pos, count);
                    }
                }

                await _stream.WriteAsync(frame, 0, frame.Length, cancellationToken);
                await _stream.FlushAsync(cancellationToken);
            }
            finally
            {
                _writeSemaphore.Release();
            }
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            return ReadAsync(buffer, offset, count, CancellationToken.None).GetAwaiter().GetResult();
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            WriteAsync(buffer, offset, count, CancellationToken.None).GetAwaiter().GetResult();
        }

        public override void Flush() { }
#if NET40
        public Task FlushAsync(CancellationToken cancellationToken) { return Compat.FromResult(); }
#else
        public override Task FlushAsync(CancellationToken cancellationToken) { return Compat.FromResult(); }
#endif
        public override long Seek(long offset, SeekOrigin origin) { throw new NotSupportedException(); }
        public override void SetLength(long value) { throw new NotSupportedException(); }

        protected override void Dispose(bool disposing)
        {
            if (!_disposed && disposing)
            {
                _disposed = true;
                IsOpen = false;
                try { _stream.Dispose(); } catch { }
                try { _client.Close(); } catch { }
                _writeSemaphore.Dispose();
            }
            base.Dispose(disposing);
        }

        private void ThrowIfDisposed()
        {
            if (_disposed)
                throw new ObjectDisposedException("WebSocketFrameStream");
        }

        private class Frame
        {
            public bool Fin;
            public byte Opcode;
            public byte[] Payload;
        }
    }
}
