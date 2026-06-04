using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Numerics;
using ChiselSharp.Utils;

namespace ChiselSharp.SSH
{
    /// <summary>
    /// SSH message type constants (RFC 4253).
    /// </summary>
    public static class SshMsg
    {
        public const byte SSH_MSG_DISCONNECT = 1;
        public const byte SSH_MSG_IGNORE = 2;
        public const byte SSH_MSG_UNIMPLEMENTED = 3;
        public const byte SSH_MSG_DEBUG = 4;
        public const byte SSH_MSG_SERVICE_REQUEST = 5;
        public const byte SSH_MSG_SERVICE_ACCEPT = 6;
        public const byte SSH_MSG_KEXINIT = 20;
        public const byte SSH_MSG_NEWKEYS = 21;
        public const byte SSH_MSG_KEXDH_INIT = 30;
        public const byte SSH_MSG_KEXDH_REPLY = 31;
        public const byte SSH_MSG_USERAUTH_REQUEST = 50;
        public const byte SSH_MSG_USERAUTH_FAILURE = 51;
        public const byte SSH_MSG_USERAUTH_SUCCESS = 52;
        public const byte SSH_MSG_USERAUTH_BANNER = 53;
        public const byte SSH_MSG_GLOBAL_REQUEST = 80;
        public const byte SSH_MSG_REQUEST_SUCCESS = 81;
        public const byte SSH_MSG_REQUEST_FAILURE = 82;
        public const byte SSH_MSG_CHANNEL_OPEN = 90;
        public const byte SSH_MSG_CHANNEL_OPEN_CONFIRMATION = 91;
        public const byte SSH_MSG_CHANNEL_OPEN_FAILURE = 92;
        public const byte SSH_MSG_CHANNEL_WINDOW_ADJUST = 93;
        public const byte SSH_MSG_CHANNEL_DATA = 94;
        public const byte SSH_MSG_CHANNEL_EXTENDED_DATA = 95;
        public const byte SSH_MSG_CHANNEL_EOF = 96;
        public const byte SSH_MSG_CHANNEL_CLOSE = 97;
        public const byte SSH_MSG_CHANNEL_REQUEST = 98;
        public const byte SSH_MSG_CHANNEL_SUCCESS = 99;
        public const byte SSH_MSG_CHANNEL_FAILURE = 100;
    }

    /// <summary>
    /// AES-CTR mode implementation using AesManaged with ECB mode.
    /// Uses a persistent counter that increments across ProcessBytes calls.
    /// Counter is a big-endian 128-bit integer.
    /// </summary>
    internal class AesCtrTransform : IDisposable
    {
        private byte[] _key;
        private byte[] _counter;
        private byte[] _keyStream;
        private int _blockOffset;
        private SymmetricAlgorithm _aes;
        private ICryptoTransform _encryptor;

        public AesCtrTransform(byte[] key, byte[] iv)
        {
            if (key.Length != 16)
                throw new ArgumentException("AES-128-CTR requires 16-byte key", "key");
            if (iv.Length != 16)
                throw new ArgumentException("CTR mode requires 16-byte IV", "iv");

            _key = new byte[16];
            Buffer.BlockCopy(key, 0, _key, 0, 16);
            _counter = new byte[16];
            Buffer.BlockCopy(iv, 0, _counter, 0, 16);
            _keyStream = new byte[16];
            _blockOffset = 0;

            _aes = new AesCryptoServiceProvider();
            _aes.KeySize = 128;
            _aes.Key = _key;
            _aes.Mode = CipherMode.ECB;
            _aes.Padding = PaddingMode.None;
            _encryptor = _aes.CreateEncryptor();
        }

        public void ProcessBytes(byte[] buffer, int offset, int count)
        {
            for (int i = 0; i < count; i++)
            {
                if (_blockOffset == 0)
                {
                    _encryptor.TransformBlock(_counter, 0, 16, _keyStream, 0);
                    for (int j = 15; j >= 0; j--) { _counter[j]++; if (_counter[j] != 0) break; }
                }
                buffer[offset + i] ^= _keyStream[_blockOffset];
                _blockOffset = (_blockOffset + 1) & 15;
            }
        }

        public void Dispose()
        {
            if (_encryptor != null) _encryptor.Dispose();
            if (_aes != null) _aes.Dispose();
            _key = null;
            _counter = null;
            _keyStream = null;
            _encryptor = null;
            _aes = null;
        }
    }

    /// <summary>
    /// Low-level SSH binary packet transport.
    /// Handles version exchange, DH group14 key exchange, AES-128-CTR encryption,
    /// and HMAC-SHA1 packet authentication -- with no external dependencies.
    /// </summary>
    public class SshTransport : IDisposable
    {
        // ------------------ DH group14 parameters ------------------
        private static readonly BigInteger DH_P;
        private static readonly BigInteger DH_G = 2;

        private const int MAC_LENGTH = 20; // HMAC-SHA1 (could also be 12 for hmac-sha1-96)
        private const int BLOCK_SIZE_BEFORE_ENCRYPT = 8;
        private const int BLOCK_SIZE_AFTER_ENCRYPT = 16; // AES block size
        private const int MAX_PACKET_LENGTH = 256 * 1024;

        static SshTransport()
        {
            DH_P = ParseHexBigInteger(
                "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" +
                "29024E088A67CC74020BBEA63B139B22514A08798E3404DD" +
                "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" +
                "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
                "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D" +
                "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F" +
                "83655D23DCA3AD961C62F356208552BB9ED529077096966D" +
                "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B" +
                "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9" +
                "DE2BCBF6955817183995497CEA956AE515D2261898FA0510" +
                "15728E5A8AACAA68FFFFFFFFFFFFFFFF");
        }

        private static BigInteger ParseHexBigInteger(string hex)
        {
            int len = hex.Length / 2;
            byte[] beBytes = new byte[len];
            for (int i = 0; i < len; i++)
                beBytes[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);

            // Convert big-endian to little-endian for BigInteger
            byte[] leBytes = new byte[len + 1];
            for (int i = 0; i < len; i++)
                leBytes[i] = beBytes[len - 1 - i];
            leBytes[len] = 0; // ensure positive
            return new BigInteger(leBytes);
        }

        // ------------------ Instance state ------------------

        private readonly Stream _stream;
        private readonly SemaphoreSlim _sendSemaphore = new SemaphoreSlim(1, 1);
        private readonly SemaphoreSlim _recvSemaphore = new SemaphoreSlim(1, 1);
        private bool _disposed;

        // Encryption state (null before key exchange)
        private AesCtrTransform _sendCipher;
        private AesCtrTransform _recvCipher;
        private byte[] _sendMacKey;
        private byte[] _recvMacKey;
        private HMACSHA1 _sendMac;
        private HMACSHA1 _recvMac;
        private bool _sendEncrypted;
        private bool _recvEncrypted;

        // Sequence numbers for MAC
        private uint _sendSeqNum;
        private uint _recvSeqNum;

        // Session identity
        private byte[] _sessionId;
        private byte[] _clientKexInitPayload;
        private byte[] _serverKexInitPayload;
        private string _clientVersionString;
        private string _serverVersionString;

        // Server host key (for server mode)
        private RSACryptoServiceProvider _serverRsa;
        private byte[] _serverPublicKeyBlob;

        // Public properties
        public bool IsEncrypted { get; private set; }
        public SshHostKey ServerHostKey { get; private set; }

        /// <summary>
        /// Wrap a stream (e.g. WebSocketFrameStream) with SSH binary packet framing.
        /// Call HandshakeAsync() to perform version + key exchange.
        /// </summary>
        public SshTransport(Stream stream)
        {
            if (stream == null)
                throw new ArgumentNullException("stream");

            _stream = stream;
            _clientVersionString = "SSH-2.0-chiselSharp";
        }

        // ===================== Public API =====================

        /// <summary>
        /// Generate a 2048-bit RSA host key pair for SSH server mode.
        /// Returns the key as a CSP blob (includes both public and private key).
        /// Pass this blob to HandshakeAsServerAsync().
        /// </summary>
        public static byte[] GenerateHostKey()
        {
            using (var rsa = new RSACryptoServiceProvider(2048))
            {
                return rsa.ExportCspBlob(true);
            }
        }

        /// <summary>
        /// Perform SSH version exchange and key exchange (DH group14) as server.
        /// After this succeeds, the transport is encrypted.
        /// </summary>
        public async Task HandshakeAsServerAsync(byte[] hostKey)
        {
            _serverRsa = new RSACryptoServiceProvider();
            _serverRsa.ImportCspBlob(hostKey);

            RSAParameters parameters = _serverRsa.ExportParameters(false);
            _serverPublicKeyBlob = EncodeRsaSshPublicKey(parameters);

            // 1. Version exchange (receive first, send second)
            await DoServerVersionExchangeAsync();

            // 2. KEXINIT exchange (receive first, send second)
            NegotiatedAlgorithms algos = await DoServerKexInitAsync();

            // 3. DH group14 key exchange (server role)
            await DoServerDHGroup14Async(algos);

            // 4. Exchange NEWKEYS. Per RFC 4253 and Go's crypto/ssh,
            // NEWKEYS itself is sent with the old cipher; the new cipher is
            // activated for packets after sending/receiving NEWKEYS.
            await SendPacketAsync(new byte[] { SshMsg.SSH_MSG_NEWKEYS });

            byte[] newKeysPayload = await ReceivePacketAsync();
            if (newKeysPayload == null || newKeysPayload.Length == 0 ||
                newKeysPayload[0] != SshMsg.SSH_MSG_NEWKEYS)
            {
                throw new Exception("Expected SSH_MSG_NEWKEYS from client");
            }
        }

        /// <summary>
        /// Perform SSH version exchange and key exchange (DH group14).
        /// After this succeeds, the transport is encrypted.
        /// </summary>
        public async Task HandshakeAsync()
        {
            // 1. Version exchange
            await DoVersionExchangeAsync();

            // 2. KEXINIT exchange + negotiation
            NegotiatedAlgorithms algos = await DoKexInitAsync();
            // 3. DH group14 key exchange
            await DoDHGroup14Async(algos);

            // 4. Send NEWKEYS with the old cipher, then activate the new
            // cipher for subsequent client-to-server packets.
            await SendPacketAsync(new byte[] { SshMsg.SSH_MSG_NEWKEYS });

            byte[] newKeysPayload = await ReceivePacketAsync();
            if (newKeysPayload == null || newKeysPayload.Length == 0 ||
                newKeysPayload[0] != SshMsg.SSH_MSG_NEWKEYS)
            {
                throw new Exception("Expected SSH_MSG_NEWKEYS from server");
            }

        }

        /// <summary>
        /// Send an SSH packet. The payload is the raw message content including
        /// the message type byte. Padding and (after key exchange) encryption
        /// and MAC are handled internally.
        /// </summary>
        public async Task SendPacketAsync(byte[] payload)
        {
            await _sendSemaphore.WaitAsync();
            try
            {
                bool encrypted = _sendEncrypted;
                bool changeKeys = payload != null && payload.Length > 0 &&
                    payload[0] == SshMsg.SSH_MSG_NEWKEYS;
                uint seqNum = _sendSeqNum;

                int blockSize = encrypted ? BLOCK_SIZE_AFTER_ENCRYPT : BLOCK_SIZE_BEFORE_ENCRYPT;

                // packet_length = padding_length (1) + payload + padding
                int minPacketLen = 1 + payload.Length + 4; // at least 4 bytes of padding
                int paddingLength = blockSize - ((minPacketLen) % blockSize);
                if (paddingLength < 4)
                    paddingLength += blockSize;

                int packetLength = 1 + payload.Length + paddingLength;
                int totalBeforeMac = 4 + packetLength;

                byte[] packet = new byte[totalBeforeMac];

                packet[0] = (byte)((packetLength >> 24) & 0xFF);
                packet[1] = (byte)((packetLength >> 16) & 0xFF);
                packet[2] = (byte)((packetLength >> 8) & 0xFF);
                packet[3] = (byte)(packetLength & 0xFF);
                packet[4] = (byte)paddingLength;
                Buffer.BlockCopy(payload, 0, packet, 5, payload.Length);

                int padStart = 5 + payload.Length;
                for (int i = padStart; i < totalBeforeMac; i++)
                    packet[i] = (byte)(i & 0xFF);

                byte[] mac = null;

                if (encrypted)
                {
                    // Go's writeCipherPacket for NON-EtM (hmac-sha1):
                    //   s.mac.Write(packet) -- MAC over PLAINTEXT
                    //   s.cipher.XORKeyStream(packet, packet) -- THEN encrypt
                    // MAC over plaintext matches Go's readCipherPacket which MACs over decrypted data.

                    mac = ComputeMac(_sendMac, seqNum, packet, totalBeforeMac);

                    // THEN encrypt
                    _sendCipher.ProcessBytes(packet, 0, totalBeforeMac);
                }

                byte[] wireBuf;
                if (mac != null)
                {
                    wireBuf = new byte[totalBeforeMac + MAC_LENGTH];
                    Buffer.BlockCopy(packet, 0, wireBuf, 0, totalBeforeMac);
                    Buffer.BlockCopy(mac, 0, wireBuf, totalBeforeMac, MAC_LENGTH);
                }
                else
                {
                    wireBuf = packet;
                }

                await _stream.WriteAsync(wireBuf, 0, wireBuf.Length);
                await _stream.FlushAsync();

                _sendSeqNum++;
                if (changeKeys)
                    ActivateSendCipher();
            }
            finally
            {
                _sendSemaphore.Release();
            }
        }

        /// <summary>
        /// Receive an SSH packet payload. Blocks until a complete packet arrives.
        /// Handles decryption and MAC verification when in encrypted mode.
        /// </summary>
        public async Task<byte[]> ReceivePacketAsync()
        {
            await _recvSemaphore.WaitAsync();
            try
            {
                return await ReceivePacketCoreAsync();
            }
            finally
            {
                _recvSemaphore.Release();
            }
        }

        private async Task<byte[]> ReceivePacketCoreAsync()
        {
            bool encrypted = _recvEncrypted;
            uint seqNum = _recvSeqNum;
            int packetLength;
            int totalBeforeMac;
            byte[] packet;

            if (encrypted)
            {
                byte[] firstBlock = new byte[BLOCK_SIZE_AFTER_ENCRYPT];
                int got = await ReadExactAsync(firstBlock, 0, firstBlock.Length);
                if (got < firstBlock.Length)
                    return null;

                _recvCipher.ProcessBytes(firstBlock, 0, firstBlock.Length);
                packetLength = ReadPacketLength(firstBlock);
                int paddingLengthFromPrefix = firstBlock[4];
                ValidatePacketLength(packetLength, paddingLengthFromPrefix);

                totalBeforeMac = 4 + packetLength;
                packet = new byte[totalBeforeMac];
                Buffer.BlockCopy(firstBlock, 0, packet, 0, firstBlock.Length);

                int remainingEncrypted = totalBeforeMac - firstBlock.Length;
                if (remainingEncrypted > 0)
                {
                    got = await ReadExactAsync(packet, firstBlock.Length, remainingEncrypted);
                    if (got < remainingEncrypted)
                        return null;
                    _recvCipher.ProcessBytes(packet, firstBlock.Length, remainingEncrypted);
                }

                byte[] mac = new byte[MAC_LENGTH];
                got = await ReadExactAsync(mac, 0, MAC_LENGTH);
                if (got < MAC_LENGTH)
                    return null;

                byte[] expectedMac = ComputeMac(_recvMac, seqNum, packet, totalBeforeMac);
                if (!ConstantTimeEquals(mac, expectedMac))
                    throw new Exception("MAC verification failed");
            }
            else
            {
                byte[] lenBuf = new byte[4];
                int got = await ReadExactAsync(lenBuf, 0, 4);
                if (got < 4)
                    return null;

                packetLength = ReadPacketLength(lenBuf);
                ValidatePacketLength(packetLength, -1);

                totalBeforeMac = 4 + packetLength;
                packet = new byte[totalBeforeMac];
                Buffer.BlockCopy(lenBuf, 0, packet, 0, 4);

                got = await ReadExactAsync(packet, 4, packetLength);
                if (got < packetLength)
                    return null;

                ValidatePacketLength(packetLength, packet[4]);
            }

            _recvSeqNum++;

            // Extract payload
            int paddingLength = packet[4];
            int payloadLength = packetLength - paddingLength - 1;

            if (payloadLength < 0)
                throw new Exception("Invalid SSH packet: padding_length exceeds packet_length");

            byte[] payload = new byte[payloadLength];
            Buffer.BlockCopy(packet, 5, payload, 0, payloadLength);

            if (payload.Length > 0 && payload[0] == SshMsg.SSH_MSG_NEWKEYS)
                ActivateReceiveCipher();

            return payload;
        }

        // ===================== Version Exchange =====================

        private async Task DoVersionExchangeAsync()
        {
            string clientLine = _clientVersionString + "\r\n";
            byte[] clientBytes = Encoding.UTF8.GetBytes(clientLine);
            await _stream.WriteAsync(clientBytes, 0, clientBytes.Length);
            await _stream.FlushAsync();

            // Read server version line ALL AT ONCE to avoid consuming past \r\n.
            // WebSocketFrameStream reads full messages - a single ReadAsync with a large
            // buffer gets the entire version line without over-reading into KEXINIT.
            byte[] buf = new byte[256];
            int n = await _stream.ReadAsync(buf, 0, buf.Length);
            if (n == 0)
                throw new Exception("Server disconnected during version exchange");

            // Find \r\n
            for (int i = 1; i < n; i++)
            {
                if (buf[i] == '\n' && buf[i - 1] == '\r')
                {
                    _serverVersionString = Encoding.UTF8.GetString(buf, 0, i - 1);
                    return;
                }
            }

            throw new Exception("Version line too long or no CR LF found in: " + Encoding.UTF8.GetString(buf, 0, Math.Min(n, 80)));
        }

        /// <summary>
        /// Read exactly count bytes from the stream.
        /// </summary>
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

        private static byte[] EncodeSequence(uint seqNum)
        {
            return new byte[]
            {
                (byte)((seqNum >> 24) & 0xFF),
                (byte)((seqNum >> 16) & 0xFF),
                (byte)((seqNum >> 8) & 0xFF),
                (byte)(seqNum & 0xFF)
            };
        }

        private static int ReadPacketLength(byte[] buf)
        {
            return (buf[0] << 24) | (buf[1] << 16) | (buf[2] << 8) | buf[3];
        }

        private static void ValidatePacketLength(int packetLength, int paddingLength)
        {
            if (packetLength < 1 || packetLength > MAX_PACKET_LENGTH)
                throw new Exception("Invalid SSH packet length: " + packetLength);

            if (paddingLength >= 0 && packetLength <= paddingLength + 1)
                throw new Exception("Invalid SSH packet length: packet too small");
        }

        private void ActivateSendCipher()
        {
            if (_sendCipher == null)
                throw new Exception("No SSH send cipher available for NEWKEYS");

            _sendEncrypted = true;
            UpdateEncryptionState();
        }

        private void ActivateReceiveCipher()
        {
            if (_recvCipher == null)
                throw new Exception("No SSH receive cipher available for NEWKEYS");

            _recvEncrypted = true;
            UpdateEncryptionState();
        }

        private void UpdateEncryptionState()
        {
            IsEncrypted = _sendEncrypted && _recvEncrypted;
        }

        // ===================== KEXINIT Exchange =====================

        private class NegotiatedAlgorithms
        {
            public string Kex;
            public string HostKey;
            public string Cipher;
            public string Mac;
            public string Compression;
        }

        private async Task<NegotiatedAlgorithms> DoKexInitAsync()
        {
            // Build client KEXINIT payload
            byte[] clientPayload = BuildKexInitPayload("ssh-rsa,ecdsa-sha2-nistp256,ssh-ed25519");
            _clientKexInitPayload = clientPayload;

            await SendPacketAsync(clientPayload);

            // Receive server KEXINIT
            byte[] serverPayload = await ReceivePacketAsync();
            if (serverPayload == null || serverPayload.Length == 0 ||
                serverPayload[0] != SshMsg.SSH_MSG_KEXINIT)
            {
                throw new Exception("Expected SSH_MSG_KEXINIT from server");
            }
            _serverKexInitPayload = serverPayload;

            // Negotiate algorithms
            NegotiatedAlgorithms algos = new NegotiatedAlgorithms();

            string[] myKex = new string[] { "diffie-hellman-group14-sha1" };
            string[] serverKex = ParseKexInitAlgorithms(serverPayload, 0);
            algos.Kex = FindMatch(myKex, serverKex);
            if (algos.Kex == null)
                throw new Exception("No common key exchange algorithm");

            string[] myHostKey = new string[] { "ssh-rsa", "ecdsa-sha2-nistp256", "ssh-ed25519" };
            string[] serverHostKey = ParseKexInitAlgorithms(serverPayload, 1);
            algos.HostKey = FindMatch(myHostKey, serverHostKey);
            if (algos.HostKey == null)
                throw new Exception("No common host key algorithm");

            // Use same cipher for both directions
            string[] myCipher = new string[] { "aes128-ctr" };
            string[] serverCipherC2S = ParseKexInitAlgorithms(serverPayload, 2);
            algos.Cipher = FindMatch(myCipher, serverCipherC2S);
            if (algos.Cipher == null)
                throw new Exception("No common encryption algorithm");

            string[] myMac = new string[] { "hmac-sha1" };
            string[] serverMacC2S = ParseKexInitAlgorithms(serverPayload, 4);
            algos.Mac = FindMatch(myMac, serverMacC2S);
            if (algos.Mac == null)
                throw new Exception("No common MAC algorithm");

            string[] myComp = new string[] { "none" };
            string[] serverCompC2S = ParseKexInitAlgorithms(serverPayload, 6);
            algos.Compression = FindMatch(myComp, serverCompC2S);
            if (algos.Compression == null)
                throw new Exception("No common compression algorithm");

            return algos;
        }

        private byte[] BuildKexInitPayload(string hostKeyAlgorithms)
        {
            using (var ms = new MemoryStream())
            {
                ms.WriteByte(SshMsg.SSH_MSG_KEXINIT);

                // Cookie: 16 random bytes
                byte[] cookie = new byte[16];
                using (var rng = RandomNumberGenerator.Create())
                {
                    rng.GetBytes(cookie);
                }
                ms.Write(cookie, 0, 16);

                // Algorithm name lists
                WriteString(ms, "diffie-hellman-group14-sha1");
                WriteString(ms, hostKeyAlgorithms);
                WriteString(ms, "aes128-ctr");
                WriteString(ms, "aes128-ctr");
                WriteString(ms, "hmac-sha1");
                WriteString(ms, "hmac-sha1");
                WriteString(ms, "none");
                WriteString(ms, "none");
                WriteString(ms, ""); // languages c2s
                WriteString(ms, ""); // languages s2c

                // first_kex_packet_follows = 0
                ms.WriteByte(0);

                // reserved = 0 (uint32)
                ms.Write(new byte[4], 0, 4);

                return ms.ToArray();
            }
        }

        private static void WriteString(MemoryStream ms, string str)
        {
            byte[] strBytes = Encoding.UTF8.GetBytes(str);
            byte[] lenBytes = SshWire.EncodeUint32((uint)strBytes.Length);
            ms.Write(lenBytes, 0, 4);
            ms.Write(strBytes, 0, strBytes.Length);
        }

        private static string[] ParseKexInitAlgorithms(byte[] payload, int algoIndex)
        {
            int offset = 1; // skip message type
            offset += 16; // skip cookie

            // Read algoIndex strings (0-based)
            for (int i = 0; i < algoIndex; i++)
            {
                if (offset + 4 > payload.Length)
                    return new string[0];
                uint len = SshWire.ReadUint32(payload, ref offset);
                offset += (int)len;
            }

            if (offset + 4 > payload.Length)
                return new string[0];
            uint myLen = SshWire.ReadUint32(payload, ref offset);
            if (myLen == 0)
                return new string[0];
            string algoList = Encoding.UTF8.GetString(payload, offset, (int)myLen);
            return algoList.Split(',');
        }

        private static string FindMatch(string[] preferred, string[] server)
        {
            HashSet<string> serverSet = new HashSet<string>(server, StringComparer.Ordinal);
            foreach (string algo in preferred)
            {
                if (serverSet.Contains(algo))
                    return algo;
            }
            return null;
        }

        // ===================== DH Group14 Key Exchange =====================

        private async Task DoDHGroup14Async(NegotiatedAlgorithms algos)
        {
            // Generate client DH keypair
            byte[] privateBytes = new byte[256];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(privateBytes);
            }

            // Interpret as a big-endian integer
            byte[] privateLe = new byte[257];
            for (int i = 0; i < 256; i++)
                privateLe[i] = privateBytes[255 - i];
            privateLe[256] = 0; // ensure positive
            BigInteger privateKey = new BigInteger(privateLe);

            // e = g^private mod p
            BigInteger e = BigInteger.ModPow(DH_G, privateKey, DH_P);

            // Build and send KEXDH_INIT
            byte[] eMpint = SshWire.EncodeMpint(e);
            byte[] initPayload = new byte[1 + eMpint.Length];
            initPayload[0] = SshMsg.SSH_MSG_KEXDH_INIT;
            Buffer.BlockCopy(eMpint, 0, initPayload, 1, eMpint.Length);

            await SendPacketAsync(initPayload);

            // Read KEXDH_REPLY
            byte[] replyPayload = await ReceivePacketAsync();
            if (replyPayload == null || replyPayload.Length == 0 ||
                replyPayload[0] != SshMsg.SSH_MSG_KEXDH_REPLY)
            {
                throw new Exception("Expected SSH_MSG_KEXDH_REPLY from server");
            }

            // Parse KEXDH_REPLY: string host_key, mpint f, string signature
            int offset = 1;

            // Read host key
            uint hostKeyLen = SshWire.ReadUint32(replyPayload, ref offset);

            // Go's crypto/ssh uses K_S (the host key blob) directly in writeString(h, K_S).
            // K_S already contains the algorithm name as an SSH string at the beginning
            // (e.g. [4-byte len(7)]["ssh-rsa"][mpint e][mpint n]).
            // writeString adds a 4-byte length prefix around K_S. So we must NOT prepend
            // the algorithm name again; hostKeyData already includes it.
            byte[] hostKeyData = new byte[hostKeyLen];
            Buffer.BlockCopy(replyPayload, offset, hostKeyData, 0, (int)hostKeyLen);
            // Wrap in STRING encoding for writeString(h, K_S)
            byte[] hostKeyFullBlob = SshWire.EncodeBytes(hostKeyData);

            // Advance offset past host key data (already read above)
            offset += (int)hostKeyLen;

            // Store host key
            ServerHostKey = SshHostKey.Parse(hostKeyData);

            // Continue parsing f and signature
            BigInteger f = SshWire.ReadMpint(replyPayload, ref offset);
            byte[] signature = SshWire.ReadBytes(replyPayload, ref offset);

            // Compute shared secret: K = f^private mod p
            BigInteger sharedSecret = BigInteger.ModPow(f, privateKey, DH_P);

            if (Logger.Verbose)
            {
                byte[] kRawDbg = BigIntegerToMinimalBigEndian(sharedSecret);
                byte[] fRawDbg = BigIntegerToMinimalBigEndian(f);
                byte[] privRawDbg = BigIntegerToMinimalBigEndian(privateKey);
                byte[] pRawDbg = BigIntegerToMinimalBigEndian(DH_P);
                Logger.Debug("DH key sizes:");
                Logger.Debug("  P length=" + pRawDbg.Length);
                Logger.Debug("  f length=" + fRawDbg.Length + " privateKey length=" + privRawDbg.Length);
                Logger.Debug("  K length=" + kRawDbg.Length);
                if (kRawDbg.Length > 256)
                    Logger.Debug("  WARNING: K length > 256 bytes, something is wrong!");
            }

            // Build exchange hash H. Go's writeInt/marshalInt writes SSH
            // mpint bytes, including the uint32 length prefix.
            byte[] eVal = SshWire.EncodeMpint(e);
            byte[] fVal = SshWire.EncodeMpint(f);
            byte[] kVal = SshWire.EncodeMpint(sharedSecret);
            byte[] h = ComputeExchangeHash(hostKeyFullBlob, eVal, fVal, kVal);

            // Save session_id (H from first key exchange)
            if (_sessionId == null)
            {
                _sessionId = new byte[h.Length];
                Buffer.BlockCopy(h, 0, _sessionId, 0, h.Length);
            }

            // Derive keys using Go's kexResult.K bytes: SSH mpint encoding.
            DeriveKeys(SshWire.EncodeMpint(sharedSecret), h, false);
        }

        // ===================== Server Mode Key Exchange =====================

        private async Task DoServerVersionExchangeAsync()
        {
            // Read client version line (until \r\n)
            byte[] buffer = new byte[4096];
            int totalRead = 0;
            bool foundCr = false;

            while (totalRead < buffer.Length)
            {
                int n = await _stream.ReadAsync(buffer, totalRead, 1);
                if (n == 0)
                    throw new Exception("Client disconnected during version exchange");

                if (buffer[totalRead] == '\r')
                {
                    foundCr = true;
                }
                else if (buffer[totalRead] == '\n' && foundCr)
                {
                    string versionLine = Encoding.UTF8.GetString(buffer, 0, totalRead - 1);
                    _clientVersionString = versionLine;

                    // Send server version
                    _serverVersionString = "SSH-2.0-chiselSharp";
                    string serverLine = _serverVersionString + "\r\n";
                    byte[] serverBytes = Encoding.UTF8.GetBytes(serverLine);
                    _stream.Write(serverBytes, 0, serverBytes.Length);
                    await _stream.FlushAsync();
                    return;
                }
                else
                {
                    foundCr = false;
                }

                totalRead++;
            }

            throw new Exception("Version line too long or no CR LF found");
        }

        private async Task<NegotiatedAlgorithms> DoServerKexInitAsync()
        {
            // Receive client KEXINIT first
            byte[] clientPayload = await ReceivePacketAsync();
            if (clientPayload == null || clientPayload.Length == 0 ||
                clientPayload[0] != SshMsg.SSH_MSG_KEXINIT)
            {
                throw new Exception("Expected SSH_MSG_KEXINIT from client");
            }
            _clientKexInitPayload = clientPayload;

            // Send server KEXINIT
            byte[] serverPayload = BuildKexInitPayload("ssh-rsa");
            _serverKexInitPayload = serverPayload;
            await SendPacketAsync(serverPayload);

            // Negotiate algorithms (server picks from client's lists)
            NegotiatedAlgorithms algos = new NegotiatedAlgorithms();

            string[] myKex = new string[] { "diffie-hellman-group14-sha1" };
            string[] clientKex = ParseKexInitAlgorithms(clientPayload, 0);
            algos.Kex = FindMatch(myKex, clientKex);
            if (algos.Kex == null)
                throw new Exception("No common key exchange algorithm");

            string[] myHostKey = new string[] { "ssh-rsa", "ecdsa-sha2-nistp256", "ssh-ed25519" };
            string[] clientHostKey = ParseKexInitAlgorithms(clientPayload, 1);
            algos.HostKey = FindMatch(myHostKey, clientHostKey);
            if (algos.HostKey == null)
                throw new Exception("No common host key algorithm");

            string[] myCipher = new string[] { "aes128-ctr" };
            string[] clientCipherC2S = ParseKexInitAlgorithms(clientPayload, 2);
            algos.Cipher = FindMatch(myCipher, clientCipherC2S);
            if (algos.Cipher == null)
            {
                string[] clientCipherS2C = ParseKexInitAlgorithms(clientPayload, 3);
                algos.Cipher = FindMatch(myCipher, clientCipherS2C);
            }
            if (algos.Cipher == null)
                throw new Exception("No common encryption algorithm");

            string[] myMac = new string[] { "hmac-sha1" };
            string[] clientMacC2S = ParseKexInitAlgorithms(clientPayload, 4);
            algos.Mac = FindMatch(myMac, clientMacC2S);
            if (algos.Mac == null)
            {
                string[] clientMacS2C = ParseKexInitAlgorithms(clientPayload, 5);
                algos.Mac = FindMatch(myMac, clientMacS2C);
            }
            if (algos.Mac == null)
                throw new Exception("No common MAC algorithm");

            string[] myComp = new string[] { "none" };
            string[] clientCompC2S = ParseKexInitAlgorithms(clientPayload, 6);
            algos.Compression = FindMatch(myComp, clientCompC2S);
            if (algos.Compression == null)
            {
                string[] clientCompS2C = ParseKexInitAlgorithms(clientPayload, 7);
                algos.Compression = FindMatch(myComp, clientCompS2C);
            }
            if (algos.Compression == null)
                throw new Exception("No common compression algorithm");

            return algos;
        }

        private async Task DoServerDHGroup14Async(NegotiatedAlgorithms algos)
        {
            // Generate server DH keypair
            byte[] privateBytes = new byte[256];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(privateBytes);
            }

            byte[] privateLe = new byte[257];
            for (int i = 0; i < 256; i++)
                privateLe[i] = privateBytes[255 - i];
            privateLe[256] = 0;
            BigInteger privateKey = new BigInteger(privateLe);

            // f = g^private mod p
            BigInteger f = BigInteger.ModPow(DH_G, privateKey, DH_P);

            // Receive KEXDH_INIT from client
            byte[] initPayload = await ReceivePacketAsync();
            if (initPayload == null || initPayload.Length == 0 ||
                initPayload[0] != SshMsg.SSH_MSG_KEXDH_INIT)
            {
                throw new Exception("Expected SSH_MSG_KEXDH_INIT from client");
            }

            // Parse e from client
            int offset = 1;
            BigInteger e = SshWire.ReadMpint(initPayload, ref offset);

            // Compute shared secret: K = e^private mod p
            BigInteger sharedSecret = BigInteger.ModPow(e, privateKey, DH_P);

            // Build values for exchange hash. Go's writeInt/marshalInt writes
            // SSH mpint bytes, including the uint32 length prefix.
            byte[] eVal = SshWire.EncodeMpint(e);
            byte[] fVal = SshWire.EncodeMpint(f);
            byte[] kVal = SshWire.EncodeMpint(sharedSecret);

            // Go's crypto/ssh uses K_S (the host key blob) directly in writeString(h, K_S).
            // _serverPublicKeyBlob already contains the algorithm name as an SSH string at
            // the beginning. Do NOT prepend the algorithm name again.
            byte[] hostKeyString = SshWire.EncodeBytes(_serverPublicKeyBlob);

            // Compute exchange hash H
            byte[] h = ComputeExchangeHash(hostKeyString, eVal, fVal, kVal);

            // Save session_id
            if (_sessionId == null)
            {
                _sessionId = new byte[h.Length];
                Buffer.BlockCopy(h, 0, _sessionId, 0, h.Length);
            }

            // Sign H with host key
            byte[] signature = SignHash(h);

            // Build and send KEXDH_REPLY (f is sent on wire as SSH mpint with length prefix)
            byte[] fMpint = SshWire.EncodeMpint(f);
            using (var ms = new MemoryStream())
            {
                ms.WriteByte(SshMsg.SSH_MSG_KEXDH_REPLY);

                // K_S: string(host_key_data)
                byte[] ksBlob = SshWire.EncodeBytes(_serverPublicKeyBlob);
                ms.Write(ksBlob, 0, ksBlob.Length);

                // f: mpint
                ms.Write(fMpint, 0, fMpint.Length);

                // signature: string(sig_blob)
                byte[] sigBlob = SshWire.EncodeBytes(signature);
                ms.Write(sigBlob, 0, sigBlob.Length);

                await SendPacketAsync(ms.ToArray());
            }

            // Derive keys using Go's kexResult.K bytes: SSH mpint encoding.
            DeriveKeys(SshWire.EncodeMpint(sharedSecret), h, true);
        }

        private byte[] SignHash(byte[] h)
        {
            // For ssh-rsa, the SSH signature blob is:
            // string "ssh-rsa" + string(RSA_PKCS1_SHA1_signature)

            byte[] digest;
            using (var sha1 = new SHA1CryptoServiceProvider())
            {
                digest = sha1.ComputeHash(h);
            }

            // Go's ssh-rsa signer hashes the exchange hash H with SHA1,
            // then signs that digest using RSA PKCS#1 v1.5.
            RSAPKCS1SignatureFormatter formatter = new RSAPKCS1SignatureFormatter(_serverRsa);
            formatter.SetHashAlgorithm("SHA1");
            byte[] rawSignature = formatter.CreateSignature(digest);

            // Build the SSH signature blob
            using (var ms = new MemoryStream())
            {
                WriteString(ms, "ssh-rsa");
                byte[] sigString = SshWire.EncodeBytes(rawSignature);
                ms.Write(sigString, 0, sigString.Length);
                return ms.ToArray();
            }
        }

        private byte[] EncodeRsaSshPublicKey(RSAParameters parameters)
        {
            using (var ms = new MemoryStream())
            {
                WriteString(ms, "ssh-rsa");

                // e as mpint
                BigInteger e = BigEndianBytesToBigInteger(parameters.Exponent);
                byte[] eMpint = SshWire.EncodeMpint(e);
                ms.Write(eMpint, 0, eMpint.Length);

                // n as mpint
                BigInteger n = BigEndianBytesToBigInteger(parameters.Modulus);
                byte[] nMpint = SshWire.EncodeMpint(n);
                ms.Write(nMpint, 0, nMpint.Length);

                return ms.ToArray();
            }
        }

        private static BigInteger BigEndianBytesToBigInteger(byte[] beBytes)
        {
            byte[] leBytes = new byte[beBytes.Length + 1];
            for (int i = 0; i < beBytes.Length; i++)
                leBytes[i] = beBytes[beBytes.Length - 1 - i];
            leBytes[beBytes.Length] = 0;
            return new BigInteger(leBytes);
        }

        private byte[] ComputeExchangeHash(byte[] hostKeyBlob, byte[] eVal, byte[] fVal, byte[] kVal)
        {
            // Go's crypto/ssh computes H as:
            // H = SHA1(
            //     string(V_C) || string(V_S) || string(I_C) || string(I_S) ||
            //     string(K_S) ||
            //     mpint_val(e) || mpint_val(f) || mpint_val(K)
            // )
            // where string(X) = 4-byte BE length + X   (writeString)
            // and mpint(X) = uint32 length + signed two's-complement bytes
            // as emitted by writeInt/marshalInt.
            //
            // This matches Go's implementation in kex.go:
            //   magics.write(h)  -> writeString for V_C, V_S, I_C, I_S
            //   writeString(h, K_S)
            //   writeInt(h, e) / writeInt(h, f) / marshalInt(K) -> just value bytes
            byte[] vC = SshWire.EncodeBytes(Encoding.UTF8.GetBytes(_clientVersionString));
            byte[] vS = SshWire.EncodeBytes(Encoding.UTF8.GetBytes(_serverVersionString));
            byte[] iC = SshWire.EncodeBytes(_clientKexInitPayload);
            byte[] iS = SshWire.EncodeBytes(_serverKexInitPayload);

            int totalLen = vC.Length + vS.Length + iC.Length + iS.Length +
                           hostKeyBlob.Length +
                           eVal.Length + fVal.Length + kVal.Length;

            byte[] data = new byte[totalLen];
            int offset = 0;

            Buffer.BlockCopy(vC, 0, data, offset, vC.Length); offset += vC.Length;
            Buffer.BlockCopy(vS, 0, data, offset, vS.Length); offset += vS.Length;
            Buffer.BlockCopy(iC, 0, data, offset, iC.Length); offset += iC.Length;
            Buffer.BlockCopy(iS, 0, data, offset, iS.Length); offset += iS.Length;
            Buffer.BlockCopy(hostKeyBlob, 0, data, offset, hostKeyBlob.Length); offset += hostKeyBlob.Length;
            Buffer.BlockCopy(eVal, 0, data, offset, eVal.Length); offset += eVal.Length;
            Buffer.BlockCopy(fVal, 0, data, offset, fVal.Length); offset += fVal.Length;
            Buffer.BlockCopy(kVal, 0, data, offset, kVal.Length); offset += kVal.Length;

            using (var sha1 = new SHA1CryptoServiceProvider())
            {
                byte[] result = sha1.ComputeHash(data);
                if (Logger.Verbose)
                {
                    Logger.Debug("Exchange hash H=" + HexDump(result));
                    Logger.Debug("  vC=" + HexDump(vC) + " vS=" + HexDump(vS));
                    Logger.Debug("  hostKey=" + HexDump(hostKeyBlob));
                    Logger.Debug("  eVal=" + HexDump(eVal) + " fVal=" + HexDump(fVal) + " kVal=" + HexDump(kVal));
                }
                return result;
            }
        }

        // ===================== Key Derivation (RFC 4253 section 7.2) =====================

        private void DeriveKeys(byte[] kRaw, byte[] h, bool isServer)
        {
            byte[] sessionId = _sessionId ?? h;

            // Initial IV client-to-server: SHA1(K || H || "A" || session_id)
            byte[] ivC2S = DeriveKeyMaterial(kRaw, h, sessionId, 0x41, 16); // "A"

            // Initial IV server-to-client: SHA1(K || H || "B" || session_id)
            byte[] ivS2C = DeriveKeyMaterial(kRaw, h, sessionId, 0x42, 16); // "B"

            // Encryption key client-to-server: SHA1(K || H || "C" || session_id)
            byte[] encC2S = DeriveKeyMaterial(kRaw, h, sessionId, 0x43, 16); // "C"

            // Encryption key server-to-client: SHA1(K || H || "D" || session_id)
            byte[] encS2C = DeriveKeyMaterial(kRaw, h, sessionId, 0x44, 16); // "D"

            // Integrity key client-to-server: SHA1(K || H || "E" || session_id)
            byte[] macC2S = DeriveKeyMaterial(kRaw, h, sessionId, 0x45, 20); // "E" - full SHA1 output

            // Integrity key server-to-client: SHA1(K || H || "F" || session_id)
            byte[] macS2C = DeriveKeyMaterial(kRaw, h, sessionId, 0x46, 20); // "F" - full SHA1 output

            if (Logger.Verbose)
            {
                Logger.Debug("Key derivation (mpint K, raw H, raw session_id):");
                Logger.Debug("  K length=" + kRaw.Length + " H length=" + h.Length);
                Logger.Debug("  ivC2S=" + HexDump(ivC2S));
                Logger.Debug("  ivS2C=" + HexDump(ivS2C));
                Logger.Debug("  encC2S=" + HexDump(encC2S));
                Logger.Debug("  encS2C=" + HexDump(encS2C));
                Logger.Debug("  macC2S=" + HexDump(macC2S));
                Logger.Debug("  macS2C=" + HexDump(macS2C));
            }

            // debug removed
            if (isServer)
            {
                _sendCipher = new AesCtrTransform(encS2C, ivS2C);
                _recvCipher = new AesCtrTransform(encC2S, ivC2S);
                _sendMacKey = macS2C;
                _recvMacKey = macC2S;
            }
            else
            {
                _sendCipher = new AesCtrTransform(encC2S, ivC2S);
                _recvCipher = new AesCtrTransform(encS2C, ivS2C);
                _sendMacKey = macC2S;
                _recvMacKey = macS2C;
            }

            if (_sendMac != null) _sendMac.Dispose();
            if (_recvMac != null) _recvMac.Dispose();
            _sendMac = new HMACSHA1(_sendMacKey);
            _recvMac = new HMACSHA1(_recvMacKey);
        }

        private static string HexDump(byte[] bytes)
        {
            if (bytes == null) return "null";
            var sb = new StringBuilder(bytes.Length * 2);
            foreach (byte b in bytes)
                sb.Append(b.ToString("x2"));
            return sb.ToString();
        }

        /// <summary>
        /// Marshal a BigInteger as an SSH mpint, exactly matching Go's ssh.Marshal().
        /// Go's ssh.Marshal: strips leading zeros, adds 0x00 sign byte if MSB set,
        /// then prepends 4-byte big-endian length.
        /// </summary>
        private static byte[] MarshalMpint(System.Numerics.BigInteger value)
        {
            byte[] raw = BigIntegerToMinimalBigEndian(value);
            // Remove leading zeros (matching Go's loop: for b[0]==0 && b[1]&0x80==0 { b = b[1:] })
            while (raw.Length > 1 && raw[0] == 0 && (raw[1] & 0x80) == 0)
                raw = Slice(raw, 1);
            // If MSB is set, prepend 0x00
            if (raw.Length > 0 && (raw[0] & 0x80) != 0)
            {
                byte[] withSign = new byte[raw.Length + 1];
                withSign[0] = 0;
                Buffer.BlockCopy(raw, 0, withSign, 1, raw.Length);
                raw = withSign;
            }
            // Prepend 4-byte BE length
            return SshWire.EncodeBytes(raw);
        }

        private static byte[] Slice(byte[] src, int start)
        {
            byte[] dst = new byte[src.Length - start];
            Buffer.BlockCopy(src, start, dst, 0, dst.Length);
            return dst;
        }

        /// <summary>
        /// Convert BigInteger to MINIMAL big-endian byte array (matching Go's big.Int.Bytes()).
        /// Used for DH shared secret in key derivation.
        /// </summary>
        private static byte[] BigIntegerToMinimalBigEndian(System.Numerics.BigInteger value)
        {
            byte[] bytes = value.ToByteArray(); // little-endian, may have trailing 0x00 sign byte
            int len = bytes.Length;
            // Remove trailing 0x00 sign byte if present
            if (len > 1 && bytes[len - 1] == 0) len--;
            // Convert to big-endian (minimal, no leading zeros)
            byte[] result = new byte[len];
            for (int i = 0; i < len; i++)
                result[i] = bytes[len - 1 - i];
            return result;
        }

        // VERIFIED against Go reference: K uses mpintWriter (ssh.Marshal = MarshalMpint)
        // H and session_id use stringWriter (writeString = EncodeBytes).
        // Caller MUST pass K already encoded via MarshalMpint.
        private static byte[] DeriveOne(byte[] ke, byte[] h, byte suf, int n) {
            byte[] hs = SshWire.EncodeBytes(h);
            byte[] input = new byte[ke.Length + hs.Length + 1 + hs.Length];
            int o=0;
            Buffer.BlockCopy(ke,0,input,o,ke.Length);o+=ke.Length;
            Buffer.BlockCopy(hs,0,input,o,hs.Length);o+=hs.Length;
            input[o]=suf;o++;
            Buffer.BlockCopy(hs,0,input,o,hs.Length);
            using(var sha1=new SHA1CryptoServiceProvider()){byte[] hh=sha1.ComputeHash(input);byte[] r=new byte[n];Buffer.BlockCopy(hh,0,r,0,n);return r;}
        }

        // Go's crypto/ssh generateKeyMaterial writes kexResult.K, H, and
        // session_id directly. For DH group14, kexResult.K is SSH mpint bytes.
        // We match this exactly.
        private static byte[] DeriveKeyMaterial(byte[] kRaw, byte[] h, byte[] sessionId, byte suffix, int neededBytes)
        {
            byte[] input = new byte[kRaw.Length + h.Length + 1 + sessionId.Length];
            int offset = 0;
            Buffer.BlockCopy(kRaw, 0, input, offset, kRaw.Length); offset += kRaw.Length;
            Buffer.BlockCopy(h, 0, input, offset, h.Length); offset += h.Length;
            input[offset] = suffix; offset++;
            Buffer.BlockCopy(sessionId, 0, input, offset, sessionId.Length);

            byte[] hash;
            using (var sha1 = new SHA1CryptoServiceProvider())
            {
                hash = sha1.ComputeHash(input);
            }

            if (hash.Length >= neededBytes)
            {
                byte[] result = new byte[neededBytes];
                Buffer.BlockCopy(hash, 0, result, 0, neededBytes);
                return result;
            }

            // Extension: chain additional hashes (not normally needed for AES-128 + HMAC-SHA1)
            // but implemented for completeness
            List<byte> all = new List<byte>();
            all.AddRange(hash);

            while (all.Count < neededBytes)
            {
                // Extended: SHA1(K || H || all previous digests), matching Go.
                byte[] previous = all.ToArray();
                byte[] extended = new byte[kRaw.Length + h.Length + previous.Length];
                int o = 0;
                Buffer.BlockCopy(kRaw, 0, extended, o, kRaw.Length); o += kRaw.Length;
                Buffer.BlockCopy(h, 0, extended, o, h.Length); o += h.Length;
                Buffer.BlockCopy(previous, 0, extended, o, previous.Length);

                using (var sha1 = new SHA1CryptoServiceProvider())
                {
                    hash = sha1.ComputeHash(extended);
                }
                all.AddRange(hash);
            }

            byte[] result2 = new byte[neededBytes];
            for (int i = 0; i < neededBytes; i++)
                result2[i] = all[i];
            return result2;
        }

        // ===================== I/O Helpers =====================

        private static bool ConstantTimeEquals(byte[] a, byte[] b)
        {
            if (a.Length != b.Length) return false;
            int diff = 0;
            for (int i = 0; i < a.Length; i++)
                diff |= a[i] ^ b[i];
            return diff == 0;
        }

        private static byte[] ComputeMac(HMACSHA1 hmac, uint seqNum, byte[] packet, int packetLength)
        {
            if (hmac == null)
                throw new InvalidOperationException("MAC has not been initialized");

            byte[] seqBuf = EncodeSequence(seqNum);
            hmac.Initialize();
            hmac.TransformBlock(seqBuf, 0, seqBuf.Length, seqBuf, 0);
            hmac.TransformFinalBlock(packet, 0, packetLength);
            return hmac.Hash;
        }

        // ===================== IDisposable =====================

        public void Dispose()
        {
            if (!_disposed)
            {
                _disposed = true;
                if (_sendCipher != null) _sendCipher.Dispose();
                if (_recvCipher != null) _recvCipher.Dispose();
                if (_sendMac != null) _sendMac.Dispose();
                if (_recvMac != null) _recvMac.Dispose();
                _sendCipher = null;
                _recvCipher = null;
                _sendMacKey = null;
                _recvMacKey = null;
                _sendMac = null;
                _recvMac = null;
                _sessionId = null;
                _sendSemaphore.Dispose();
                _recvSemaphore.Dispose();
            }
        }
    }
}
