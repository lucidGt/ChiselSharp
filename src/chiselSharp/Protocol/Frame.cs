using System;
using System.IO;
using System.Text;

namespace ChiselSharp.Protocol
{
    [Flags]
    public enum FrameFlags : byte
    {
        None = 0x00,
        SYN = 0x01,
        FIN = 0x02,
        RST = 0x04,
        ACK = 0x08,
        DATA = 0x10
    }

    public class Frame
    {
        public uint ChannelId { get; set; }
        public FrameFlags Flags { get; set; }
        public byte[] Payload { get; set; }

        public Frame() { Payload = new byte[0]; }

        public Frame(uint channelId, FrameFlags flags, byte[] payload)
        {
            ChannelId = channelId;
            Flags = flags;
            Payload = payload ?? new byte[0];
        }

        /// <summary>
        /// Encode frame to bytes for wire transmission.
        /// Format: [length(4)] [channel(4)] [flags(1)] [payload(N)]
        /// Length = 5 + payload length (channel + flags + payload)
        /// </summary>
        public byte[] Encode()
        {
            int totalLen = 4 + 4 + 1 + Payload.Length; // length field + channel + flags + payload
            int bodyLen = 4 + 1 + Payload.Length; // channel + flags + payload (what length field covers)

            byte[] buf = new byte[4 + bodyLen]; // 4 bytes for length prefix + body

            // Length (big-endian, covers channel + flags + payload, i.e. everything after the length field)
            buf[0] = (byte)((bodyLen >> 24) & 0xFF);
            buf[1] = (byte)((bodyLen >> 16) & 0xFF);
            buf[2] = (byte)((bodyLen >> 8) & 0xFF);
            buf[3] = (byte)(bodyLen & 0xFF);

            // Channel ID (big-endian)
            buf[4] = (byte)((ChannelId >> 24) & 0xFF);
            buf[5] = (byte)((ChannelId >> 16) & 0xFF);
            buf[6] = (byte)((ChannelId >> 8) & 0xFF);
            buf[7] = (byte)(ChannelId & 0xFF);

            // Flags
            buf[8] = (byte)Flags;

            // Payload
            if (Payload.Length > 0)
                Buffer.BlockCopy(Payload, 0, buf, 9, Payload.Length);

            return buf;
        }

        /// <summary>
        /// Try to decode a frame from a byte array. Returns null if not enough data.
        /// Returns the decoded frame and the number of bytes consumed via out param.
        /// </summary>
        public static Frame Decode(byte[] data, int offset, int count, out int bytesConsumed)
        {
            bytesConsumed = 0;

            if (count < 4) return null; // need at least length field

            // Read body length (big-endian)
            int bodyLen = (data[offset] << 24) | (data[offset + 1] << 16) | (data[offset + 2] << 8) | data[offset + 3];
            int totalLen = 4 + bodyLen;

            if (count < totalLen) return null; // not enough data

            // Channel ID
            uint channelId = (uint)((data[offset + 4] << 24) | (data[offset + 5] << 16) | (data[offset + 6] << 8) | data[offset + 7]);

            // Flags
            FrameFlags flags = (FrameFlags)data[offset + 8];

            // Payload
            int payloadLen = bodyLen - 4 - 1; // subtract channel and flags
            byte[] payload = new byte[payloadLen];
            if (payloadLen > 0)
                Buffer.BlockCopy(data, offset + 9, payload, 0, payloadLen);

            bytesConsumed = totalLen;
            return new Frame(channelId, flags, payload);
        }

        public static Frame CreateSyn(uint channelId, string jsonPayload)
        {
            return new Frame(channelId, FrameFlags.SYN, Encoding.UTF8.GetBytes(jsonPayload));
        }

        public static Frame CreateAck(uint channelId)
        {
            return new Frame(channelId, FrameFlags.ACK, new byte[0]);
        }

        public static Frame CreateFin(uint channelId)
        {
            return new Frame(channelId, FrameFlags.FIN, new byte[0]);
        }

        public static Frame CreateRst(uint channelId)
        {
            return new Frame(channelId, FrameFlags.RST, new byte[0]);
        }

        public static Frame CreateData(uint channelId, byte[] data)
        {
            return new Frame(channelId, FrameFlags.DATA, data);
        }

        public string GetJsonPayload()
        {
            if (Payload == null || Payload.Length == 0) return null;
            return Encoding.UTF8.GetString(Payload);
        }
    }
}
