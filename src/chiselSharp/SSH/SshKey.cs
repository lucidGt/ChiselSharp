using System;
using System.Security.Cryptography;
using System.Text;

namespace ChiselSharp.SSH
{
    /// <summary>
    /// Represents an SSH host key received from the server during key exchange.
    /// </summary>
    public class SshHostKey
    {
        public string KeyType { get; private set; }
        public byte[] PublicKeyBlob { get; private set; }
        public string Fingerprint { get; private set; }

        public SshHostKey(string keyType, byte[] publicKeyBlob)
        {
            KeyType = keyType;
            PublicKeyBlob = publicKeyBlob;
            using (var sha256 = SHA256.Create())
            {
                byte[] hash = sha256.ComputeHash(publicKeyBlob);
                Fingerprint = Convert.ToBase64String(hash);
            }
        }

        /// <summary>
        /// Parse an SSH host key blob (as received in KEXDH_REPLY).
        /// Format: string key_type, followed by key-specific fields.
        /// </summary>
        public static SshHostKey Parse(byte[] blob)
        {
            int offset = 0;
            string keyType = SshWire.ReadString(blob, ref offset);
            return new SshHostKey(keyType, blob);
        }

        /// <summary>
        /// Extract the algorithm name (e.g., "ssh-rsa", "ecdsa-sha2-nistp256") from
        /// a host key blob. The blob format is: string algo_name, ...key_data...
        /// </summary>
        public static string GetAlgorithm(byte[] blob)
        {
            int offset = 0;
            return SshWire.ReadString(blob, ref offset);
        }
    }

    /// <summary>
    /// Helper methods for SSH wire-format encoding/decoding.
    /// All multi-byte integers are big-endian. Strings are uint32 length + bytes.
    /// </summary>
    public static class SshWire
    {
        public static byte[] EncodeUint32(uint value)
        {
            byte[] buf = new byte[4];
            buf[0] = (byte)((value >> 24) & 0xFF);
            buf[1] = (byte)((value >> 16) & 0xFF);
            buf[2] = (byte)((value >> 8) & 0xFF);
            buf[3] = (byte)(value & 0xFF);
            return buf;
        }

        public static uint ReadUint32(byte[] data, ref int offset)
        {
            uint val = (uint)((data[offset] << 24) | (data[offset + 1] << 16) | (data[offset + 2] << 8) | data[offset + 3]);
            offset += 4;
            return val;
        }

        public static byte[] EncodeString(string str)
        {
            byte[] strBytes = Encoding.UTF8.GetBytes(str);
            byte[] result = new byte[4 + strBytes.Length];
            byte[] lenBytes = EncodeUint32((uint)strBytes.Length);
            Buffer.BlockCopy(lenBytes, 0, result, 0, 4);
            Buffer.BlockCopy(strBytes, 0, result, 4, strBytes.Length);
            return result;
        }

        public static byte[] EncodeBytes(byte[] data)
        {
            byte[] result = new byte[4 + data.Length];
            byte[] lenBytes = EncodeUint32((uint)data.Length);
            Buffer.BlockCopy(lenBytes, 0, result, 0, 4);
            Buffer.BlockCopy(data, 0, result, 4, data.Length);
            return result;
        }

        public static string ReadString(byte[] data, ref int offset)
        {
            uint len = ReadUint32(data, ref offset);
            if (len > int.MaxValue) throw new InvalidOperationException("String length too large");
            string result = Encoding.UTF8.GetString(data, offset, (int)len);
            offset += (int)len;
            return result;
        }

        public static byte[] ReadBytes(byte[] data, ref int offset)
        {
            uint len = ReadUint32(data, ref offset);
            if (len > int.MaxValue) throw new InvalidOperationException("Byte array length too large");
            byte[] result = new byte[len];
            Buffer.BlockCopy(data, offset, result, 0, (int)len);
            offset += (int)len;
            return result;
        }

        /// <summary>
        /// Encode a BigInteger as SSH mpint.
        /// mpint: uint32 length + big-endian bytes, with 0x00 prefix if high bit set.
        ///
        /// .NET's BigInteger.ToByteArray() returns little-endian with a sign byte.
        /// This method converts to SSH's big-endian unsigned mpint format.
        /// </summary>
        public static byte[] EncodeMpint(System.Numerics.BigInteger value)
        {
            byte[] leBytes = value.ToByteArray();
            int leLen = leBytes.Length;

            // For a positive value, ToByteArray appends a 0x00 sign byte at the
            // high end (last element in little-endian) if the MSB of the true
            // value has the high bit set. Remove this marker byte here.
            int actualLen = leLen;
            if (actualLen > 1 && leBytes[actualLen - 1] == 0)
            {
                actualLen--;
            }

            // Convert little-endian to big-endian
            byte[] beBody = new byte[actualLen];
            for (int i = 0; i < actualLen; i++)
            {
                beBody[i] = leBytes[actualLen - 1 - i];
            }

            // If the MSB (first byte in big-endian) has the high bit set,
            // prepend a 0x00 to indicate a positive value
            bool highBitSet = (actualLen > 0 && (beBody[0] & 0x80) != 0);
            byte[] mpintBody;
            if (highBitSet)
            {
                mpintBody = new byte[actualLen + 1];
                mpintBody[0] = 0;
                Buffer.BlockCopy(beBody, 0, mpintBody, 1, actualLen);
            }
            else
            {
                mpintBody = beBody;
            }

            // Prepend length as uint32
            byte[] result = new byte[4 + mpintBody.Length];
            byte[] lenBytes = EncodeUint32((uint)mpintBody.Length);
            Buffer.BlockCopy(lenBytes, 0, result, 0, 4);
            Buffer.BlockCopy(mpintBody, 0, result, 4, mpintBody.Length);
            return result;
        }

        /// <summary>
        /// Read a BigInteger from SSH mpint format.
        /// </summary>
        public static System.Numerics.BigInteger ReadMpint(byte[] data, ref int offset)
        {
            uint len = ReadUint32(data, ref offset);
            if (len > int.MaxValue) throw new InvalidOperationException("Mpint length too large");

            int mpintLen = (int)len;
            bool hasLeadingZero = (mpintLen > 0 && data[offset] == 0);

            int actualLen = hasLeadingZero ? mpintLen - 1 : mpintLen;
            int srcOffset = hasLeadingZero ? offset + 1 : offset;

            // Reverse to little-endian for BigInteger
            byte[] leBytes = new byte[actualLen + 1];
            for (int i = 0; i < actualLen; i++)
            {
                leBytes[i] = data[srcOffset + actualLen - 1 - i];
            }
            // Add a 0x00 sign byte to ensure positive
            leBytes[actualLen] = 0;

            offset += mpintLen;
            return new System.Numerics.BigInteger(leBytes);
        }
    }
}
