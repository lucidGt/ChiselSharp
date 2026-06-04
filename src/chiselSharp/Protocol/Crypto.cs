using System;
using System.Security.Cryptography;
using System.Text;

namespace ChiselSharp.Protocol
{
    /// <summary>
    /// Session crypto using AES-256-CBC + HMAC-SHA256 (encrypt-then-MAC).
    /// Uses only built-in .NET Framework crypto with no external dependencies.
    /// </summary>
    public class SessionCrypto : IDisposable
    {
        private readonly byte[] _sendKey;
        private readonly byte[] _recvKey;
        private readonly object _sendLock = new object();
        private readonly object _recvLock = new object();

        private const int KeySize = 32;   // AES-256
        private const int IvSize = 16;    // AES block size
        private const int HmacSize = 32;  // HMAC-SHA256

        public SessionCrypto(byte[] sendKey, byte[] recvKey)
        {
            _sendKey = new byte[KeySize];
            _recvKey = new byte[KeySize];
            Buffer.BlockCopy(sendKey, 0, _sendKey, 0, Math.Min(sendKey.Length, KeySize));
            Buffer.BlockCopy(recvKey, 0, _recvKey, 0, Math.Min(recvKey.Length, KeySize));
        }

        /// <summary>
        /// Encrypt plaintext with AES-256-CBC + HMAC-SHA256 (encrypt-then-MAC).
        /// Returns: IV(16) + ciphertext(N) + HMAC(32).
        /// </summary>
        public byte[] Encrypt(byte[] plaintext)
        {
            lock (_sendLock)
            {
                // Generate random IV
                byte[] iv = new byte[IvSize];
                using (var rng = RandomNumberGenerator.Create())
                {
                    rng.GetBytes(iv);
                }

                // Encrypt with AES-256-CBC
                byte[] ciphertext;
                using (var aes = Aes.Create())
                {
                    aes.Key = _sendKey;
                    aes.IV = iv;
                    aes.Mode = CipherMode.CBC;
                    aes.Padding = PaddingMode.PKCS7;

                    using (var encryptor = aes.CreateEncryptor())
                    {
                        ciphertext = encryptor.TransformFinalBlock(plaintext, 0, plaintext.Length);
                    }
                }

                // Compute HMAC over IV + ciphertext
                byte[] hmac;
                using (var hmacSha = new HMACSHA256(_sendKey))
                {
                    byte[] dataToMac = new byte[iv.Length + ciphertext.Length];
                    Buffer.BlockCopy(iv, 0, dataToMac, 0, iv.Length);
                    Buffer.BlockCopy(ciphertext, 0, dataToMac, iv.Length, ciphertext.Length);
                    hmac = hmacSha.ComputeHash(dataToMac);
                }

                // Combine: IV + ciphertext + HMAC
                byte[] result = new byte[IvSize + ciphertext.Length + HmacSize];
                Buffer.BlockCopy(iv, 0, result, 0, IvSize);
                Buffer.BlockCopy(ciphertext, 0, result, IvSize, ciphertext.Length);
                Buffer.BlockCopy(hmac, 0, result, IvSize + ciphertext.Length, HmacSize);

                return result;
            }
        }

        /// <summary>
        /// Decrypt. Verifies HMAC first, then decrypts with AES-256-CBC.
        /// Returns plaintext or null if authentication fails.
        /// </summary>
        public byte[] Decrypt(byte[] data)
        {
            lock (_recvLock)
            {
                if (data.Length < IvSize + HmacSize + 1) return null;

                // Extract parts
                byte[] iv = new byte[IvSize];
                Buffer.BlockCopy(data, 0, iv, 0, IvSize);

                int ciphertextLen = data.Length - IvSize - HmacSize;
                byte[] ciphertext = new byte[ciphertextLen];
                Buffer.BlockCopy(data, IvSize, ciphertext, 0, ciphertextLen);

                byte[] receivedHmac = new byte[HmacSize];
                Buffer.BlockCopy(data, IvSize + ciphertextLen, receivedHmac, 0, HmacSize);

                // Verify HMAC
                using (var hmacSha = new HMACSHA256(_recvKey))
                {
                    byte[] dataToMac = new byte[IvSize + ciphertextLen];
                    Buffer.BlockCopy(iv, 0, dataToMac, 0, IvSize);
                    Buffer.BlockCopy(ciphertext, 0, dataToMac, IvSize, ciphertextLen);
                    byte[] computedHmac = hmacSha.ComputeHash(dataToMac);

                    // Constant-time comparison
                    if (!ConstantTimeEquals(computedHmac, receivedHmac))
                        return null;
                }

                // Decrypt
                try
                {
                    using (var aes = Aes.Create())
                    {
                        aes.Key = _recvKey;
                        aes.IV = iv;
                        aes.Mode = CipherMode.CBC;
                        aes.Padding = PaddingMode.PKCS7;

                        using (var decryptor = aes.CreateDecryptor())
                        {
                            return decryptor.TransformFinalBlock(ciphertext, 0, ciphertext.Length);
                        }
                    }
                }
                catch
                {
                    return null;
                }
            }
        }

        private static bool ConstantTimeEquals(byte[] a, byte[] b)
        {
            if (a.Length != b.Length) return false;
            int diff = 0;
            for (int i = 0; i < a.Length; i++)
                diff |= a[i] ^ b[i];
            return diff == 0;
        }

        public void Dispose()
        {
            Array.Clear(_sendKey, 0, _sendKey.Length);
            Array.Clear(_recvKey, 0, _recvKey.Length);
        }
    }

    /// <summary>
    /// Static crypto utilities for key generation and fingerprints.
    /// </summary>
    public static class CryptoUtils
    {
        /// <summary>
        /// Generate a random 32-byte key (or derive from seed).
        /// </summary>
        public static byte[] GenerateServerKey(string seed = null)
        {
            byte[] key = new byte[32];
            if (!string.IsNullOrEmpty(seed))
            {
                using (var sha256 = SHA256.Create())
                {
                    byte[] hash = sha256.ComputeHash(Encoding.UTF8.GetBytes(seed));
                    Buffer.BlockCopy(hash, 0, key, 0, 32);
                }
            }
            else
            {
                using (var rng = RandomNumberGenerator.Create())
                {
                    rng.GetBytes(key);
                }
            }
            return key;
        }

        /// <summary>
        /// Compute SHA256 fingerprint of the server key (base64 encoded).
        /// </summary>
        public static string ComputeFingerprint(byte[] serverKey)
        {
            using (var sha256 = SHA256.Create())
            {
                byte[] hash = sha256.ComputeHash(serverKey);
                return Convert.ToBase64String(hash);
            }
        }

        /// <summary>
        /// Derive session keys from a shared secret.
        /// Returns [sendKey (32 bytes), recvKey (32 bytes)].
        /// </summary>
        public static byte[][] DeriveSessionKeys(byte[] sharedSecret, bool isServer)
        {
            using (var sha256 = SHA256.Create())
            {
                byte[] serverKey = sha256.ComputeHash(Concat(sharedSecret, Encoding.UTF8.GetBytes("server")));
                byte[] clientKey = sha256.ComputeHash(Concat(sharedSecret, Encoding.UTF8.GetBytes("client")));

                byte[] sendKey = isServer ? serverKey : clientKey;
                byte[] recvKey = isServer ? clientKey : serverKey;

                return new byte[][] { sendKey, recvKey };
            }
        }

        private static byte[] Concat(byte[] a, byte[] b)
        {
            byte[] result = new byte[a.Length + b.Length];
            Buffer.BlockCopy(a, 0, result, 0, a.Length);
            Buffer.BlockCopy(b, 0, result, a.Length, b.Length);
            return result;
        }
    }
}
