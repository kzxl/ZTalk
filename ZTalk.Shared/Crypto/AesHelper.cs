using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace ZTalk.Shared.Crypto
{
    /// <summary>
    /// Authenticated encryption helper using Encrypt-then-MAC: AES-256-CBC + HMAC-SHA256.
    /// Wire format (v2): [Version: 1B = 0x02][IV: 16B][CipherText: N bytes][HMAC-SHA256: 32B]
    /// Pure .NET 4.8 BCL (zero external dependencies).
    /// </summary>
    public class AesHelper : ICryptoService
    {
        private const byte FormatVersionV2 = 0x02;
        private const int IvLength = 16;
        private const int MacLength = 32;
        private const int MinV2Length = 1 + IvLength + 16 + MacLength;

        private static readonly byte[] EncDomain = Encoding.ASCII.GetBytes("ZTALK-ENC-V2");
        private static readonly byte[] MacDomain = Encoding.ASCII.GetBytes("ZTALK-MAC-V2");

        /// <summary>
        /// Mã hoá text bằng AES-256-CBC + HMAC-SHA256.
        /// Output: Base64(Version + IV + CipherText + HMAC)
        /// </summary>
        public string Encrypt(string plainText, byte[] key)
        {
            if (string.IsNullOrEmpty(plainText))
                return plainText;

            var encrypted = EncryptBytes(Encoding.UTF8.GetBytes(plainText), key);
            return Convert.ToBase64String(encrypted);
        }

        /// <summary>
        /// Giải mã text từ Base64(Version + IV + CipherText + HMAC)
        /// </summary>
        public string Decrypt(string cipherText, byte[] key)
        {
            if (string.IsNullOrEmpty(cipherText))
                return cipherText;

            var cipherBytes = Convert.FromBase64String(cipherText);
            var decrypted = DecryptBytes(cipherBytes, key);
            return Encoding.UTF8.GetString(decrypted);
        }

        /// <summary>
        /// Mã hoá byte array theo chuẩn Encrypt-then-MAC (AES-256-CBC + HMAC-SHA256).
        /// </summary>
        public byte[] EncryptBytes(byte[] data, byte[] key)
        {
            if (data == null) throw new ArgumentNullException(nameof(data));
            if (key == null || key.Length == 0) throw new ArgumentException("Key cannot be null or empty.", nameof(key));

            byte[] masterKey = EnsureKeySize(key, 32);
            byte[] encKey = DeriveSubkey(masterKey, EncDomain);
            byte[] macKey = DeriveSubkey(masterKey, MacDomain);

            try
            {
                using (var aes = Aes.Create())
                {
                    aes.KeySize = 256;
                    aes.Mode = CipherMode.CBC;
                    aes.Padding = PaddingMode.PKCS7;
                    aes.Key = encKey;
                    aes.GenerateIV();

                    int paddedLen = ((data.Length / 16) + 1) * 16;
                    using (var encryptor = aes.CreateEncryptor())
                    using (var ms = new MemoryStream(1 + IvLength + paddedLen + MacLength))
                    {
                        ms.WriteByte(FormatVersionV2);
                        ms.Write(aes.IV, 0, IvLength);

                        using (var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write, leaveOpen: true))
                        {
                            cs.Write(data, 0, data.Length);
                            cs.FlushFinalBlock();
                        }

                        byte[] authenticatedData = ms.ToArray();
                        using (var hmac = new HMACSHA256(macKey))
                        {
                            byte[] mac = hmac.ComputeHash(authenticatedData, 0, authenticatedData.Length);
                            var output = new byte[authenticatedData.Length + MacLength];
                            Buffer.BlockCopy(authenticatedData, 0, output, 0, authenticatedData.Length);
                            Buffer.BlockCopy(mac, 0, output, authenticatedData.Length, MacLength);
                            return output;
                        }
                    }
                }
            }
            finally
            {
                Array.Clear(encKey, 0, encKey.Length);
                Array.Clear(macKey, 0, macKey.Length);
            }
        }

        /// <summary>
        /// Xác thực HMAC-SHA256 (constant-time) trước rồi mới giải mã AES-256-CBC.
        /// Chống sửa đổi ciphertext và Padding Oracle attacks.
        /// </summary>
        public byte[] DecryptBytes(byte[] data, byte[] key)
        {
            if (data == null || data.Length < IvLength)
                throw new ArgumentException("Encrypted data is too short.", nameof(data));
            if (key == null || key.Length == 0)
                throw new ArgumentException("Key cannot be null or empty.", nameof(key));

            if (data[0] != FormatVersionV2 || data.Length < MinV2Length)
                throw new CryptographicException("Unsupported or truncated authenticated ciphertext format.");

            byte[] masterKey = EnsureKeySize(key, 32);
            byte[] encKey = DeriveSubkey(masterKey, EncDomain);
            byte[] macKey = DeriveSubkey(masterKey, MacDomain);

            try
            {
                int payloadLen = data.Length - MacLength;
                using (var hmac = new HMACSHA256(macKey))
                {
                    byte[] expectedMac = hmac.ComputeHash(data, 0, payloadLen);
                    if (!FixedTimeMacEquals(expectedMac, data, payloadLen))
                    {
                        throw new CryptographicException("Message authentication failed (tampered payload or wrong key).");
                    }
                }

                using (var aes = Aes.Create())
                {
                    aes.KeySize = 256;
                    aes.Mode = CipherMode.CBC;
                    aes.Padding = PaddingMode.PKCS7;
                    aes.Key = encKey;

                    var iv = new byte[IvLength];
                    Buffer.BlockCopy(data, 1, iv, 0, IvLength);
                    aes.IV = iv;

                    int cipherOffset = 1 + IvLength;
                    int cipherLen = payloadLen - cipherOffset;
                    using (var decryptor = aes.CreateDecryptor())
                    using (var ms = new MemoryStream(data, cipherOffset, cipherLen))
                    using (var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                    using (var output = new MemoryStream(cipherLen))
                    {
                        cs.CopyTo(output);
                        return output.ToArray();
                    }
                }
            }
            finally
            {
                Array.Clear(encKey, 0, encKey.Length);
                Array.Clear(macKey, 0, macKey.Length);
            }
        }

        private static byte[] DeriveSubkey(byte[] masterKey, byte[] domainLabel)
        {
            var input = new byte[masterKey.Length + domainLabel.Length];
            Buffer.BlockCopy(masterKey, 0, input, 0, masterKey.Length);
            Buffer.BlockCopy(domainLabel, 0, input, masterKey.Length, domainLabel.Length);
            try
            {
                using (var sha = SHA256.Create())
                {
                    return sha.ComputeHash(input);
                }
            }
            finally
            {
                Array.Clear(input, 0, input.Length);
            }
        }

        private static bool FixedTimeMacEquals(byte[] expected, byte[] buffer, int offset)
        {
            int diff = 0;
            for (int i = 0; i < MacLength; i++)
            {
                diff |= expected[i] ^ buffer[offset + i];
            }
            return diff == 0;
        }

        /// <summary>
        /// Đảm bảo key đúng kích thước. Nếu ngắn hơn thì pad 0, dài hơn thì cắt.
        /// Thực tế key từ DH sẽ là 32 bytes (SHA256 hash).
        /// </summary>
        private static byte[] EnsureKeySize(byte[] key, int size)
        {
            if (key.Length == size)
                return key;

            var result = new byte[size];
            Buffer.BlockCopy(key, 0, result, 0, Math.Min(key.Length, size));
            return result;
        }

        /// <summary>
        /// Tạo random AES key (256-bit) cho testing
        /// </summary>
        public static byte[] GenerateRandomKey()
        {
            using (var aes = Aes.Create())
            {
                aes.KeySize = 256;
                aes.GenerateKey();
                return aes.Key;
            }
        }
    }
}
