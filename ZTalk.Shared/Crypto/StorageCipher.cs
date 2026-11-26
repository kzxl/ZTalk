using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace ZTalk.Shared.Crypto
{
    /// <summary>
    /// Encryption-at-rest helper for server stores (AEAD AES-256-CBC + HMAC-SHA256)
    /// and Windows DPAPI protection for local keys and client chat history.
    /// Zero external dependencies (.NET Framework 4.8 BCL).
    /// </summary>
    public static class StorageCipher
    {
        public const string AeadPrefix = "ZTALK_ENC_V2:";
        public const string DpapiPrefix = "ZTALK_DPAPI:";

        private static readonly byte[] DpapiEntropy = Encoding.ASCII.GetBytes("ZTALK-ENTERPRISE-DPAPI-V1");
        private static readonly AesHelper _aes = new AesHelper();

        /// <summary>
        /// Encrypt text with AEAD (AES-256-CBC + HMAC-SHA256) for server storage-at-rest.
        /// If key is null, returns plaintext unchanged.
        /// </summary>
        public static string EncryptText(string plainText, byte[] key)
        {
            if (key == null || string.IsNullOrEmpty(plainText))
                return plainText;

            return AeadPrefix + _aes.Encrypt(plainText, key);
        }

        /// <summary>
        /// Decrypt AEAD-encrypted storage text. Transparently passes through legacy plaintext.
        /// </summary>
        public static string DecryptText(string storedText, byte[] key)
        {
            if (string.IsNullOrEmpty(storedText))
                return storedText;

            if (!storedText.StartsWith(AeadPrefix, StringComparison.Ordinal))
                return storedText; // Legacy plaintext compatibility

            if (key == null)
                throw new CryptographicException("Storage encryption key is required to decrypt protected data.");

            string cipherPayload = storedText.Substring(AeadPrefix.Length);
            return _aes.Decrypt(cipherPayload, key);
        }

        /// <summary>
        /// Load a 256-bit storage key protected by Windows DPAPI (CurrentUser),
        /// or generate and persist a new CSPRNG 256-bit key if the file does not exist.
        /// </summary>
        public static byte[] LoadOrCreateProtectedKey(string keyFilePath)
        {
            if (string.IsNullOrWhiteSpace(keyFilePath))
                throw new ArgumentException("Key file path is required.", nameof(keyFilePath));

            string fullPath = Path.GetFullPath(keyFilePath);
            if (File.Exists(fullPath))
            {
                byte[] protectedBytes = File.ReadAllBytes(fullPath);
                return ProtectedData.Unprotect(protectedBytes, DpapiEntropy, DataProtectionScope.CurrentUser);
            }

            string dir = Path.GetDirectoryName(fullPath);
            if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir))
                Directory.CreateDirectory(dir);

            byte[] rawKey = AesHelper.GenerateRandomKey();
            byte[] protectedNew = ProtectedData.Protect(rawKey, DpapiEntropy, DataProtectionScope.CurrentUser);
            File.WriteAllBytes(fullPath, protectedNew);
            return rawKey;
        }

        /// <summary>
        /// Protect a single line of text with Windows DPAPI (CurrentUser) for local client cache.
        /// </summary>
        public static string ProtectDpapiLine(string plainText)
        {
            if (string.IsNullOrEmpty(plainText)) return plainText;

            byte[] rawBytes = Encoding.UTF8.GetBytes(plainText);
            byte[] protectedBytes = ProtectedData.Protect(rawBytes, DpapiEntropy, DataProtectionScope.CurrentUser);
            return DpapiPrefix + Convert.ToBase64String(protectedBytes);
        }

        /// <summary>
        /// Unprotect a DPAPI-protected line. Transparently passes through legacy plaintext lines.
        /// </summary>
        public static string UnprotectDpapiLine(string storedLine)
        {
            if (string.IsNullOrEmpty(storedLine)) return storedLine;

            if (!storedLine.StartsWith(DpapiPrefix, StringComparison.Ordinal))
                return storedLine; // Legacy plaintext line

            byte[] protectedBytes = Convert.FromBase64String(storedLine.Substring(DpapiPrefix.Length));
            byte[] rawBytes = ProtectedData.Unprotect(protectedBytes, DpapiEntropy, DataProtectionScope.CurrentUser);
            return Encoding.UTF8.GetString(rawBytes);
        }
    }
}
