using System;
using System.Security.Cryptography;

namespace ZTalk.Shared.Crypto
{
    /// <summary>
    /// Salted PBKDF2-HMAC-SHA256 password hashing with constant-time verification
    /// and seamless legacy hash migration detection.
    /// Format: pbkdf2$sha256$<iterations>$<base64Salt>$<base64Hash>
    /// </summary>
    public static class PasswordHasher
    {
        public const int DefaultIterations = 100000;
        private const int SaltSize = 16;
        private const int KeySize = 32;
        private const string Prefix = "pbkdf2$sha256$";

        private static readonly RandomNumberGenerator _rng = RandomNumberGenerator.Create();

        public static string Hash(string secret, int iterations = DefaultIterations)
        {
            if (string.IsNullOrEmpty(secret))
                throw new ArgumentException("Secret cannot be null or empty.", nameof(secret));
            if (iterations < 10000)
                throw new ArgumentOutOfRangeException(nameof(iterations), "Iterations must be >= 10,000.");

            var salt = new byte[SaltSize];
            _rng.GetBytes(salt);

            byte[] derived;
            using (var pbkdf2 = new Rfc2898DeriveBytes(secret, salt, iterations, HashAlgorithmName.SHA256))
            {
                derived = pbkdf2.GetBytes(KeySize);
            }

            return $"{Prefix}{iterations}${Convert.ToBase64String(salt)}${Convert.ToBase64String(derived)}";
        }

        public static bool Verify(string secret, string storedHash)
        {
            if (string.IsNullOrEmpty(secret) || string.IsNullOrEmpty(storedHash))
                return false;

            if (!storedHash.StartsWith(Prefix, StringComparison.Ordinal))
            {
                // Legacy unsalted SHA-256 compatibility (constant-time compare)
                return FixedTimeEquals(secret, storedHash);
            }

            var parts = storedHash.Split('$');
            if (parts.Length != 5)
                return false;

            int iterations;
            if (!int.TryParse(parts[2], out iterations) || iterations < 1000)
                return false;

            byte[] salt;
            byte[] expectedHash;
            try
            {
                salt = Convert.FromBase64String(parts[3]);
                expectedHash = Convert.FromBase64String(parts[4]);
            }
            catch
            {
                return false;
            }

            byte[] actualHash;
            using (var pbkdf2 = new Rfc2898DeriveBytes(secret, salt, iterations, HashAlgorithmName.SHA256))
            {
                actualHash = pbkdf2.GetBytes(expectedHash.Length);
            }

            return FixedTimeEquals(actualHash, expectedHash);
        }

        public static bool NeedsRehash(string storedHash)
        {
            if (string.IsNullOrEmpty(storedHash) || !storedHash.StartsWith(Prefix, StringComparison.Ordinal))
                return true;

            var parts = storedHash.Split('$');
            int iterations;
            if (parts.Length != 5 || !int.TryParse(parts[2], out iterations))
                return true;

            return iterations < DefaultIterations;
        }

        public static bool FixedTimeEquals(byte[] a, byte[] b)
        {
            if (a == null || b == null || a.Length != b.Length)
                return false;

            int diff = 0;
            for (int i = 0; i < a.Length; i++)
            {
                diff |= a[i] ^ b[i];
            }
            return diff == 0;
        }

        public static bool FixedTimeEquals(string a, string b)
        {
            if (a == null || b == null || a.Length != b.Length)
                return false;

            int diff = 0;
            for (int i = 0; i < a.Length; i++)
            {
                diff |= a[i] ^ b[i];
            }
            return diff == 0;
        }
    }
}
