using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using ZTalk.Shared.Crypto;

namespace ZTalk.Shared.Network
{
    /// <summary>
    /// Binary control & data protocol for ZTalk's Zero-Trust Reverse Tunnel.
    /// Uses 32-byte CSPRNG challenge-response HMAC-SHA256 authentication over TLS 1.2.
    /// </summary>
    public static class ReverseTunnelProtocol
    {
        public const byte OpChallenge = 0x01;       // Server -> Agent: [0x01][32B nonce]
        public const byte OpControlAuth = 0x02;     // Agent -> Server: [0x02][32B HMAC]
        public const byte OpControlAuthOk = 0x03;   // Server -> Agent: [0x03]
        public const byte OpDataBind = 0x04;        // Agent -> Server: [0x04][16B sessionId][32B HMAC]
        public const byte OpDataBindOk = 0x05;      // Server -> Agent: [0x05]
        public const byte OpOpenSession = 0x10;     // Server -> Agent: [0x10][16B sessionId]
        public const byte OpPing = 0x20;            // Keepalive ping:  [0x20]
        public const byte OpPong = 0x21;            // Keepalive pong:  [0x21]

        public const int NonceLength = 32;
        public const int SessionIdLength = 16;
        public const int HmacLength = 32;

        private static readonly byte[] ControlDomain = Encoding.ASCII.GetBytes("ZTALK-TUNNEL-CTRL:");
        private static readonly byte[] DataDomain = Encoding.ASCII.GetBytes("ZTALK-TUNNEL-DATA:");
        private static readonly RandomNumberGenerator _rng = RandomNumberGenerator.Create();

        public static byte[] GenerateNonce()
        {
            var nonce = new byte[NonceLength];
            _rng.GetBytes(nonce);
            return nonce;
        }

        public static byte[] ComputeControlHmac(string sharedSecret, byte[] nonce)
        {
            if (string.IsNullOrEmpty(sharedSecret))
                throw new ArgumentException("Tunnel shared secret cannot be empty.", nameof(sharedSecret));
            if (nonce == null || nonce.Length != NonceLength)
                throw new ArgumentException("Invalid challenge nonce length.", nameof(nonce));

            byte[] keyBytes = Encoding.UTF8.GetBytes(sharedSecret);
            var payload = new byte[ControlDomain.Length + NonceLength];
            Buffer.BlockCopy(ControlDomain, 0, payload, 0, ControlDomain.Length);
            Buffer.BlockCopy(nonce, 0, payload, ControlDomain.Length, NonceLength);

            using (var hmac = new HMACSHA256(keyBytes))
            {
                return hmac.ComputeHash(payload);
            }
        }

        public static byte[] ComputeDataHmac(string sharedSecret, byte[] sessionId, byte[] nonce)
        {
            if (string.IsNullOrEmpty(sharedSecret))
                throw new ArgumentException("Tunnel shared secret cannot be empty.", nameof(sharedSecret));
            if (sessionId == null || sessionId.Length != SessionIdLength)
                throw new ArgumentException("Invalid sessionId length.", nameof(sessionId));
            if (nonce == null || nonce.Length != NonceLength)
                throw new ArgumentException("Invalid challenge nonce length.", nameof(nonce));

            byte[] keyBytes = Encoding.UTF8.GetBytes(sharedSecret);
            var payload = new byte[DataDomain.Length + SessionIdLength + NonceLength];
            Buffer.BlockCopy(DataDomain, 0, payload, 0, DataDomain.Length);
            Buffer.BlockCopy(sessionId, 0, payload, DataDomain.Length, SessionIdLength);
            Buffer.BlockCopy(nonce, 0, payload, DataDomain.Length + SessionIdLength, NonceLength);

            using (var hmac = new HMACSHA256(keyBytes))
            {
                return hmac.ComputeHash(payload);
            }
        }

        public static bool VerifyControlHmac(string sharedSecret, byte[] nonce, byte[] providedHmac)
        {
            if (providedHmac == null || providedHmac.Length != HmacLength) return false;
            byte[] expected = ComputeControlHmac(sharedSecret, nonce);
            return PasswordHasher.FixedTimeEquals(expected, providedHmac);
        }

        public static bool VerifyDataHmac(string sharedSecret, byte[] sessionId, byte[] nonce, byte[] providedHmac)
        {
            if (providedHmac == null || providedHmac.Length != HmacLength) return false;
            byte[] expected = ComputeDataHmac(sharedSecret, sessionId, nonce);
            return PasswordHasher.FixedTimeEquals(expected, providedHmac);
        }

        public static async Task<bool> ReadExactAsync(Stream stream, byte[] buffer, int count, CancellationToken ct)
        {
            int totalRead = 0;
            while (totalRead < count)
            {
                int bytesRead = await stream.ReadAsync(buffer, totalRead, count - totalRead, ct).ConfigureAwait(false);
                if (bytesRead == 0)
                    return false;
                totalRead += bytesRead;
            }
            return true;
        }

        /// <summary>
        /// Full-duplex raw byte bridge between two streams (preserves inner end-to-end TLS untouched).
        /// Closes both streams cleanly as soon as either side closes or cancels.
        /// </summary>
        public static async Task BridgeBidirectionalAsync(Stream streamA, Stream streamB, CancellationToken ct)
        {
            using (var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(ct))
            {
                var token = linkedCts.Token;
                var aToB = PumpAsync(streamA, streamB, token);
                var bToA = PumpAsync(streamB, streamA, token);

                await Task.WhenAny(aToB, bToA).ConfigureAwait(false);
                linkedCts.Cancel();

                try { streamA.Close(); } catch { }
                try { streamB.Close(); } catch { }

                try { await Task.WhenAll(aToB, bToA).ConfigureAwait(false); } catch { }
            }
        }

        private static async Task PumpAsync(Stream source, Stream destination, CancellationToken ct)
        {
            var buffer = new byte[16384];
            try
            {
                while (!ct.IsCancellationRequested)
                {
                    int read = await source.ReadAsync(buffer, 0, buffer.Length, ct).ConfigureAwait(false);
                    if (read <= 0)
                        break;

                    await destination.WriteAsync(buffer, 0, read, ct).ConfigureAwait(false);
                }
            }
            catch
            {
                // Stream closed or cancelled
            }
        }
    }
}
