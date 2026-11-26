using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using ZTalk.Shared.Protocol;

namespace ZTalk.Server.Models
{
    /// <summary>
    /// Đại diện cho 1 client đang kết nối đến server (hỗ trợ cả NetworkStream và SslStream TLS)
    /// </summary>
    public class ConnectedClient
    {
        private readonly object _sendLock = new object();
        private volatile bool _isAuthenticated;
        private int _packetsReceived;
        private int _packetsSent;
        private string _cachedEndPoint;

        /// <summary>TCP client socket</summary>
        public TcpClient TcpClient { get; set; }

        /// <summary>Active stream (SslStream when TLS enabled, otherwise NetworkStream)</summary>
        public Stream Stream { get; set; }

        /// <summary>True if connection is secured with TLS 1.2</summary>
        public bool IsTls { get; set; }

        /// <summary>Remote IP address (cached on accept for per-IP rate limiting)</summary>
        public string RemoteIp { get; set; }

        /// <summary>User ID sau khi authenticate</summary>
        public string UserId { get; set; }

        /// <summary>Username</summary>
        public string Username { get; set; }

        /// <summary>Display name</summary>
        public string DisplayName { get; set; }

        /// <summary>Đã xác thực chưa</summary>
        public bool IsAuthenticated
        {
            get => _isAuthenticated;
            set => _isAuthenticated = value;
        }

        /// <summary>Thời gian kết nối</summary>
        public DateTime ConnectedAt { get; set; } = DateTime.Now;

        /// <summary>Số packet nhận được (thread-safe)</summary>
        public int PacketsReceived
        {
            get => Volatile.Read(ref _packetsReceived);
            set => Volatile.Write(ref _packetsReceived, value);
        }

        /// <summary>Số packet đã gửi (thread-safe)</summary>
        public int PacketsSent
        {
            get => Volatile.Read(ref _packetsSent);
            set => Volatile.Write(ref _packetsSent, value);
        }

        public void IncrementPacketsReceived() => Interlocked.Increment(ref _packetsReceived);

        public void IncrementPacketsSent() => Interlocked.Increment(ref _packetsSent);

        /// <summary>
        /// Thread-safe packet send serialized per client socket to prevent frame interleaving.
        /// </summary>
        public void SendPacket(Packet packet)
        {
            var stream = Stream;
            if (stream == null) return;

            var frame = PacketSerializer.FramePacket(packet);
            SendRawFrame(frame);
        }

        /// <summary>
        /// Thread-safe raw pre-framed write (used for zero-reserialization broadcasts).
        /// </summary>
        public void SendRawFrame(byte[] frame)
        {
            var stream = Stream;
            if (stream == null || frame == null) return;

            lock (_sendLock)
            {
                PacketSerializer.SendRawFrame(stream, frame);
            }
            Interlocked.Increment(ref _packetsSent);
        }

        /// <summary>Cache RemoteEndPoint and RemoteIp once at accept time to avoid repeated socket queries.</summary>
        public void CacheEndPoint()
        {
            try
            {
                var remote = TcpClient?.Client?.RemoteEndPoint as IPEndPoint;
                if (remote != null)
                {
                    _cachedEndPoint = remote.ToString();
                    RemoteIp = remote.Address.ToString();
                }
                else
                {
                    _cachedEndPoint = TcpClient?.Client?.RemoteEndPoint?.ToString() ?? "Unknown";
                    RemoteIp = "unknown";
                }
            }
            catch
            {
                _cachedEndPoint = "Disconnected";
                RemoteIp = "unknown";
            }
        }

        /// <summary>Endpoint address (IP:Port) để log</summary>
        public string EndPoint
        {
            get
            {
                if (_cachedEndPoint != null)
                    return _cachedEndPoint;

                try
                {
                    return TcpClient?.Client?.RemoteEndPoint?.ToString() ?? "Unknown";
                }
                catch
                {
                    return "Disconnected";
                }
            }
        }
    }
}
