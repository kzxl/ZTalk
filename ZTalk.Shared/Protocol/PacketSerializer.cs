using System;
using System.IO;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Web.Script.Serialization;
using ZTalk.Shared.Constants;

namespace ZTalk.Shared.Protocol
{
    /// <summary>
    /// Serialize/Deserialize Packet qua NetworkStream.
    /// Format: [4 bytes - payload length (BigEndian)][N bytes - JSON payload]
    /// </summary>
    public static class PacketSerializer
    {
        // JavaScriptSerializer is not guaranteed thread-safe for concurrent calls across threads
        private static readonly ThreadLocal<JavaScriptSerializer> _serializer =
            new ThreadLocal<JavaScriptSerializer>(() => new JavaScriptSerializer
            {
                MaxJsonLength = int.MaxValue
            });

        /// <summary>
        /// Serialize packet thành JSON string
        /// </summary>
        public static string Serialize(Packet packet)
        {
            if (packet == null) return null;
            return _serializer.Value.Serialize(packet);
        }

        /// <summary>
        /// Deserialize JSON string thành Packet
        /// </summary>
        public static Packet Deserialize(string json)
        {
            if (string.IsNullOrEmpty(json)) return null;
            try
            {
                return _serializer.Value.Deserialize<Packet>(json);
            }
            catch
            {
                return null;
            }
        }

        /// <summary>
        /// Helper serialize đối tượng bất kỳ thành JSON string
        /// </summary>
        public static string ToJson<T>(T obj)
        {
            if (obj == null) return null;
            return _serializer.Value.Serialize(obj);
        }

        /// <summary>
        /// Helper deserialize JSON string thành đối tượng kiểu T
        /// </summary>
        public static T FromJson<T>(string json)
        {
            if (string.IsNullOrEmpty(json)) return default(T);
            try
            {
                return _serializer.Value.Deserialize<T>(json);
            }
            catch
            {
                return default(T);
            }
        }

        /// <summary>
        /// Frame a packet into a single contiguous length-prefixed buffer:
        /// [4-byte BigEndian length][UTF-8 JSON payload].
        /// Enables single-syscall writes and zero re-serialization during broadcast.
        /// </summary>
        public static byte[] FramePacket(Packet packet)
        {
            if (packet == null) throw new ArgumentNullException(nameof(packet));

            var json = Serialize(packet);
            int payloadLength = Encoding.UTF8.GetByteCount(json);
            if (payloadLength > AppConstants.MaxPacketSize)
                throw new InvalidOperationException($"Packet size {payloadLength} exceeds maximum allowed {AppConstants.MaxPacketSize}.");

            var frame = new byte[4 + payloadLength];
            frame[0] = (byte)(payloadLength >> 24);
            frame[1] = (byte)(payloadLength >> 16);
            frame[2] = (byte)(payloadLength >> 8);
            frame[3] = (byte)payloadLength;

            Encoding.UTF8.GetBytes(json, 0, json.Length, frame, 4);
            return frame;
        }

        /// <summary>
        /// Write a pre-framed packet buffer to Stream (NetworkStream or SslStream) in a single write call.
        /// </summary>
        public static void SendRawFrame(Stream stream, byte[] frame)
        {
            if (stream == null) throw new ArgumentNullException(nameof(stream));
            if (frame == null || frame.Length < 4) throw new ArgumentException("Invalid frame buffer.", nameof(frame));

            stream.Write(frame, 0, frame.Length);
        }

        /// <summary>
        /// Gửi packet qua Stream (length-prefixed, single buffer write)
        /// </summary>
        public static void SendPacket(Stream stream, Packet packet)
        {
            var frame = FramePacket(packet);
            SendRawFrame(stream, frame);
        }

        /// <summary>
        /// Đọc packet từ Stream (length-prefixed, synchronous)
        /// </summary>
        public static Packet ReceivePacket(Stream stream)
        {
            return ReceivePacket(stream, AppConstants.MaxPacketSize);
        }

        /// <summary>
        /// Đọc packet từ Stream với giới hạn kích thước tùy chỉnh
        /// </summary>
        public static Packet ReceivePacket(Stream stream, int maxPacketSize)
        {
            var lengthBytes = new byte[4];
            if (!ReadExact(stream, lengthBytes, 4))
                return null;

            int length = DecodeBigEndianInt32(lengthBytes);
            if (length <= 0 || length > maxPacketSize)
                return null;

            var payloadBytes = new byte[length];
            if (!ReadExact(stream, payloadBytes, length))
                return null;

            var json = Encoding.UTF8.GetString(payloadBytes, 0, length);
            return Deserialize(json);
        }

        /// <summary>
        /// Đọc packet bất đồng bộ qua IOCP (hỗ trợ cả NetworkStream và SslStream)
        /// </summary>
        public static async Task<Packet> ReceivePacketAsync(
            Stream stream,
            CancellationToken ct = default(CancellationToken),
            int maxPacketSize = AppConstants.MaxPacketSize)
        {
            var lengthBytes = new byte[4];
            if (!await ReadExactAsync(stream, lengthBytes, 4, ct).ConfigureAwait(false))
                return null;

            int length = DecodeBigEndianInt32(lengthBytes);
            if (length <= 0 || length > maxPacketSize)
                return null;

            var payloadBytes = new byte[length];
            if (!await ReadExactAsync(stream, payloadBytes, length, ct).ConfigureAwait(false))
                return null;

            var json = Encoding.UTF8.GetString(payloadBytes, 0, length);
            return Deserialize(json);
        }

        private static int DecodeBigEndianInt32(byte[] buffer)
        {
            return (buffer[0] << 24) | (buffer[1] << 16) | (buffer[2] << 8) | buffer[3];
        }

        /// <summary>
        /// Đọc đúng N bytes từ stream vào buffer có sẵn
        /// </summary>
        private static bool ReadExact(Stream stream, byte[] buffer, int count)
        {
            int totalRead = 0;

            while (totalRead < count)
            {
                int bytesRead = stream.Read(buffer, totalRead, count - totalRead);
                if (bytesRead == 0)
                    return false; // Connection closed

                totalRead += bytesRead;
            }

            return true;
        }

        /// <summary>
        /// Đọc đúng N bytes bất đồng bộ từ stream vào buffer có sẵn
        /// </summary>
        private static async Task<bool> ReadExactAsync(Stream stream, byte[] buffer, int count, CancellationToken ct)
        {
            int totalRead = 0;

            while (totalRead < count)
            {
                int bytesRead = await stream.ReadAsync(buffer, totalRead, count - totalRead, ct).ConfigureAwait(false);
                if (bytesRead == 0)
                    return false; // Connection closed

                totalRead += bytesRead;
            }

            return true;
        }
    }
}
