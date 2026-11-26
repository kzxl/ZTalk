using System;
using System.Collections.Concurrent;
using ZTalk.Shared.Crypto;
using ZTalk.Shared.DTOs;
using ZTalk.Shared.Protocol;

namespace ZTalk.Client.Services
{
    /// <summary>
    /// Xử lý gửi/nhận tin nhắn text, quản lý mã hoá AES với từng user
    /// </summary>
    public class ChatService : IChatService
    {
        private readonly TcpClientService _tcpService;
        private readonly AesHelper _aesHelper;

        /// <summary>Shared keys cho từng user (userId → AES key)</summary>
        private readonly ConcurrentDictionary<string, byte[]> _sharedKeys;

        public string CurrentUserId { get; set; }

        public ChatService(TcpClientService tcpService)
        {
            _tcpService = tcpService;
            _aesHelper = new AesHelper();
            _sharedKeys = new ConcurrentDictionary<string, byte[]>();
        }

        /// <summary>
        /// Gửi tin nhắn text. Nếu có shared key với receiver → mã hoá AES.
        /// </summary>
        public void SendMessage(string receiverId, string message)
        {
            string content = message;
            bool isEncrypted = false;

            byte[] key;
            if (!string.IsNullOrEmpty(receiverId) && _sharedKeys.TryGetValue(receiverId, out key))
            {
                content = _aesHelper.Encrypt(message, key);
                isEncrypted = true;
            }

            var dto = new MessageDTO
            {
                Content = content,
                IsEncrypted = isEncrypted,
                SentAt = DateTime.Now
            };

            var data = PacketSerializer.ToJson(dto);
            var packet = new Packet(PacketType.Message, CurrentUserId, receiverId, data);
            _tcpService.SendPacket(packet);
        }

        /// <summary>
        /// Giải mã tin nhắn nhận được
        /// </summary>
        public string DecryptMessage(string senderId, string content, bool isEncrypted)
        {
            if (!isEncrypted) return content;

            byte[] key;
            if (!string.IsNullOrEmpty(senderId) && _sharedKeys.TryGetValue(senderId, out key))
            {
                try
                {
                    return _aesHelper.Decrypt(content, key);
                }
                catch
                {
                    return "[Không thể giải mã]";
                }
            }

            return "[Chưa có key để giải mã]";
        }

        /// <summary>
        /// Mã hoá dữ liệu nhị phân (file chunk) bằng shared key của receiver nếu đã trao đổi khoá
        /// </summary>
        public bool TryEncryptBytes(string receiverId, byte[] buffer, int offset, int count, out byte[] encrypted)
        {
            encrypted = null;
            byte[] key;
            if (string.IsNullOrEmpty(receiverId) || !_sharedKeys.TryGetValue(receiverId, out key))
                return false;

            byte[] slice;
            if (offset == 0 && count == buffer.Length)
            {
                slice = buffer;
            }
            else
            {
                slice = new byte[count];
                Buffer.BlockCopy(buffer, offset, slice, 0, count);
            }

            encrypted = _aesHelper.EncryptBytes(slice, key);
            return true;
        }

        /// <summary>
        /// Giải mã dữ liệu nhị phân (file chunk) bằng shared key của sender
        /// </summary>
        public bool TryDecryptBytes(string senderId, byte[] encryptedData, out byte[] decrypted)
        {
            decrypted = null;
            byte[] key;
            if (string.IsNullOrEmpty(senderId) || encryptedData == null || !_sharedKeys.TryGetValue(senderId, out key))
                return false;

            try
            {
                decrypted = _aesHelper.DecryptBytes(encryptedData, key);
                return true;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Lưu shared key cho 1 user (sau khi DH key exchange hoàn tất)
        /// </summary>
        public void SetSharedKey(string userId, byte[] key)
        {
            _sharedKeys.AddOrUpdate(userId, key, (k, v) => key);
        }

        /// <summary>
        /// Kiểm tra đã có shared key với user chưa
        /// </summary>
        public bool HasSharedKey(string userId)
        {
            return !string.IsNullOrEmpty(userId) && _sharedKeys.ContainsKey(userId);
        }
    }
}
