using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using ZTalk.Shared.Crypto;
using ZTalk.Shared.Protocol;

namespace ZTalk.Client.Services
{
    /// <summary>
    /// Lưu lịch sử tin nhắn local bằng file JSON lines (được bảo vệ bằng Windows DPAPI CurrentUser).
    /// Cho phép đọc lại lịch sử E2EE đã giải mã an toàn trên máy nhân viên kể cả sau khi xoay khóa phiên ECDH.
    /// </summary>
    public class MessageHistoryService : IMessageHistoryService
    {
        private readonly string _historyDir;
        private readonly string _fullHistoryDirPrefix;
        private readonly bool _encryptAtRest;
        private readonly object _ioLock = new object();

        public MessageHistoryService(string historyDir = null, bool encryptAtRest = true)
        {
            _historyDir = historyDir ?? Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "ChatHistory");
            _encryptAtRest = encryptAtRest;
            if (!Directory.Exists(_historyDir))
                Directory.CreateDirectory(_historyDir);

            string fullDir = Path.GetFullPath(_historyDir);
            _fullHistoryDirPrefix = fullDir.EndsWith(Path.DirectorySeparatorChar.ToString(), StringComparison.Ordinal)
                ? fullDir
                : fullDir + Path.DirectorySeparatorChar;
        }

        /// <summary>
        /// Lưu 1 tin nhắn vào file lịch sử (JSON chuẩn + mã hóa DPAPI CurrentUser trên đĩa)
        /// </summary>
        public void SaveMessage(string conversationId, string senderId, string senderName, string content, bool isFile)
        {
            var filePath = GetFilePath(conversationId);
            var item = new MessageHistoryItem
            {
                SenderId = senderId,
                SenderName = senderName,
                Content = content,
                Timestamp = DateTime.Now.ToString("O"),
                IsFile = isFile
            };

            var json = PacketSerializer.ToJson(item);
            if (string.IsNullOrEmpty(json)) return;

            var line = _encryptAtRest ? StorageCipher.ProtectDpapiLine(json) : json;

            try
            {
                lock (_ioLock)
                {
                    File.AppendAllText(filePath, line + Environment.NewLine, Encoding.UTF8);
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"Error saving local history: {ex.Message}");
            }
        }

        /// <summary>
        /// Lấy lịch sử chat từ file (tự giải mã DPAPI và tương thích ngược dòng plaintext cũ)
        /// </summary>
        public List<MessageHistoryItem> GetHistory(string conversationId, int limit = 100)
        {
            var result = new List<MessageHistoryItem>();
            if (limit <= 0) return result;

            var filePath = GetFilePath(conversationId);
            if (!File.Exists(filePath))
                return result;

            try
            {
                string[] lines;
                lock (_ioLock)
                {
                    lines = File.ReadAllLines(filePath, Encoding.UTF8);
                }

                int start = Math.Max(0, lines.Length - limit);
                for (int i = start; i < lines.Length; i++)
                {
                    var rawLine = lines[i];
                    if (string.IsNullOrWhiteSpace(rawLine)) continue;

                    try
                    {
                        string jsonLine = StorageCipher.UnprotectDpapiLine(rawLine);
                        var item = PacketSerializer.FromJson<MessageHistoryItem>(jsonLine);
                        if (item != null)
                            result.Add(item);
                    }
                    catch { }
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"Error reading local history: {ex.Message}");
            }

            return result;
        }

        private string GetFilePath(string conversationId)
        {
            string safeId = SanitizeConversationId(conversationId);
            string fullPath = Path.GetFullPath(Path.Combine(_historyDir, $"history_{safeId}.json"));

            if (!fullPath.StartsWith(_fullHistoryDirPrefix, StringComparison.OrdinalIgnoreCase))
                throw new UnauthorizedAccessException("Invalid conversation ID path.");

            return fullPath;
        }

        private static string SanitizeConversationId(string conversationId)
        {
            if (string.IsNullOrWhiteSpace(conversationId)) return "unknown";

            var sb = new StringBuilder(conversationId.Length);
            for (int i = 0; i < conversationId.Length; i++)
            {
                char c = conversationId[i];
                if (char.IsLetterOrDigit(c) || c == '_' || c == '-')
                    sb.Append(c);
                else
                    sb.Append('_');
            }

            string result = sb.ToString();
            return result.Length > 64 ? result.Substring(0, 64) : result;
        }
    }
}
