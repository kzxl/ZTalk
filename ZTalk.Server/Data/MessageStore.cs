using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace ZTalk.Server.Data
{
    /// <summary>
    /// Lưu trữ lịch sử tin nhắn trên server.
    /// Mỗi conversation (userId1_userId2) lưu vào 1 file JSON với per-conversation cache + lock.
    /// Group chat lưu riêng file __group__.json.
    /// </summary>
    public class MessageStore
    {
        private const int MaxRecordsPerConversation = 500;

        private readonly string _dataDir;
        private readonly string _fullDataDirPrefix;
        private readonly ConcurrentDictionary<string, ConversationBucket> _cache
            = new ConcurrentDictionary<string, ConversationBucket>(StringComparer.OrdinalIgnoreCase);

        public MessageStore(string dataDir = null)
        {
            _dataDir = dataDir ?? Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "ChatData");
            if (!Directory.Exists(_dataDir))
                Directory.CreateDirectory(_dataDir);

            string fullDir = Path.GetFullPath(_dataDir);
            _fullDataDirPrefix = fullDir.EndsWith(Path.DirectorySeparatorChar.ToString(), StringComparison.Ordinal)
                ? fullDir
                : fullDir + Path.DirectorySeparatorChar;
        }

        /// <summary>
        /// Lưu 1 tin nhắn (in-memory write-through cache + per-conversation lock + atomic write)
        /// </summary>
        public void SaveMessage(string senderId, string receiverId, string senderName, string content, bool isFile)
        {
            var record = new ChatRecord
            {
                SenderId = senderId,
                SenderName = senderName,
                Content = content,
                IsFile = isFile,
                Timestamp = DateTime.UtcNow
            };

            string key = GetConversationKey(senderId, receiverId);
            string filePath = GetSafeFilePath(key);
            var bucket = GetOrCreateBucket(key, filePath);

            lock (bucket.SyncRoot)
            {
                EnsureLoaded(bucket, filePath);
                bucket.Records.Add(record);

                // Giới hạn 500 tin nhắn gần nhất per conversation
                if (bucket.Records.Count > MaxRecordsPerConversation)
                    bucket.Records.RemoveRange(0, bucket.Records.Count - MaxRecordsPerConversation);

                SaveRecordsAtomic(filePath, bucket.Records);
            }
        }

        /// <summary>
        /// Lấy lịch sử chat giữa 2 user (hoặc group) từ in-memory cache
        /// </summary>
        public List<ChatRecord> GetHistory(string userId1, string userId2, int maxCount = 50)
        {
            if (maxCount <= 0) return new List<ChatRecord>();

            string key = GetConversationKey(userId1, userId2);
            string filePath = GetSafeFilePath(key);
            var bucket = GetOrCreateBucket(key, filePath);

            lock (bucket.SyncRoot)
            {
                EnsureLoaded(bucket, filePath);
                int total = bucket.Records.Count;
                if (total == 0) return new List<ChatRecord>();

                int count = Math.Min(maxCount, total);
                int start = total - count;
                return bucket.Records.GetRange(start, count);
            }
        }

        /// <summary>
        /// Serialize lịch sử thành JSON string để gửi cho client
        /// </summary>
        public string SerializeHistory(List<ChatRecord> records)
        {
            if (records == null || records.Count == 0) return "[]";
            return ZTalk.Shared.Protocol.PacketSerializer.ToJson(records);
        }

        private ConversationBucket GetOrCreateBucket(string key, string filePath)
        {
            return _cache.GetOrAdd(key, _ => new ConversationBucket());
        }

        private void EnsureLoaded(ConversationBucket bucket, string filePath)
        {
            if (bucket.IsLoaded) return;
            bucket.Records = LoadRecords(filePath);
            bucket.IsLoaded = true;
        }

        private string GetSafeFilePath(string key)
        {
            string filePath = Path.Combine(_dataDir, key + ".json");
            string fullPath = Path.GetFullPath(filePath);

            if (!fullPath.StartsWith(_fullDataDirPrefix, StringComparison.OrdinalIgnoreCase))
                throw new UnauthorizedAccessException("Invalid conversation key path.");

            return fullPath;
        }

        private static string GetConversationKey(string userId1, string userId2)
        {
            if (userId2 == null || userId2 == "__group__")
                return "__group__";

            string safe1 = SanitizeId(userId1);
            string safe2 = SanitizeId(userId2);

            // Sort để conversation key luôn giống nhau bất kể ai gửi trước
            if (StringComparer.OrdinalIgnoreCase.Compare(safe1, safe2) <= 0)
                return safe1 + "_" + safe2;

            return safe2 + "_" + safe1;
        }

        private static string SanitizeId(string id)
        {
            if (string.IsNullOrWhiteSpace(id)) return "unknown";

            var sb = new StringBuilder(id.Length);
            for (int i = 0; i < id.Length; i++)
            {
                char c = id[i];
                if (char.IsLetterOrDigit(c) || c == '_' || c == '-')
                    sb.Append(c);
                else
                    sb.Append('_');
            }

            string result = sb.ToString();
            return result.Length > 64 ? result.Substring(0, 64) : result;
        }

        private List<ChatRecord> LoadRecords(string filePath)
        {
            if (!File.Exists(filePath))
                return new List<ChatRecord>();

            try
            {
                string json = File.ReadAllText(filePath, Encoding.UTF8);
                return ZTalk.Shared.Protocol.PacketSerializer.FromJson<List<ChatRecord>>(json) ?? new List<ChatRecord>();
            }
            catch
            {
                // Preserve corrupt file as backup instead of silently destroying it on next write
                try
                {
                    string backupPath = filePath + ".corrupt." + DateTime.UtcNow.Ticks;
                    File.Copy(filePath, backupPath, true);
                }
                catch { }
                return new List<ChatRecord>();
            }
        }

        private void SaveRecordsAtomic(string filePath, List<ChatRecord> records)
        {
            try
            {
                string json = SerializeHistory(records);
                string tempPath = filePath + ".tmp";
                File.WriteAllText(tempPath, json, Encoding.UTF8);

                if (File.Exists(filePath))
                    File.Replace(tempPath, filePath, null);
                else
                    File.Move(tempPath, filePath);
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"Error saving chat records: {ex.Message}");
            }
        }

        private sealed class ConversationBucket
        {
            public readonly object SyncRoot = new object();
            public bool IsLoaded;
            public List<ChatRecord> Records;
        }
    }

    /// <summary>
    /// 1 bản ghi tin nhắn
    /// </summary>
    public class ChatRecord
    {
        public string SenderId { get; set; }
        public string SenderName { get; set; }
        public string Content { get; set; }
        public bool IsFile { get; set; }
        public DateTime Timestamp { get; set; }
    }
}
