using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Text;
using ZTalk.Shared.Crypto;
using ZTalk.Shared.Protocol;

namespace ZTalk.Server.Data
{
    /// <summary>
    /// Thread-safe persistent offline message queue per recipient user.
    /// Supports AEAD encryption-at-rest via StorageCipher, path sandboxing, and atomic writes.
    /// </summary>
    public class OfflineMessageQueue
    {
        private readonly string _queueDir;
        private readonly string _fullQueueDirPrefix;
        private readonly byte[] _storageKey;
        private readonly int _maxPerUser;
        private readonly ConcurrentDictionary<string, object> _userLocks
            = new ConcurrentDictionary<string, object>(StringComparer.OrdinalIgnoreCase);

        public OfflineMessageQueue(string queueDir = null, byte[] storageKey = null, int maxPerUser = 500)
        {
            _queueDir = queueDir ?? Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "OfflineQueue");
            _storageKey = storageKey;
            _maxPerUser = Math.Max(10, maxPerUser);

            if (!Directory.Exists(_queueDir))
                Directory.CreateDirectory(_queueDir);

            string fullDir = Path.GetFullPath(_queueDir);
            _fullQueueDirPrefix = fullDir.EndsWith(Path.DirectorySeparatorChar.ToString(), StringComparison.Ordinal)
                ? fullDir
                : fullDir + Path.DirectorySeparatorChar;
        }

        public void Enqueue(string receiverId, Packet packet)
        {
            if (string.IsNullOrWhiteSpace(receiverId) || packet == null)
                return;

            string safeId = SanitizeId(receiverId);
            string filePath = GetSafeFilePath(safeId);
            var sync = _userLocks.GetOrAdd(safeId, _ => new object());

            lock (sync)
            {
                var queued = LoadQueueInternal(filePath);
                queued.Add(packet);
                if (queued.Count > _maxPerUser)
                    queued.RemoveRange(0, queued.Count - _maxPerUser);

                SaveQueueAtomicInternal(filePath, queued);
            }
        }

        public List<Packet> DequeueAll(string receiverId)
        {
            if (string.IsNullOrWhiteSpace(receiverId))
                return new List<Packet>();

            string safeId = SanitizeId(receiverId);
            string filePath = GetSafeFilePath(safeId);
            var sync = _userLocks.GetOrAdd(safeId, _ => new object());

            lock (sync)
            {
                if (!File.Exists(filePath))
                    return new List<Packet>();

                var queued = LoadQueueInternal(filePath);
                try { File.Delete(filePath); } catch { }
                return queued;
            }
        }

        public int GetPendingCount(string receiverId)
        {
            if (string.IsNullOrWhiteSpace(receiverId)) return 0;

            string safeId = SanitizeId(receiverId);
            string filePath = GetSafeFilePath(safeId);
            var sync = _userLocks.GetOrAdd(safeId, _ => new object());

            lock (sync)
            {
                if (!File.Exists(filePath)) return 0;
                return LoadQueueInternal(filePath).Count;
            }
        }

        private List<Packet> LoadQueueInternal(string filePath)
        {
            if (!File.Exists(filePath))
                return new List<Packet>();

            try
            {
                string raw = File.ReadAllText(filePath, Encoding.UTF8);
                string json = StorageCipher.DecryptText(raw, _storageKey);
                return PacketSerializer.FromJson<List<Packet>>(json) ?? new List<Packet>();
            }
            catch
            {
                return new List<Packet>();
            }
        }

        private void SaveQueueAtomicInternal(string filePath, List<Packet> packets)
        {
            try
            {
                string json = PacketSerializer.ToJson(packets);
                string toWrite = StorageCipher.EncryptText(json, _storageKey);
                string tempPath = filePath + ".tmp";
                File.WriteAllText(tempPath, toWrite, Encoding.UTF8);

                if (File.Exists(filePath))
                    File.Replace(tempPath, filePath, null);
                else
                    File.Move(tempPath, filePath);
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"OfflineMessageQueue save error: {ex.Message}");
            }
        }

        private string GetSafeFilePath(string safeId)
        {
            string fullPath = Path.GetFullPath(Path.Combine(_queueDir, safeId + ".queue"));
            if (!fullPath.StartsWith(_fullQueueDirPrefix, StringComparison.OrdinalIgnoreCase))
                throw new UnauthorizedAccessException("Invalid offline queue path.");
            return fullPath;
        }

        private static string SanitizeId(string id)
        {
            var sb = new StringBuilder(id.Length);
            for (int i = 0; i < id.Length; i++)
            {
                char c = id[i];
                sb.Append((char.IsLetterOrDigit(c) || c == '_' || c == '-') ? c : '_');
            }
            string s = sb.ToString();
            return s.Length > 64 ? s.Substring(0, 64) : s;
        }
    }
}
