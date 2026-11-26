using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Text;
using ZTalk.Shared.Constants;

namespace ZTalk.Client.Services
{
    /// <summary>
    /// Nhận file từ sender bằng disk-streaming (.part) theo offset:
    /// RAM cố định O(1) bất kể dung lượng file, hỗ trợ ghép chunk đến sai thứ tự,
    /// chống path traversal và tự dọn file dở dang.
    /// </summary>
    public class FileReceiveService : IDisposable
    {
        private const int MaxAllowedChunks = 16384; // ~1 GB at 64 KB chunks
        private const long MaxAllowedFileSize = 1024L * 1024L * 1024L;

        private readonly string _downloadDir;
        private readonly string _partDir;
        private readonly string _fullDownloadDirPrefix;

        /// <summary>transferId → phiên nhận file đang stream ra .part</summary>
        private readonly ConcurrentDictionary<string, IncomingFile> _incomingFiles
            = new ConcurrentDictionary<string, IncomingFile>();

        /// <summary>Event khi nhận file xong (filePath, senderName)</summary>
        public event Action<string, string> OnFileReceived;

        /// <summary>Event khi nhận chunk (transferId, receivedCount, totalChunks)</summary>
        public event Action<string, int, int> OnReceiveProgress;

        public int ActiveTransferCount => _incomingFiles.Count;

        public FileReceiveService(string downloadDir = null)
        {
            _downloadDir = downloadDir ?? Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Downloads");
            _partDir = Path.Combine(_downloadDir, ".part");

            if (!Directory.Exists(_downloadDir))
                Directory.CreateDirectory(_downloadDir);
            if (!Directory.Exists(_partDir))
                Directory.CreateDirectory(_partDir);

            string fullDir = Path.GetFullPath(_downloadDir);
            _fullDownloadDirPrefix = fullDir.EndsWith(Path.DirectorySeparatorChar.ToString(), StringComparison.Ordinal)
                ? fullDir
                : fullDir + Path.DirectorySeparatorChar;
        }

        /// <summary>
        /// Xử lý FileHeader → khởi tạo file tạm .part trên đĩa (không giữ chunk trong RAM)
        /// </summary>
        public void HandleFileHeader(string senderId, string senderName, string fileName, long fileSize, int totalChunks, string transferId)
        {
            if (string.IsNullOrWhiteSpace(transferId)) return;
            if (fileSize < 0 || fileSize > MaxAllowedFileSize) return;
            if (totalChunks < 0 || totalChunks > MaxAllowedChunks) return;

            CleanupStaleTransfers(TimeSpan.FromMinutes(30));

            string safeTransfer = SanitizeFileName(transferId);
            string partPath = Path.Combine(_partDir, $"{safeTransfer}_{Guid.NewGuid():N}.part");

            try
            {
                var fs = new FileStream(partPath, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.None, 65536);
                if (fileSize > 0)
                    fs.SetLength(fileSize);

                var incoming = new IncomingFile
                {
                    SenderId = senderId,
                    SenderName = senderName,
                    FileName = SanitizeFileName(fileName),
                    FileSize = fileSize,
                    TotalChunks = totalChunks,
                    TransferId = transferId,
                    PartFilePath = partPath,
                    PartStream = fs,
                    ReceivedChunks = new HashSet<int>(),
                    LastActivityUtc = DateTime.UtcNow
                };

                IncomingFile existing;
                if (_incomingFiles.TryRemove(transferId, out existing))
                {
                    existing.AbortAndDelete();
                }
                _incomingFiles[transferId] = incoming;
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Error initializing .part file: {ex.Message}");
                TryDeleteFile(partPath);
            }
        }

        /// <summary>
        /// Xử lý FileChunk (Base64) → giải mã và ghi thẳng xuống đĩa theo offset
        /// </summary>
        public void HandleFileChunk(string transferId, int chunkIndex, string chunkDataBase64)
        {
            if (string.IsNullOrEmpty(transferId) || string.IsNullOrEmpty(chunkDataBase64))
                return;

            try
            {
                byte[] chunkData = Convert.FromBase64String(chunkDataBase64);
                HandleFileChunk(transferId, chunkIndex, chunkData);
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Error decoding file chunk: {ex.Message}");
            }
        }

        /// <summary>
        /// Xử lý FileChunk (byte[]) → seek đúng vị trí (chunkIndex * FileChunkSize) và ghi trực tiếp ra .part
        /// </summary>
        public void HandleFileChunk(string transferId, int chunkIndex, byte[] chunkData)
        {
            if (string.IsNullOrEmpty(transferId) || chunkData == null)
                return;

            IncomingFile incoming;
            if (!_incomingFiles.TryGetValue(transferId, out incoming))
                return;

            if (chunkIndex < 0 || (incoming.TotalChunks > 0 && chunkIndex >= incoming.TotalChunks))
                return;

            int receivedCount;
            lock (incoming.SyncRoot)
            {
                if (incoming.IsClosed || incoming.PartStream == null)
                    return;

                long offset = (long)chunkIndex * AppConstants.FileChunkSize;
                if (offset + chunkData.Length > MaxAllowedFileSize)
                    return;

                incoming.PartStream.Seek(offset, SeekOrigin.Begin);
                incoming.PartStream.Write(chunkData, 0, chunkData.Length);
                incoming.ReceivedChunks.Add(chunkIndex);
                incoming.LastActivityUtc = DateTime.UtcNow;

                long endPos = offset + chunkData.Length;
                if (endPos > incoming.MaxWrittenLength)
                    incoming.MaxWrittenLength = endPos;

                receivedCount = incoming.ReceivedChunks.Count;
            }

            OnReceiveProgress?.Invoke(transferId, receivedCount, incoming.TotalChunks);
        }

        /// <summary>
        /// Xử lý FileComplete → xác thực đủ chunks → đóng .part → di chuyển atomic sang file đích an toàn
        /// </summary>
        public string HandleFileComplete(string transferId)
        {
            if (string.IsNullOrEmpty(transferId))
                return null;

            IncomingFile incoming;
            if (!_incomingFiles.TryRemove(transferId, out incoming))
                return null;

            try
            {
                lock (incoming.SyncRoot)
                {
                    if (incoming.TotalChunks > 0 && incoming.ReceivedChunks.Count < incoming.TotalChunks)
                    {
                        incoming.AbortAndDelete();
                        return null; // Reject incomplete/corrupt transfer
                    }

                    // Ensure exact length and flush to disk before moving
                    long finalLen = incoming.FileSize > 0 ? incoming.FileSize : incoming.MaxWrittenLength;
                    if (incoming.PartStream != null)
                    {
                        if (incoming.PartStream.Length != finalLen)
                            incoming.PartStream.SetLength(finalLen);
                        incoming.PartStream.Flush();
                        incoming.PartStream.Dispose();
                        incoming.PartStream = null;
                    }
                    incoming.IsClosed = true;

                    string safeName = SanitizeFileName(incoming.FileName);
                    string filePath = BuildUniqueSafePath(safeName);
                    File.Move(incoming.PartFilePath, filePath);

                    OnFileReceived?.Invoke(filePath, incoming.SenderName);
                    return filePath;
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Error completing file transfer: {ex.Message}");
                incoming.AbortAndDelete();
                return null;
            }
        }

        /// <summary>
        /// Dọn dẹp các phiên nhận file bị bỏ dở quá thời gian maxIdle (xóa file .part tạm)
        /// </summary>
        public int CleanupStaleTransfers(TimeSpan maxIdle)
        {
            int cleaned = 0;
            DateTime cutoff = DateTime.UtcNow - maxIdle;

            foreach (var kvp in _incomingFiles)
            {
                bool stale;
                lock (kvp.Value.SyncRoot)
                {
                    stale = kvp.Value.LastActivityUtc < cutoff;
                }

                if (stale)
                {
                    IncomingFile removed;
                    if (_incomingFiles.TryRemove(kvp.Key, out removed))
                    {
                        removed.AbortAndDelete();
                        cleaned++;
                    }
                }
            }

            return cleaned;
        }

        private string BuildUniqueSafePath(string safeName)
        {
            string filePath = Path.GetFullPath(Path.Combine(_downloadDir, safeName));
            if (!filePath.StartsWith(_fullDownloadDirPrefix, StringComparison.OrdinalIgnoreCase))
                throw new UnauthorizedAccessException("Blocked path traversal attempt in file download.");

            int counter = 1;
            string nameWithoutExt = Path.GetFileNameWithoutExtension(safeName);
            string ext = Path.GetExtension(safeName);

            while (File.Exists(filePath))
            {
                filePath = Path.GetFullPath(Path.Combine(_downloadDir, $"{nameWithoutExt}_{counter}{ext}"));
                if (!filePath.StartsWith(_fullDownloadDirPrefix, StringComparison.OrdinalIgnoreCase))
                    throw new UnauthorizedAccessException("Blocked path traversal attempt in file download.");
                counter++;
            }

            return filePath;
        }

        public static string SanitizeFileName(string fileName)
        {
            if (string.IsNullOrWhiteSpace(fileName))
                return "unnamed_file";

            // Strip any path separators (both Windows and POSIX)
            int lastSlash = fileName.LastIndexOfAny(new[] { '\\', '/' });
            string baseName = lastSlash >= 0 ? fileName.Substring(lastSlash + 1) : fileName;
            baseName = baseName.Trim();

            if (string.IsNullOrEmpty(baseName) || baseName == "." || baseName == "..")
                return "unnamed_file";

            var invalidChars = Path.GetInvalidFileNameChars();
            var sb = new StringBuilder(baseName.Length);
            for (int i = 0; i < baseName.Length; i++)
            {
                char c = baseName[i];
                sb.Append(Array.IndexOf(invalidChars, c) >= 0 ? '_' : c);
            }

            string sanitized = sb.ToString().Trim('.');
            return string.IsNullOrWhiteSpace(sanitized) ? "unnamed_file" : sanitized;
        }

        private static void TryDeleteFile(string path)
        {
            if (string.IsNullOrEmpty(path)) return;
            try
            {
                if (File.Exists(path))
                    File.Delete(path);
            }
            catch { }
        }

        /// <summary>
        /// Mở file bằng ứng dụng mặc định của hệ thống
        /// </summary>
        public static void OpenFile(string filePath)
        {
            if (!File.Exists(filePath)) return;

            try
            {
                Process.Start(new ProcessStartInfo
                {
                    FileName = filePath,
                    UseShellExecute = true
                });
            }
            catch { }
        }

        /// <summary>
        /// Mở thư mục chứa file
        /// </summary>
        public static void OpenFolder(string filePath)
        {
            if (!File.Exists(filePath)) return;

            try
            {
                Process.Start("explorer.exe", $"/select,\"{filePath}\"");
            }
            catch { }
        }

        public void Dispose()
        {
            foreach (var kvp in _incomingFiles)
            {
                IncomingFile removed;
                if (_incomingFiles.TryRemove(kvp.Key, out removed))
                {
                    removed.AbortAndDelete();
                }
            }
        }

        /// <summary>Thông tin 1 file đang stream xuống đĩa .part</summary>
        private sealed class IncomingFile
        {
            public readonly object SyncRoot = new object();
            public string SenderId;
            public string SenderName;
            public string FileName;
            public long FileSize;
            public int TotalChunks;
            public string TransferId;
            public string PartFilePath;
            public FileStream PartStream;
            public HashSet<int> ReceivedChunks;
            public long MaxWrittenLength;
            public DateTime LastActivityUtc;
            public bool IsClosed;

            public void AbortAndDelete()
            {
                lock (SyncRoot)
                {
                    IsClosed = true;
                    try { PartStream?.Dispose(); } catch { }
                    PartStream = null;
                    TryDeleteFile(PartFilePath);
                }
            }
        }
    }
}
