using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Text;

namespace ZTalk.Client.Services
{
    /// <summary>
    /// Nhận file từ sender: tích luỹ chunks → ghép lại → lưu file an toàn trong Downloads.
    /// </summary>
    public class FileReceiveService
    {
        private const int MaxAllowedChunks = 16384; // ~1 GB at 64 KB chunks
        private const long MaxAllowedFileSize = 1024L * 1024L * 1024L;

        private readonly string _downloadDir;
        private readonly string _fullDownloadDirPrefix;

        /// <summary>transferId → thông tin file đang nhận</summary>
        private readonly ConcurrentDictionary<string, IncomingFile> _incomingFiles
            = new ConcurrentDictionary<string, IncomingFile>();

        /// <summary>Event khi nhận file xong (filePath, senderName)</summary>
        public event Action<string, string> OnFileReceived;

        /// <summary>Event khi nhận chunk (transferId, chunkIndex, totalChunks)</summary>
        public event Action<string, int, int> OnReceiveProgress;

        public FileReceiveService(string downloadDir = null)
        {
            _downloadDir = downloadDir ?? Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Downloads");
            if (!Directory.Exists(_downloadDir))
                Directory.CreateDirectory(_downloadDir);

            string fullDir = Path.GetFullPath(_downloadDir);
            _fullDownloadDirPrefix = fullDir.EndsWith(Path.DirectorySeparatorChar.ToString(), StringComparison.Ordinal)
                ? fullDir
                : fullDir + Path.DirectorySeparatorChar;
        }

        /// <summary>
        /// Xử lý FileHeader → khởi tạo session nhận file với kiểm tra giới hạn & đường dẫn an toàn
        /// </summary>
        public void HandleFileHeader(string senderId, string senderName, string fileName, long fileSize, int totalChunks, string transferId)
        {
            if (string.IsNullOrWhiteSpace(transferId)) return;
            if (fileSize < 0 || fileSize > MaxAllowedFileSize) return;
            if (totalChunks < 0 || totalChunks > MaxAllowedChunks) return;

            var incoming = new IncomingFile
            {
                SenderId = senderId,
                SenderName = senderName,
                FileName = SanitizeFileName(fileName),
                FileSize = fileSize,
                TotalChunks = totalChunks,
                TransferId = transferId,
                Chunks = new Dictionary<int, byte[]>(Math.Min(totalChunks, 256))
            };

            _incomingFiles[transferId] = incoming;
        }

        /// <summary>
        /// Xử lý FileChunk (Base64) → tích luỹ chunk data
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
        /// Xử lý FileChunk (byte[]) → tích luỹ chunk data (hỗ trợ trực tiếp dữ liệu đã giải mã)
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
                incoming.Chunks[chunkIndex] = chunkData;
                receivedCount = incoming.Chunks.Count;
            }

            OnReceiveProgress?.Invoke(transferId, receivedCount, incoming.TotalChunks);
        }

        /// <summary>
        /// Xử lý FileComplete → xác thực đủ chunks → ghép lại → lưu file an toàn
        /// Returns: đường dẫn file đã lưu, hoặc null nếu lỗi / thiếu chunk
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
                    if (incoming.TotalChunks > 0 && incoming.Chunks.Count < incoming.TotalChunks)
                        return null; // Reject incomplete/corrupt transfer

                    string safeName = SanitizeFileName(incoming.FileName);
                    string filePath = BuildUniqueSafePath(safeName);

                    using (var fs = File.Create(filePath))
                    {
                        for (int i = 0; i < incoming.TotalChunks; i++)
                        {
                            byte[] chunk;
                            if (!incoming.Chunks.TryGetValue(i, out chunk))
                                return null;

                            fs.Write(chunk, 0, chunk.Length);
                        }
                    }

                    OnFileReceived?.Invoke(filePath, incoming.SenderName);
                    return filePath;
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Error completing file transfer: {ex.Message}");
                return null;
            }
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

        /// <summary>Thông tin 1 file đang nhận</summary>
        private sealed class IncomingFile
        {
            public readonly object SyncRoot = new object();
            public string SenderId;
            public string SenderName;
            public string FileName;
            public long FileSize;
            public int TotalChunks;
            public string TransferId;
            public Dictionary<int, byte[]> Chunks;
        }
    }
}
