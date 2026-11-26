using System;
using System.IO;
using System.Linq;
using System.Text;

namespace ZTalk.Server.Services
{
    /// <summary>
    /// Thread-safe rotating security audit logger writing daily UTC logs to disk.
    /// Rolls over at 10 MB per file and retains the latest 30 log files.
    /// </summary>
    public sealed class AuditLogger : IDisposable
    {
        private const long MaxFileSizeBytes = 10L * 1024L * 1024L;
        private const int MaxRetainedFiles = 30;

        private readonly string _logDir;
        private readonly object _sync = new object();
        private bool _disposed;

        public string LogDirectory => _logDir;

        public AuditLogger(string logDirectory)
        {
            _logDir = string.IsNullOrWhiteSpace(logDirectory)
                ? Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Logs")
                : logDirectory;

            if (!Directory.Exists(_logDir))
                Directory.CreateDirectory(_logDir);
        }

        public void Write(string category, string message)
        {
            if (_disposed) return;

            var now = DateTime.UtcNow;
            string line = $"[{now:yyyy-MM-ddTHH:mm:ss.fffZ}] [{category}] {message}{Environment.NewLine}";

            lock (_sync)
            {
                if (_disposed) return;

                try
                {
                    string filePath = ResolveActiveLogFile(now);
                    File.AppendAllText(filePath, line, Encoding.UTF8);
                }
                catch (Exception ex)
                {
                    System.Diagnostics.Debug.WriteLine($"AuditLogger write failed: {ex.Message}");
                }
            }
        }

        private string ResolveActiveLogFile(DateTime utcNow)
        {
            string baseName = $"audit-{utcNow:yyyyMMdd}";
            string path = Path.Combine(_logDir, baseName + ".log");

            if (File.Exists(path) && new FileInfo(path).Length >= MaxFileSizeBytes)
            {
                int seq = 1;
                string rotated;
                do
                {
                    rotated = Path.Combine(_logDir, $"{baseName}.{seq}.log");
                    seq++;
                } while (File.Exists(rotated));

                File.Move(path, rotated);
                PruneOldLogs();
            }

            return path;
        }

        private void PruneOldLogs()
        {
            try
            {
                var files = new DirectoryInfo(_logDir)
                    .GetFiles("audit-*.log")
                    .OrderByDescending(f => f.LastWriteTimeUtc)
                    .Skip(MaxRetainedFiles);

                foreach (var f in files)
                {
                    try { f.Delete(); } catch { }
                }
            }
            catch { }
        }

        public void Dispose()
        {
            lock (_sync)
            {
                _disposed = true;
            }
        }
    }
}
