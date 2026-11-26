using System;
using System.IO;
using System.Text;
using ZTalk.Shared.Constants;
using ZTalk.Shared.Protocol;

namespace ZTalk.Server.Config
{
    /// <summary>
    /// Security and operational configuration for ZTalk.Server.
    /// Loaded from server.security.json or created programmatically.
    /// </summary>
    public class ServerSecurityConfig
    {
        public int Port { get; set; } = AppConstants.DefaultTcpPort;

        /// <summary>Enable mandatory TLS 1.2 encryption on all TCP connections.</summary>
        public bool EnableTls { get; set; } = false;

        /// <summary>Path to server PFX certificate (relative to app base directory or absolute).</summary>
        public string TlsCertPath { get; set; } = @"certs\ztalk-server.pfx";

        /// <summary>Password for server PFX certificate.</summary>
        public string TlsCertPassword { get; set; } = "";

        /// <summary>Common Name / hostname used when auto-generating a self-signed cert.</summary>
        public string TlsSubjectCn { get; set; } = "ZTalk-Server";

        /// <summary>Auto-generate a self-signed PFX if EnableTls is true and TlsCertPath does not exist.</summary>
        public bool AutoGenerateSelfSignedCert { get; set; } = true;

        /// <summary>Allow unauthenticated clients to self-register accounts. Disable in enterprise deployments.</summary>
        public bool AllowPublicRegistration { get; set; } = true;

        /// <summary>Seed default demo accounts (alice/bob/charlie). Disabled automatically in enterprise mode.</summary>
        public bool SeedDemoUsers { get; set; } =
#if DEBUG
            true;
#else
            false;
#endif

        /// <summary>Maximum concurrent TCP connections accepted by the server.</summary>
        public int MaxConnections { get; set; } = 250;

        /// <summary>Maximum concurrent TCP connections allowed per client IP address.</summary>
        public int MaxConnectionsPerIp { get; set; } = 25;

        /// <summary>Maximum seconds an unauthenticated socket may stay open before disconnect.</summary>
        public int AuthTimeoutSeconds { get; set; } = 10;

        /// <summary>Maximum milliseconds allowed for TLS handshake.</summary>
        public int TlsHandshakeTimeoutMs { get; set; } = 5000;

        /// <summary>Failed login attempts before lockout triggers.</summary>
        public int MaxFailedLoginAttempts { get; set; } = 5;

        /// <summary>Lockout duration in minutes after exceeding MaxFailedLoginAttempts.</summary>
        public int LockoutMinutes { get; set; } = 5;

        /// <summary>Directory for rotating security audit log files.</summary>
        public string AuditLogDirectory { get; set; } = "Logs";

        public static ServerSecurityConfig CreateEnterpriseDefault()
        {
            return new ServerSecurityConfig
            {
                EnableTls = true,
                AutoGenerateSelfSignedCert = true,
                AllowPublicRegistration = false,
                SeedDemoUsers = false,
                MaxConnections = 250,
                MaxConnectionsPerIp = 25,
                AuthTimeoutSeconds = 10,
                MaxFailedLoginAttempts = 5,
                LockoutMinutes = 5
            };
        }

        public static ServerSecurityConfig LoadOrDefault(string filePath = null, bool enterpriseDefault = false)
        {
            string resolvedPath = filePath ?? Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "server.security.json");
            if (File.Exists(resolvedPath))
            {
                try
                {
                    string json = File.ReadAllText(resolvedPath, Encoding.UTF8);
                    var cfg = PacketSerializer.FromJson<ServerSecurityConfig>(json);
                    if (cfg != null)
                        return cfg;
                }
                catch { }
            }

            return enterpriseDefault ? CreateEnterpriseDefault() : new ServerSecurityConfig();
        }

        public void Save(string filePath = null)
        {
            string resolvedPath = filePath ?? Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "server.security.json");
            string dir = Path.GetDirectoryName(Path.GetFullPath(resolvedPath));
            if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir))
                Directory.CreateDirectory(dir);

            string json = PacketSerializer.ToJson(this);
            File.WriteAllText(resolvedPath, json, Encoding.UTF8);
        }

        public string ResolveCertPath()
        {
            if (string.IsNullOrWhiteSpace(TlsCertPath))
                return Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "certs", "ztalk-server.pfx");

            return Path.IsPathRooted(TlsCertPath)
                ? TlsCertPath
                : Path.Combine(AppDomain.CurrentDomain.BaseDirectory, TlsCertPath);
        }

        public string ResolveAuditLogDirectory()
        {
            if (string.IsNullOrWhiteSpace(AuditLogDirectory))
                return Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Logs");

            return Path.IsPathRooted(AuditLogDirectory)
                ? AuditLogDirectory
                : Path.Combine(AppDomain.CurrentDomain.BaseDirectory, AuditLogDirectory);
        }
    }
}
