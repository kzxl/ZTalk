using System;
using System.IO;
using System.Text;
using ZTalk.Shared.Constants;
using ZTalk.Shared.Protocol;

namespace ZTalk.Client.Config
{
    /// <summary>
    /// Client connection and TLS pinning configuration loaded from client.config.json.
    /// Allows IT admins to distribute pre-configured secure defaults alongside ZTalk.Client.exe.
    /// </summary>
    public class ClientSecurityConfig
    {
        public string ServerHost { get; set; } = AppConstants.DefaultServerAddress;
        public int ServerPort { get; set; } = AppConstants.DefaultTcpPort;

        /// <summary>Optional external WAN / EdgeRelay hostname used when LAN ServerHost is unreachable.</summary>
        public string FallbackServerHost { get; set; } = "";

        /// <summary>Port for external WAN / EdgeRelay endpoint (default 443).</summary>
        public int FallbackServerPort { get; set; } = 443;

        /// <summary>Fast timeout (ms) when probing LAN primary endpoint before falling back to WAN Edge.</summary>
        public int LanConnectTimeoutMs { get; set; } = 1200;

        public bool UseTls { get; set; } = false;
        public string TlsTargetHost { get; set; } = "";
        public string PinnedCertSha256 { get; set; } = "";
        public bool AllowSelfSignedCert { get; set; } = false;
        public int ConnectTimeoutMs { get; set; } = 5000;
        public bool HideDemoAccounts { get; set; } = false;

        /// <summary>Automatically reconnect with exponential backoff and re-authenticate on unexpected drop.</summary>
        public bool AutoReconnect { get; set; } = true;
        public int ReconnectInitialDelayMs { get; set; } = 1500;
        public int ReconnectMaxDelayMs { get; set; } = 30000;

        public static ClientSecurityConfig LoadOrDefault(string filePath = null)
        {
            string resolvedPath = filePath ?? Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "client.config.json");
            if (File.Exists(resolvedPath))
            {
                try
                {
                    string json = File.ReadAllText(resolvedPath, Encoding.UTF8);
                    var cfg = PacketSerializer.FromJson<ClientSecurityConfig>(json);
                    if (cfg != null)
                        return cfg;
                }
                catch { }
            }

            return new ClientSecurityConfig();
        }
    }
}
