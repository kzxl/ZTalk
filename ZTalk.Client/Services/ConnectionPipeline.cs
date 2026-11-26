using System;
using System.Threading;
using System.Threading.Tasks;
using ZTalk.Client.Config;
using ZTalk.Shared.DTOs;
using ZTalk.Shared.Protocol;

namespace ZTalk.Client.Services
{
    /// <summary>
    /// Smart client connectivity pipeline supporting:
    /// 1. Dual-Endpoint failover (fast LAN probe -> automatic WAN EdgeRelay TLS 443 fallback).
    /// 2. Automatic reconnect with exponential backoff + jitter and transparent re-authentication.
    /// </summary>
    public sealed class ConnectionPipeline : IDisposable
    {
        private readonly TcpClientService _tcpService;
        private readonly ClientSecurityConfig _config;
        private readonly object _sync = new object();

        private string _primaryHostOverride;
        private int? _primaryPortOverride;
        private string _sessionUsername;
        private string _sessionPasswordHash;
        private CancellationTokenSource _reconnectCts;
        private volatile bool _autoReconnectEnabled;
        private int _reconnectingFlag;
        private bool _disposed;

        public TcpClientService TcpService => _tcpService;
        public ClientSecurityConfig Config => _config;
        public string ActiveHost { get; private set; }
        public int ActivePort { get; private set; }
        public bool IsUsingFallback { get; private set; }
        public string ActiveEndpointLabel { get; private set; } = "Disconnected";
        public bool IsAutoReconnectEnabled => _autoReconnectEnabled;

        public event Action<int, int> OnReconnecting;   // attempt, delayMs
        public event Action<string> OnReconnected;      // activeEndpointLabel
        public event Action<string> OnReconnectFailed;  // fatal reason (e.g. auth rejected)

        public ConnectionPipeline(TcpClientService tcpService, ClientSecurityConfig config = null)
        {
            _tcpService = tcpService ?? throw new ArgumentNullException(nameof(tcpService));
            _config = config ?? new ClientSecurityConfig();
        }

        /// <summary>
        /// Attempt primary (LAN) endpoint first with fast timeout when fallback exists;
        /// automatically fail over to external WAN Edge endpoint if unreachable.
        /// </summary>
        public async Task<bool> ConnectSmartAsync(string primaryHost = null, int? primaryPort = null)
        {
            string host1 = !string.IsNullOrWhiteSpace(primaryHost) ? primaryHost.Trim() : _config.ServerHost;
            int port1 = primaryPort ?? _config.ServerPort;

            _primaryHostOverride = host1;
            _primaryPortOverride = port1;

            bool hasFallback = !string.IsNullOrWhiteSpace(_config.FallbackServerHost)
                && _config.FallbackServerPort > 0
                && (!string.Equals(host1, _config.FallbackServerHost, StringComparison.OrdinalIgnoreCase)
                    || port1 != _config.FallbackServerPort);

            int primaryTimeout = hasFallback
                ? Math.Max(400, _config.LanConnectTimeoutMs)
                : Math.Max(500, _config.ConnectTimeoutMs);

            // 1. Try Primary / LAN endpoint
            if (!string.IsNullOrWhiteSpace(host1) && port1 > 0)
            {
                bool ok = await _tcpService.ConnectAsync(
                    host1,
                    port1,
                    _config.UseTls,
                    _config.PinnedCertSha256,
                    _config.AllowSelfSignedCert,
                    _config.TlsTargetHost,
                    primaryTimeout).ConfigureAwait(false);

                if (ok)
                {
                    SetActiveEndpoint(host1, port1, isFallback: false);
                    return true;
                }
            }

            // 2. Fall back to External WAN / EdgeRelay endpoint
            if (hasFallback)
            {
                bool okFallback = await _tcpService.ConnectAsync(
                    _config.FallbackServerHost.Trim(),
                    _config.FallbackServerPort,
                    _config.UseTls,
                    _config.PinnedCertSha256,
                    _config.AllowSelfSignedCert,
                    string.IsNullOrWhiteSpace(_config.TlsTargetHost) ? _config.FallbackServerHost.Trim() : _config.TlsTargetHost,
                    Math.Max(1000, _config.ConnectTimeoutMs)).ConfigureAwait(false);

                if (okFallback)
                {
                    SetActiveEndpoint(_config.FallbackServerHost.Trim(), _config.FallbackServerPort, isFallback: true);
                    return true;
                }
            }

            ActiveEndpointLabel = "Disconnected";
            return false;
        }

        /// <summary>
        /// Store authenticated credentials in memory so unexpected drops can seamlessly re-authenticate.
        /// </summary>
        public void SetSessionCredentials(string username, string passwordHash)
        {
            lock (_sync)
            {
                _sessionUsername = username;
                _sessionPasswordHash = passwordHash;
            }
        }

        public void EnableAutoReconnect()
        {
            if (_disposed || !_config.AutoReconnect) return;

            lock (_sync)
            {
                if (_autoReconnectEnabled) return;
                _autoReconnectEnabled = true;
                _tcpService.OnDisconnected += HandleUnexpectedDisconnect;
            }
        }

        public void DisableAutoReconnect()
        {
            CancellationTokenSource ctsToCancel;
            lock (_sync)
            {
                _autoReconnectEnabled = false;
                _tcpService.OnDisconnected -= HandleUnexpectedDisconnect;
                ctsToCancel = _reconnectCts;
                _reconnectCts = null;
            }

            if (ctsToCancel != null)
            {
                try { ctsToCancel.Cancel(); } catch { }
                try { ctsToCancel.Dispose(); } catch { }
            }
        }

        private void HandleUnexpectedDisconnect()
        {
            if (!_autoReconnectEnabled || _disposed) return;

            // Single-flight guard: only one reconnect loop at a time
            if (Interlocked.CompareExchange(ref _reconnectingFlag, 1, 0) != 0)
                return;

            CancellationToken ct;
            lock (_sync)
            {
                if (!_autoReconnectEnabled || _disposed)
                {
                    Interlocked.Exchange(ref _reconnectingFlag, 0);
                    return;
                }
                _reconnectCts?.Dispose();
                _reconnectCts = new CancellationTokenSource();
                ct = _reconnectCts.Token;
            }

            Task.Run(() => ReconnectLoopAsync(ct));
        }

        private async Task ReconnectLoopAsync(CancellationToken ct)
        {
            int baseDelayMs = Math.Max(200, _config.ReconnectInitialDelayMs);
            int maxDelayMs = Math.Max(baseDelayMs, _config.ReconnectMaxDelayMs);
            int currentDelayMs = baseDelayMs;
            int attempt = 0;
            var jitterRng = new Random();

            try
            {
                while (!ct.IsCancellationRequested && _autoReconnectEnabled && !_disposed)
                {
                    attempt++;
                    int jitter = jitterRng.Next(-(currentDelayMs / 5), (currentDelayMs / 5) + 1);
                    int waitMs = Math.Max(200, currentDelayMs + jitter);

                    OnReconnecting?.Invoke(attempt, waitMs);

                    try { await Task.Delay(waitMs, ct).ConfigureAwait(false); }
                    catch (OperationCanceledException) { break; }

                    if (ct.IsCancellationRequested || !_autoReconnectEnabled)
                        break;

                    bool connected = await ConnectSmartAsync(_primaryHostOverride, _primaryPortOverride).ConfigureAwait(false);
                    if (!connected)
                    {
                        currentDelayMs = Math.Min(maxDelayMs, currentDelayMs * 2);
                        continue;
                    }

                    // Re-authenticate transparently if session credentials exist
                    string user, passHash;
                    lock (_sync)
                    {
                        user = _sessionUsername;
                        passHash = _sessionPasswordHash;
                    }

                    if (!string.IsNullOrEmpty(user) && !string.IsNullOrEmpty(passHash))
                    {
                        var authResult = await ReauthenticateAsync(user, passHash, ct).ConfigureAwait(false);
                        if (!authResult.Completed)
                        {
                            // Network dropped during auth -> retry with backoff
                            _tcpService.Disconnect();
                            currentDelayMs = Math.Min(maxDelayMs, currentDelayMs * 2);
                            continue;
                        }

                        if (!authResult.Success)
                        {
                            // Credentials rejected (revoked/locked) -> stop auto-reconnect
                            _tcpService.Disconnect();
                            DisableAutoReconnect();
                            OnReconnectFailed?.Invoke(authResult.Message ?? "Re-authentication failed");
                            return;
                        }
                    }

                    OnReconnected?.Invoke(ActiveEndpointLabel);
                    return;
                }
            }
            finally
            {
                Interlocked.Exchange(ref _reconnectingFlag, 0);
            }
        }

        private async Task<ReauthResult> ReauthenticateAsync(string username, string passwordHash, CancellationToken ct)
        {
            var tcs = new TaskCompletionSource<Packet>(TaskCreationOptions.RunContinuationsAsynchronously);
            Action<Packet> handler = null;
            handler = p =>
            {
                if (p.Type == PacketType.LoginResponse)
                {
                    _tcpService.OnPacketReceived -= handler;
                    tcs.TrySetResult(p);
                }
            };

            _tcpService.OnPacketReceived += handler;
            try
            {
                var req = new LoginRequestDTO { Username = username, PasswordHash = passwordHash };
                _tcpService.SendPacket(new Packet(PacketType.Login, null, null, PacketSerializer.ToJson(req)));

                using (var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct))
                {
                    var delayTask = Task.Delay(5000, timeoutCts.Token);
                    var completed = await Task.WhenAny(tcs.Task, delayTask).ConfigureAwait(false);
                    if (completed == delayTask)
                        return new ReauthResult { Completed = false };

                    timeoutCts.Cancel();
                }

                var responsePacket = await tcs.Task.ConfigureAwait(false);
                var dto = PacketSerializer.FromJson<LoginResponseDTO>(responsePacket?.Data);
                return new ReauthResult
                {
                    Completed = true,
                    Success = dto != null && dto.Success,
                    Message = dto?.Message
                };
            }
            catch
            {
                return new ReauthResult { Completed = false };
            }
            finally
            {
                _tcpService.OnPacketReceived -= handler;
            }
        }

        private void SetActiveEndpoint(string host, int port, bool isFallback)
        {
            ActiveHost = host;
            ActivePort = port;
            IsUsingFallback = isFallback;
            string route = isFallback ? "WAN Edge" : "LAN Direct";
            string sec = _config.UseTls ? "TLS 1.2" : "TCP";
            ActiveEndpointLabel = $"{route} ({host}:{port} • {sec})";
        }

        public void Dispose()
        {
            _disposed = true;
            DisableAutoReconnect();
        }

        private struct ReauthResult
        {
            public bool Completed;
            public bool Success;
            public string Message;
        }
    }
}
