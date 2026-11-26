using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using ZTalk.Server.Config;
using ZTalk.Server.Data;
using ZTalk.Server.Models;
using ZTalk.Shared.Constants;
using ZTalk.Shared.DTOs;
using ZTalk.Shared.Network;
using ZTalk.Shared.Protocol;

namespace ZTalk.Server.Services
{
    /// <summary>
    /// Enterprise TCP/TLS 1.2 Server xử lý nhiều client đồng thời qua IOCP.
    /// Hỗ trợ TLS SslStream, giới hạn kết nối/IP, pre-auth timeout, brute-force rate limiting và Audit Log.
    /// </summary>
    public class TcpServerService : ITcpServerService, IDisposable
    {
        private const int PreAuthMaxPacketSize = 65536;

        private TcpListener _listener;
        private CancellationTokenSource _cts;
        private readonly object _lifecycleLock = new object();
        private readonly ConcurrentDictionary<string, ConnectedClient> _clients;
        private readonly ConcurrentDictionary<string, int> _connectionsByIp;
        private readonly AuthService _authService;
        private readonly MessageRouter _messageRouter;
        private readonly MessageStore _messageStore;
        private readonly ServerSecurityConfig _config;
        private readonly AuthRateLimiter _rateLimiter;
        private readonly AuditLogger _auditLogger;
        private X509Certificate2 _tlsCertificate;
        private bool _ownsTlsCertificate;
        private int _connectionCounter;
        private int _totalMessagesRouted;
        private volatile bool _isRunning;

        public bool IsRunning => _isRunning;
        public int ConnectedCount => _clients.Count;
        public int TotalMessagesRouted => Volatile.Read(ref _totalMessagesRouted);
        public DateTime? StartTime { get; private set; }
        public bool IsTlsEnabled => _config.EnableTls && _tlsCertificate != null;
        public string ActiveTlsThumbprint { get; private set; }
        public ServerSecurityConfig SecurityConfig => _config;

        public event Action<string> OnLog;
        public event Action OnClientListChanged;

        public List<ConnectedClient> GetClientsSnapshot()
        {
            return new List<ConnectedClient>(_clients.Values);
        }

        public TcpServerService(UserStore userStore, ServerSecurityConfig config = null, X509Certificate2 tlsCertificate = null)
        {
            _config = config ?? new ServerSecurityConfig();
            _clients = new ConcurrentDictionary<string, ConnectedClient>();
            _connectionsByIp = new ConcurrentDictionary<string, int>(StringComparer.OrdinalIgnoreCase);
            _authService = new AuthService(userStore);
            _messageRouter = new MessageRouter(_clients, msg => OnLog?.Invoke(msg));
            _messageStore = new MessageStore();
            _rateLimiter = new AuthRateLimiter(_config.MaxFailedLoginAttempts, _config.LockoutMinutes);
            _auditLogger = new AuditLogger(_config.ResolveAuditLogDirectory());
            _tlsCertificate = tlsCertificate;
            _ownsTlsCertificate = false;
        }

        /// <summary>
        /// Khởi động server trên port chỉ định (tự nạp hoặc sinh chứng chỉ TLS nếu EnableTls = true)
        /// </summary>
        public void Start(int port)
        {
            lock (_lifecycleLock)
            {
                if (_isRunning) return;

                EnsureTlsCertificate();

                _cts?.Dispose();
                _cts = new CancellationTokenSource();
                _listener = new TcpListener(IPAddress.Any, port);
                _listener.Start();
                _isRunning = true;
                StartTime = DateTime.Now;
                Interlocked.Exchange(ref _totalMessagesRouted, 0);

                string mode = IsTlsEnabled
                    ? $"TLS 1.2 (SHA-256 Pin: {ActiveTlsThumbprint})"
                    : "Plain TCP (DEV/LAN)";
                Log($"Server started on port {port} | Mode: {mode} | PublicRegister: {_config.AllowPublicRegistration}");
                _auditLogger.Write("SERVER_START", $"port={port} tls={IsTlsEnabled} publicRegister={_config.AllowPublicRegistration} maxConn={_config.MaxConnections}");

                var ct = _cts.Token;
                Task.Run(() => AcceptClientsAsync(ct));
            }
        }

        private void EnsureTlsCertificate()
        {
            if (!_config.EnableTls)
            {
                ActiveTlsThumbprint = null;
                return;
            }

            if (_tlsCertificate == null)
            {
                string certPath = _config.ResolveCertPath();
                if (File.Exists(certPath))
                {
                    _tlsCertificate = TlsHelper.LoadCertificate(certPath, _config.TlsCertPassword);
                    _ownsTlsCertificate = true;
                }
                else if (_config.AutoGenerateSelfSignedCert)
                {
                    _tlsCertificate = TlsHelper.GenerateAndSaveSelfSignedPfx(
                        certPath,
                        _config.TlsCertPassword,
                        _config.TlsSubjectCn);
                    _ownsTlsCertificate = true;
                    Log($"[TLS] Generated self-signed certificate at {certPath}");
                }
                else
                {
                    throw new FileNotFoundException($"TLS enabled but certificate not found: {certPath}", certPath);
                }
            }

            ActiveTlsThumbprint = TlsHelper.GetCertSha256Thumbprint(_tlsCertificate);
        }

        /// <summary>
        /// Stop server and disconnect all clients
        /// </summary>
        public void Stop()
        {
            CancellationTokenSource ctsToDispose = null;
            lock (_lifecycleLock)
            {
                if (!_isRunning) return;

                _isRunning = false;
                ctsToDispose = _cts;
                _cts = null;

                try { ctsToDispose?.Cancel(); } catch { }

                foreach (var kvp in _clients)
                {
                    CloseClientQuietly(kvp.Value);
                }
                _clients.Clear();
                _connectionsByIp.Clear();

                try
                {
                    _listener?.Stop();
                }
                catch { }
            }

            ctsToDispose?.Dispose();

            Log("Server stopped");
            _auditLogger.Write("SERVER_STOP", "Server stopped cleanly");
            OnClientListChanged?.Invoke();
        }

        /// <summary>
        /// Asynchronously accept new clients with global & per-IP connection caps
        /// </summary>
        private async Task AcceptClientsAsync(CancellationToken ct)
        {
            while (!ct.IsCancellationRequested)
            {
                try
                {
                    var tcpClient = await _listener.AcceptTcpClientAsync().ConfigureAwait(false);
                    tcpClient.NoDelay = true;

                    var client = new ConnectedClient { TcpClient = tcpClient };
                    client.CacheEndPoint();
                    string remoteIp = client.RemoteIp ?? "unknown";

                    // Enforce global connection cap
                    if (_clients.Count >= _config.MaxConnections)
                    {
                        Log($"[SECURITY] Rejected connection from {client.EndPoint}: MaxConnections ({_config.MaxConnections}) reached");
                        _auditLogger.Write("CONN_LIMIT_REJECT", $"ip={remoteIp} reason=max_global");
                        CloseClientQuietly(client);
                        continue;
                    }

                    // Enforce per-IP connection cap
                    int ipCount = _connectionsByIp.AddOrUpdate(remoteIp, 1, (ipKey, count) => count + 1);
                    if (ipCount > _config.MaxConnectionsPerIp)
                    {
                        DecrementIpCount(remoteIp);
                        Log($"[SECURITY] Rejected connection from {client.EndPoint}: MaxConnectionsPerIp ({_config.MaxConnectionsPerIp}) exceeded");
                        _auditLogger.Write("CONN_LIMIT_REJECT", $"ip={remoteIp} reason=max_per_ip");
                        CloseClientQuietly(client);
                        continue;
                    }

                    var connectionId = "conn_" + Interlocked.Increment(ref _connectionCounter);
                    client.UserId = connectionId;
                    _clients.TryAdd(connectionId, client);

                    Log($"[CONNECT] New client connected: {client.EndPoint} (ID: {connectionId})");
                    OnClientListChanged?.Invoke();

                    var handleTask = Task.Run(() => HandleClientAsync(connectionId, client, ct));
                }
                catch (ObjectDisposedException)
                {
                    break; // Server stopped
                }
                catch (Exception ex)
                {
                    if (!ct.IsCancellationRequested)
                        Log($"[ERROR] Accept failed: {ex.Message}");
                }
            }
        }

        /// <summary>
        /// Xử lý 1 client: TLS handshake (nếu bật) + pre-auth timeout + vòng đọc IOCP
        /// </summary>
        private async Task HandleClientAsync(string connectionId, ConnectedClient client, CancellationToken ct)
        {
            try
            {
                NetworkStream rawStream = client.TcpClient.GetStream();

                if (IsTlsEnabled)
                {
                    try
                    {
                        client.Stream = await TlsHelper.AuthenticateAsServerAsync(
                            rawStream,
                            _tlsCertificate,
                            ct,
                            _config.TlsHandshakeTimeoutMs).ConfigureAwait(false);
                        client.IsTls = true;
                    }
                    catch (Exception tlsEx)
                    {
                        Log($"[TLS FAIL] {client.EndPoint}: {tlsEx.Message}");
                        _auditLogger.Write("TLS_HANDSHAKE_FAIL", $"endpoint={client.EndPoint} error={tlsEx.Message}");
                        return;
                    }
                }
                else
                {
                    client.Stream = rawStream;
                    client.IsTls = false;
                }

                DateTime authDeadlineUtc = DateTime.UtcNow.AddSeconds(Math.Max(1, _config.AuthTimeoutSeconds));

                while (!ct.IsCancellationRequested && client.TcpClient != null && client.TcpClient.Connected)
                {
                    Packet packet;
                    if (!client.IsAuthenticated)
                    {
                        int remainingMs = (int)(authDeadlineUtc - DateTime.UtcNow).TotalMilliseconds;
                        if (remainingMs <= 0)
                        {
                            Log($"[SECURITY] Auth timeout for {client.EndPoint} ({connectionId})");
                            _auditLogger.Write("AUTH_TIMEOUT", $"endpoint={client.EndPoint} conn={connectionId}");
                            break;
                        }

                        using (var authTimeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct))
                        {
                            authTimeoutCts.CancelAfter(remainingMs);
                            try
                            {
                                packet = await PacketSerializer.ReceivePacketAsync(
                                    client.Stream,
                                    authTimeoutCts.Token,
                                    PreAuthMaxPacketSize).ConfigureAwait(false);
                            }
                            catch (OperationCanceledException) when (!ct.IsCancellationRequested)
                            {
                                Log($"[SECURITY] Auth timeout for {client.EndPoint} ({connectionId})");
                                _auditLogger.Write("AUTH_TIMEOUT", $"endpoint={client.EndPoint} conn={connectionId}");
                                break;
                            }
                        }
                    }
                    else
                    {
                        packet = await PacketSerializer.ReceivePacketAsync(
                            client.Stream,
                            ct,
                            AppConstants.MaxPacketSize).ConfigureAwait(false);
                    }

                    if (packet == null)
                        break; // Client disconnected or invalid packet

                    if (!ProcessPacket(connectionId, client, packet, ct))
                        break; // Client requested disconnect
                }
            }
            catch (OperationCanceledException)
            {
                // Server shutting down
            }
            catch (Exception ex)
            {
                if (!ct.IsCancellationRequested)
                    Log($"[ERROR] Client {client.UserId ?? connectionId}: {ex.Message}");
            }
            finally
            {
                DisconnectClient(client.UserId ?? connectionId, client);
            }
        }

        /// <summary>
        /// Xử lý packet nhận được từ client. Trả về false nếu cần đóng kết nối.
        /// </summary>
        private bool ProcessPacket(string connectionId, ConnectedClient client, Packet packet, CancellationToken ct)
        {
            client.IncrementPacketsReceived();
            Interlocked.Increment(ref _totalMessagesRouted);

            switch (packet.Type)
            {
                case PacketType.Login:
                    HandleLogin(connectionId, client, packet, ct);
                    break;

                case PacketType.Register:
                    HandleRegister(connectionId, client, packet);
                    break;

                case PacketType.Message:
                case PacketType.GroupMessage:
                    if (HandleForward(client, packet))
                    {
                        SaveMessageToStore(client, packet);
                    }
                    break;

                case PacketType.TypingIndicator:
                case PacketType.FileHeader:
                case PacketType.FileChunk:
                case PacketType.FileComplete:
                case PacketType.KeyExchange:
                case PacketType.KeyExchangeResponse:
                case PacketType.VideoCallRequest:
                case PacketType.VideoCallAccept:
                case PacketType.VideoCallReject:
                case PacketType.VideoCallEnd:
                case PacketType.VideoFrame:
                case PacketType.AudioFrame:
                    HandleForward(client, packet);
                    break;

                case PacketType.ChatHistoryRequest:
                    HandleChatHistoryRequest(client, packet);
                    break;

                case PacketType.Heartbeat:
                    if (client.IsAuthenticated)
                    {
                        _messageRouter.SendUserListToClient(client);
                    }
                    break;

                case PacketType.Disconnect:
                    DisconnectClient(client.UserId ?? connectionId, client);
                    return false;

                default:
                    Log($"[WARN] Unknown packet type: {packet.Type} from {client.UserId ?? connectionId}");
                    break;
            }

            return true;
        }

        /// <summary>
        /// Xử lý đăng nhập với rate limiter chống brute-force và audit logging
        /// </summary>
        private void HandleLogin(string connectionId, ConnectedClient client, Packet packet, CancellationToken ct)
        {
            if (client.IsAuthenticated)
            {
                var alreadyLoggedIn = new LoginResponseDTO
                {
                    Success = false,
                    Message = "Client is already authenticated"
                };
                client.SendPacket(new Packet(PacketType.LoginResponse, "server", client.UserId, PacketSerializer.ToJson(alreadyLoggedIn)));
                return;
            }

            var request = PacketSerializer.FromJson<LoginRequestDTO>(packet.Data) ?? new LoginRequestDTO();
            string remoteIp = client.RemoteIp ?? "unknown";

            // Rate-limit / lockout check
            TimeSpan remainingLockout;
            if (_rateLimiter.IsLockedOut(request.Username, remoteIp, out remainingLockout))
            {
                int waitSeconds = Math.Max(1, (int)Math.Ceiling(remainingLockout.TotalSeconds));
                var lockedResponse = new LoginResponseDTO
                {
                    Success = false,
                    Message = $"Tài khoản hoặc IP tạm khóa do đăng nhập sai nhiều lần. Thử lại sau {waitSeconds}s."
                };
                client.SendPacket(new Packet(PacketType.LoginResponse, "server", connectionId, PacketSerializer.ToJson(lockedResponse)));
                Log($"[SECURITY] Blocked locked login attempt for '{request.Username}' from {remoteIp}");
                _auditLogger.Write("LOGIN_LOCKED", $"user={request.Username} ip={remoteIp} waitSeconds={waitSeconds}");
                return;
            }

            var response = _authService.Authenticate(request);

            if (response.Success)
            {
                _rateLimiter.RecordSuccess(request.Username, remoteIp);

                ConnectedClient removed;
                _clients.TryRemove(connectionId, out removed);

                ConnectedClient existingSession;
                if (_clients.TryRemove(response.UserId, out existingSession) && !ReferenceEquals(existingSession, client))
                {
                    Log($"[LOGIN] Replacing existing session for '{request.Username}' (ID: {response.UserId})");
                    DecrementIpCount(existingSession.RemoteIp);
                    CloseClientQuietly(existingSession);
                }

                client.UserId = response.UserId;
                client.Username = request.Username;
                client.DisplayName = response.DisplayName;
                client.IsAuthenticated = true;

                _clients[response.UserId] = client;

                Log($"[LOGIN] User '{request.Username}' authenticated successfully (ID: {response.UserId}, TLS: {client.IsTls})");
                _auditLogger.Write("LOGIN_OK", $"user={request.Username} userId={response.UserId} ip={remoteIp} tls={client.IsTls}");
            }
            else
            {
                _rateLimiter.RecordFailure(request.Username, remoteIp);
                Log($"[LOGIN FAILED] {request.Username} ({remoteIp}): {response.Message}");
                _auditLogger.Write("LOGIN_FAIL", $"user={request.Username} ip={remoteIp} reason={response.Message}");
            }

            var responseData = PacketSerializer.ToJson(response);
            var responsePacket = new Packet(PacketType.LoginResponse, "server", connectionId, responseData);
            client.SendPacket(responsePacket);

            if (response.Success)
            {
                Task.Run(async () =>
                {
                    try
                    {
                        await Task.Delay(500, ct).ConfigureAwait(false);
                        if (!ct.IsCancellationRequested)
                            _messageRouter.BroadcastUserList();
                    }
                    catch (OperationCanceledException) { }
                });
                OnClientListChanged?.Invoke();
            }
        }

        /// <summary>
        /// Handle registration (gated by ServerSecurityConfig.AllowPublicRegistration)
        /// </summary>
        private void HandleRegister(string connectionId, ConnectedClient client, Packet packet)
        {
            var request = PacketSerializer.FromJson<LoginRequestDTO>(packet.Data) ?? new LoginRequestDTO();
            string remoteIp = client.RemoteIp ?? "unknown";

            LoginResponseDTO response;
            if (!_config.AllowPublicRegistration)
            {
                response = new LoginResponseDTO
                {
                    Success = false,
                    Message = "Đăng ký tự do đã bị tắt. Vui lòng liên hệ quản trị viên để được cấp tài khoản."
                };
                Log($"[SECURITY] Blocked public registration attempt for '{request.Username}' from {remoteIp}");
                _auditLogger.Write("REGISTER_BLOCKED", $"user={request.Username} ip={remoteIp}");
            }
            else
            {
                response = _authService.Register(request);
                Log($"[REGISTER] {request.Username}: {response.Message}");
                _auditLogger.Write(response.Success ? "REGISTER_OK" : "REGISTER_FAIL", $"user={request.Username} ip={remoteIp}");
            }

            var responseData = PacketSerializer.ToJson(response);
            var responsePacket = new Packet(PacketType.RegisterResponse, "server", connectionId, responseData);
            client.SendPacket(responsePacket);
        }

        /// <summary>
        /// Forward packet from sender to receiver
        /// </summary>
        private bool HandleForward(ConnectedClient sender, Packet packet)
        {
            if (!sender.IsAuthenticated)
            {
                Log($"[WARN] Unauthenticated client tried to send {packet.Type}");
                return false;
            }

            packet.SenderId = sender.UserId;

            if (string.IsNullOrEmpty(packet.ReceiverId))
            {
                _messageRouter.Broadcast(packet, sender.UserId);
            }
            else
            {
                _messageRouter.SendToClient(packet.ReceiverId, packet);
            }

            return true;
        }

        /// <summary>
        /// Disconnect client (public for admin Kick support)
        /// </summary>
        public void DisconnectClient(string connectionId)
        {
            DisconnectClient(connectionId, null);
        }

        private void DisconnectClient(string connectionId, ConnectedClient expectedClient)
        {
            if (string.IsNullOrEmpty(connectionId)) return;

            ConnectedClient client;
            if (expectedClient != null)
            {
                if (!_clients.TryGetValue(connectionId, out client) || !ReferenceEquals(client, expectedClient))
                {
                    CloseClientQuietly(expectedClient);
                    return;
                }
            }

            if (_clients.TryRemove(connectionId, out client))
            {
                DecrementIpCount(client.RemoteIp);
                CloseClientQuietly(client);

                Log($"[DISCONNECT] Client disconnected: {client.DisplayName ?? client.Username ?? connectionId}");
                _auditLogger.Write("DISCONNECT", $"userId={client.UserId} ip={client.RemoteIp}");

                if (client.IsAuthenticated)
                {
                    _messageRouter.BroadcastUserList();
                }

                OnClientListChanged?.Invoke();
            }
        }

        private void DecrementIpCount(string remoteIp)
        {
            if (string.IsNullOrEmpty(remoteIp)) return;

            int newCount = _connectionsByIp.AddOrUpdate(remoteIp, 0, (_, count) => Math.Max(0, count - 1));
            if (newCount == 0)
            {
                int ignored;
                _connectionsByIp.TryRemove(remoteIp, out ignored);
            }
        }

        private static void CloseClientQuietly(ConnectedClient client)
        {
            if (client == null) return;
            try { client.Stream?.Close(); } catch { }
            try { client.TcpClient?.Close(); } catch { }
        }

        private void Log(string message)
        {
            OnLog?.Invoke($"[{DateTime.Now:HH:mm:ss}] {message}");
        }

        /// <summary>
        /// Save authenticated message to store
        /// </summary>
        private void SaveMessageToStore(ConnectedClient sender, Packet packet)
        {
            if (!sender.IsAuthenticated) return;

            if (packet.Type == PacketType.Message || packet.Type == PacketType.GroupMessage)
            {
                var msg = PacketSerializer.FromJson<MessageDTO>(packet.Data);
                string content = msg?.Content;
                if (string.IsNullOrEmpty(content)) return;

                string receiverId = packet.Type == PacketType.GroupMessage ? "__group__" : packet.ReceiverId;
                _messageStore.SaveMessage(sender.UserId, receiverId, sender.DisplayName ?? sender.UserId, content, false);
            }
        }

        /// <summary>
        /// Handle history request
        /// </summary>
        private void HandleChatHistoryRequest(ConnectedClient client, Packet packet)
        {
            if (!client.IsAuthenticated) return;

            string partnerId = packet.ReceiverId ?? "__group__";
            int maxCount = 50;

            var history = _messageStore.GetHistory(client.UserId, partnerId, maxCount);
            var historyPayload = new Dictionary<string, object>
            {
                { "PartnerId", partnerId },
                { "Messages", history }
            };

            var response = new Packet(PacketType.ChatHistoryResponse, "SERVER", client.UserId, PacketSerializer.ToJson(historyPayload));
            client.SendPacket(response);
            Log($"Sent {history.Count} history messages to {client.DisplayName} (partner: {partnerId})");
        }

        public void Dispose()
        {
            Stop();
            if (_ownsTlsCertificate && _tlsCertificate != null)
            {
                _tlsCertificate.Dispose();
                _tlsCertificate = null;
            }
            _auditLogger?.Dispose();
        }
    }
}
