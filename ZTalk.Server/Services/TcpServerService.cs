using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using ZTalk.Server.Data;
using ZTalk.Server.Models;
using ZTalk.Shared.Constants;
using ZTalk.Shared.DTOs;
using ZTalk.Shared.Protocol;

namespace ZTalk.Server.Services
{
    /// <summary>
    /// TCP Server xử lý nhiều client đồng thời.
    /// Mỗi client kết nối → chạy async I/O (IOCP) qua NetworkStream.ReadAsync.
    /// </summary>
    public class TcpServerService : ITcpServerService, IDisposable
    {
        private const int PreAuthMaxPacketSize = 65536;

        private TcpListener _listener;
        private CancellationTokenSource _cts;
        private readonly object _lifecycleLock = new object();
        private readonly ConcurrentDictionary<string, ConnectedClient> _clients;
        private readonly AuthService _authService;
        private readonly MessageRouter _messageRouter;
        private readonly MessageStore _messageStore;
        private int _connectionCounter;
        private int _totalMessagesRouted;
        private volatile bool _isRunning;

        public bool IsRunning => _isRunning;
        public int ConnectedCount => _clients.Count;
        public int TotalMessagesRouted => Volatile.Read(ref _totalMessagesRouted);
        public DateTime? StartTime { get; private set; }

        public event Action<string> OnLog;
        public event Action OnClientListChanged;

        public List<ConnectedClient> GetClientsSnapshot()
        {
            return new List<ConnectedClient>(_clients.Values);
        }

        public TcpServerService(UserStore userStore)
        {
            _clients = new ConcurrentDictionary<string, ConnectedClient>();
            _authService = new AuthService(userStore);
            _messageRouter = new MessageRouter(_clients, msg => OnLog?.Invoke(msg));
            _messageStore = new MessageStore();
        }

        /// <summary>
        /// Khởi động server trên port chỉ định
        /// </summary>
        public void Start(int port)
        {
            lock (_lifecycleLock)
            {
                if (_isRunning) return;

                _cts?.Dispose();
                _cts = new CancellationTokenSource();
                _listener = new TcpListener(IPAddress.Any, port);
                _listener.Start();
                _isRunning = true;
                StartTime = DateTime.Now;
                Interlocked.Exchange(ref _totalMessagesRouted, 0);

                Log($"Server started on port {port}");

                var ct = _cts.Token;
                Task.Run(() => AcceptClientsAsync(ct));
            }
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

                // Disconnect all clients
                foreach (var kvp in _clients)
                {
                    CloseClientQuietly(kvp.Value);
                }
                _clients.Clear();

                try
                {
                    _listener?.Stop();
                }
                catch { }
            }

            ctsToDispose?.Dispose();

            Log("Server stopped");
            OnClientListChanged?.Invoke();
        }

        /// <summary>
        /// Asynchronously accept new clients
        /// </summary>
        private async Task AcceptClientsAsync(CancellationToken ct)
        {
            while (!ct.IsCancellationRequested)
            {
                try
                {
                    var tcpClient = await _listener.AcceptTcpClientAsync().ConfigureAwait(false);
                    tcpClient.NoDelay = true;

                    var connectionId = "conn_" + Interlocked.Increment(ref _connectionCounter);

                    var client = new ConnectedClient
                    {
                        TcpClient = tcpClient,
                        Stream = tcpClient.GetStream(),
                        UserId = connectionId
                    };
                    client.CacheEndPoint();

                    _clients.TryAdd(connectionId, client);
                    Log($"[CONNECT] New client connected: {client.EndPoint} (ID: {connectionId})");
                    OnClientListChanged?.Invoke();

                    // Handle client asynchronously using IOCP reads
                    var _ = Task.Run(() => HandleClientAsync(connectionId, client, ct));
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
        /// Xử lý 1 client: đọc packet bất đồng bộ và route
        /// </summary>
        private async Task HandleClientAsync(string connectionId, ConnectedClient client, CancellationToken ct)
        {
            try
            {
                while (!ct.IsCancellationRequested && client.TcpClient != null && client.TcpClient.Connected)
                {
                    int maxSize = client.IsAuthenticated ? AppConstants.MaxPacketSize : PreAuthMaxPacketSize;
                    var packet = await PacketSerializer.ReceivePacketAsync(client.Stream, ct, maxSize).ConfigureAwait(false);
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
                // Remove by active key (UserId after login, connectionId before login)
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
                    // Only forward & persist authenticated messages
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
                    // Forward only (không lưu store)
                    HandleForward(client, packet);
                    break;

                case PacketType.ChatHistoryRequest:
                    HandleChatHistoryRequest(client, packet);
                    break;

                case PacketType.Heartbeat:
                    // Reply with online user list only to requesting client (avoids O(N²) broadcast storm)
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
        /// Xử lý đăng nhập
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
            var response = _authService.Authenticate(request);

            if (response.Success)
            {
                // Remove temporary connection key
                ConnectedClient removed;
                _clients.TryRemove(connectionId, out removed);

                // Replace any stale session for the same UserId cleanly
                ConnectedClient existingSession;
                if (_clients.TryRemove(response.UserId, out existingSession) && !ReferenceEquals(existingSession, client))
                {
                    Log($"[LOGIN] Replacing existing session for '{request.Username}' (ID: {response.UserId})");
                    CloseClientQuietly(existingSession);
                }

                client.UserId = response.UserId;
                client.Username = request.Username;
                client.DisplayName = response.DisplayName;
                client.IsAuthenticated = true;

                _clients[response.UserId] = client;

                Log($"[LOGIN] User '{request.Username}' authenticated successfully (ID: {response.UserId})");
            }
            else
            {
                Log($"[LOGIN FAILED] {request.Username}: {response.Message}");
            }

            // Send response back to client (thread-safe)
            var responseData = PacketSerializer.ToJson(response);
            var responsePacket = new Packet(PacketType.LoginResponse, "server", connectionId, responseData);
            client.SendPacket(responsePacket);

            if (response.Success)
            {
                // Brief delay to allow client to open frmChat and subscribe to events
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
        /// Handle registration
        /// </summary>
        private void HandleRegister(string connectionId, ConnectedClient client, Packet packet)
        {
            var request = PacketSerializer.FromJson<LoginRequestDTO>(packet.Data) ?? new LoginRequestDTO();
            var response = _authService.Register(request);
            var responseData = PacketSerializer.ToJson(response);

            var responsePacket = new Packet(PacketType.RegisterResponse, "server", connectionId, responseData);
            client.SendPacket(responsePacket);

            Log($"[REGISTER] {request.Username}: {response.Message}");
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

            // Always overwrite SenderId with authenticated UserId to prevent spoofing
            packet.SenderId = sender.UserId;

            if (string.IsNullOrEmpty(packet.ReceiverId))
            {
                // Broadcast
                _messageRouter.Broadcast(packet, sender.UserId);
            }
            else
            {
                // Point-to-point
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
                // Ensure a closing replaced session does not kick the newly logged-in session
                if (!_clients.TryGetValue(connectionId, out client) || !ReferenceEquals(client, expectedClient))
                {
                    CloseClientQuietly(expectedClient);
                    return;
                }
            }

            if (_clients.TryRemove(connectionId, out client))
            {
                CloseClientQuietly(client);

                Log($"[DISCONNECT] Client disconnected: {client.DisplayName ?? client.Username ?? connectionId}");

                if (client.IsAuthenticated)
                {
                    _messageRouter.BroadcastUserList();
                }

                OnClientListChanged?.Invoke();
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
        }
    }
}
