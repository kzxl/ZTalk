using System;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using ZTalk.Shared.Network;

namespace ZTalk.Client.Services
{
    /// <summary>
    /// Quản lý kết nối UDP P2P cho video call.
    /// Thực hiện hole punching và streaming video frames.
    /// </summary>
    public class UdpPeerService : IDisposable
    {
        private static readonly byte[] PingPayload = Encoding.UTF8.GetBytes("CHATBOX_PING");
        private static readonly byte[] PongPayload = Encoding.UTF8.GetBytes("CHATBOX_PONG");

        private UdpClient _udpClient;
        private CancellationTokenSource _cts;
        private volatile IPEndPoint _peerEndPoint;
        private volatile bool _isConnected;
        private readonly object _lock = new object();

        /// <summary>Local UDP port đang lắng nghe</summary>
        public int LocalPort { get; private set; }

        /// <summary>Public endpoint (từ STUN)</summary>
        public IPEndPoint PublicEndPoint { get; private set; }

        /// <summary>Local endpoint</summary>
        public IPEndPoint LocalEndPoint { get; private set; }

        /// <summary>Đã kết nối P2P thành công chưa</summary>
        public bool IsConnected => _isConnected;

        /// <summary>Event nhận data từ peer</summary>
        public event Action<byte[]> OnDataReceived;

        /// <summary>Event khi P2P connection thành công</summary>
        public event Action OnConnected;

        /// <summary>
        /// Khởi tạo UDP socket và discover endpoints
        /// </summary>
        public void Initialize()
        {
            _udpClient = new UdpClient(0); // Random available port
            LocalPort = ((IPEndPoint)_udpClient.Client.LocalEndPoint).Port;

            // Discover local IP
            var localIp = StunClient.GetLocalIPAddress();
            LocalEndPoint = new IPEndPoint(localIp, LocalPort);

            // Discover public endpoint qua STUN (dùng cùng socket)
            PublicEndPoint = StunClient.GetPublicEndPoint(_udpClient);
        }

        /// <summary>
        /// Thực hiện UDP hole punching đến peer.
        /// Thử cả public và local endpoint, timeout 5 giây.
        /// </summary>
        public async Task<bool> HolePunchAsync(
            string peerPublicIp, int peerPublicPort,
            string peerLocalIp, int peerLocalPort)
        {
            if (_udpClient == null) return false;

            ReplaceCts();
            var ct = _cts.Token;
            _isConnected = false;

            // Safely parse peer endpoints
            IPEndPoint publicEp = TryParseEndPoint(peerPublicIp, peerPublicPort);
            IPEndPoint localEp = TryParseEndPoint(peerLocalIp, peerLocalPort);

            // Start listening for pings
            var listenTask = Task.Run(() => ListenForPing(ct));

            int attempts = 0;
            while (!_isConnected && !ct.IsCancellationRequested && attempts < 25) // 25 x 200ms = 5 seconds
            {
                try
                {
                    if (publicEp != null)
                        _udpClient.Send(PingPayload, PingPayload.Length, publicEp);

                    if (localEp != null)
                        _udpClient.Send(PingPayload, PingPayload.Length, localEp);
                }
                catch { }

                try { await Task.Delay(200, ct).ConfigureAwait(false); }
                catch (OperationCanceledException) { break; }

                attempts++;
            }

            if (!_isConnected)
            {
                try { _cts?.Cancel(); } catch { }
            }

            // Ensure ListenForPing exits before caller invokes StartReceiving()
            try { await listenTask.ConfigureAwait(false); } catch { }

            return _isConnected;
        }

        private static IPEndPoint TryParseEndPoint(string ip, int port)
        {
            IPAddress parsed;
            if (!string.IsNullOrEmpty(ip) && port > 0 && port <= 65535 && IPAddress.TryParse(ip, out parsed))
            {
                return new IPEndPoint(parsed, port);
            }
            return null;
        }

        /// <summary>
        /// Lắng nghe ping từ peer, trả lời pong, thiết lập connection
        /// </summary>
        private void ListenForPing(CancellationToken ct)
        {
            try
            {
                _udpClient.Client.ReceiveTimeout = 500;
            }
            catch { return; }

            var remoteEp = new IPEndPoint(IPAddress.Any, 0);

            while (!ct.IsCancellationRequested && !_isConnected)
            {
                try
                {
                    var data = _udpClient.Receive(ref remoteEp);
                    var message = Encoding.UTF8.GetString(data);

                    if (message == "CHATBOX_PING" || message == "CHATBOX_PONG")
                    {
                        _peerEndPoint = remoteEp;
                        _isConnected = true;

                        // Reply pong
                        if (message == "CHATBOX_PING")
                        {
                            _udpClient.Send(PongPayload, PongPayload.Length, remoteEp);
                        }

                        OnConnected?.Invoke();
                        break;
                    }
                }
                catch (SocketException)
                {
                    // Timeout, try again
                }
                catch
                {
                    break;
                }
            }
        }

        /// <summary>
        /// Bắt đầu nhận data từ peer (sau khi P2P connected)
        /// </summary>
        public void StartReceiving()
        {
            if (!_isConnected || _udpClient == null) return;

            ReplaceCts();
            var ct = _cts.Token;
            Task.Run(() => ReceiveLoop(ct));
        }

        private void ReceiveLoop(CancellationToken ct)
        {
            try
            {
                _udpClient.Client.ReceiveTimeout = 5000;
            }
            catch { return; }

            var remoteEp = new IPEndPoint(IPAddress.Any, 0);

            while (!ct.IsCancellationRequested && _isConnected)
            {
                try
                {
                    var data = _udpClient.Receive(ref remoteEp);
                    if (data.Length > 0)
                    {
                        OnDataReceived?.Invoke(data);
                    }
                }
                catch (SocketException ex)
                {
                    if (ex.SocketErrorCode == SocketError.TimedOut)
                        continue;
                    break;
                }
                catch
                {
                    break;
                }
            }
        }

        /// <summary>
        /// Gửi data đến peer qua UDP
        /// </summary>
        public void SendData(byte[] data)
        {
            var peerEp = _peerEndPoint;
            var client = _udpClient;
            if (!_isConnected || peerEp == null || client == null || data == null || data.Length == 0 || data.Length > 65507)
                return;

            lock (_lock)
            {
                try
                {
                    client.Send(data, data.Length, peerEp);
                }
                catch { }
            }
        }

        private void ReplaceCts()
        {
            var old = Interlocked.Exchange(ref _cts, new CancellationTokenSource());
            if (old != null)
            {
                try { old.Cancel(); } catch { }
                try { old.Dispose(); } catch { }
            }
        }

        /// <summary>
        /// Dừng kết nối
        /// </summary>
        public void Stop()
        {
            _isConnected = false;
            var old = Interlocked.Exchange(ref _cts, null);
            if (old != null)
            {
                try { old.Cancel(); } catch { }
                try { old.Dispose(); } catch { }
            }
        }

        public void Dispose()
        {
            Stop();
            var client = Interlocked.Exchange(ref _udpClient, null);
            try { client?.Close(); } catch { }
        }
    }
}
