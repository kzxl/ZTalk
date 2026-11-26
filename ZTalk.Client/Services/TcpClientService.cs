using System;
using System.IO;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using ZTalk.Shared.Network;
using ZTalk.Shared.Protocol;

namespace ZTalk.Client.Services
{
    /// <summary>
    /// Quản lý TCP/TLS 1.2 connection đến server.
    /// Nhận packet bằng async IOCP, gửi packet thread-safe, hỗ trợ SHA-256 certificate pinning.
    /// </summary>
    public class TcpClientService : ITcpClientService, IDisposable
    {
        private TcpClient _client;
        private Stream _stream;
        private CancellationTokenSource _cts;
        private readonly object _sendLock = new object();
        private int _connectedFlag;

        public bool IsConnected => Volatile.Read(ref _connectedFlag) == 1;
        public bool IsTlsActive { get; private set; }

        public event Action<Packet> OnPacketReceived;
        public event Action OnDisconnected;

        /// <summary>
        /// Kết nối TCP chuẩn đến server (tương thích ngược ITcpClientService)
        /// </summary>
        public Task<bool> ConnectAsync(string host, int port)
        {
            return ConnectAsync(host, port, useTls: false);
        }

        /// <summary>
        /// Kết nối đến server với tùy chọn TLS 1.2 + SHA-256 certificate pinning + connect timeout
        /// </summary>
        public async Task<bool> ConnectAsync(
            string host,
            int port,
            bool useTls,
            string pinnedCertSha256 = null,
            bool allowSelfSigned = false,
            string tlsTargetHost = null,
            int connectTimeoutMs = 5000)
        {
            // Clean up any previous connection before reconnecting
            CloseConnectionQuietly();

            TcpClient client = null;
            Stream activeStream = null;
            try
            {
                client = new TcpClient { NoDelay = true };

                var connectTask = client.ConnectAsync(host, port);
                var delayTask = Task.Delay(Math.Max(500, connectTimeoutMs));
                if (await Task.WhenAny(connectTask, delayTask).ConfigureAwait(false) == delayTask)
                {
                    try { client.Close(); } catch { }
                    return false;
                }
                await connectTask.ConfigureAwait(false);

                NetworkStream rawStream = client.GetStream();
                if (useTls)
                {
                    string target = string.IsNullOrWhiteSpace(tlsTargetHost) ? host : tlsTargetHost;
                    activeStream = await TlsHelper.AuthenticateAsClientAsync(
                        rawStream,
                        target,
                        pinnedCertSha256,
                        allowSelfSigned,
                        CancellationToken.None,
                        Math.Max(1000, connectTimeoutMs)).ConfigureAwait(false);
                }
                else
                {
                    activeStream = rawStream;
                }

                _client = client;
                _stream = activeStream;
                IsTlsActive = useTls;
                _cts = new CancellationTokenSource();
                Interlocked.Exchange(ref _connectedFlag, 1);

                var ct = _cts.Token;
                var _ = Task.Run(() => ReceiveLoopAsync(activeStream, ct));

                return true;
            }
            catch
            {
                try { activeStream?.Dispose(); } catch { }
                try { client?.Close(); } catch { }
                CloseConnectionQuietly();
                return false;
            }
        }

        /// <summary>
        /// Ngắt kết nối
        /// </summary>
        public void Disconnect()
        {
            Interlocked.Exchange(ref _connectedFlag, 0);
            CloseConnectionQuietly();
        }

        /// <summary>
        /// Gửi packet (thread-safe)
        /// </summary>
        public void SendPacket(Packet packet)
        {
            if (!IsConnected || packet == null) return;

            bool disconnectedNow = false;
            lock (_sendLock)
            {
                var stream = _stream;
                if (!IsConnected || stream == null) return;

                try
                {
                    PacketSerializer.SendPacket(stream, packet);
                }
                catch
                {
                    disconnectedNow = Interlocked.Exchange(ref _connectedFlag, 0) == 1;
                }
            }

            if (disconnectedNow)
            {
                CloseConnectionQuietly();
                OnDisconnected?.Invoke();
            }
        }

        /// <summary>
        /// Vòng lặp nhận packet bất đồng bộ từ server (hỗ trợ cả NetworkStream và SslStream)
        /// </summary>
        private async Task ReceiveLoopAsync(Stream stream, CancellationToken ct)
        {
            try
            {
                while (!ct.IsCancellationRequested && IsConnected)
                {
                    var packet = await PacketSerializer.ReceivePacketAsync(stream, ct).ConfigureAwait(false);
                    if (packet == null)
                        break;

                    OnPacketReceived?.Invoke(packet);
                }
            }
            catch (OperationCanceledException)
            {
                // Clean disconnect
            }
            catch
            {
                // Connection lost
            }
            finally
            {
                if (Interlocked.Exchange(ref _connectedFlag, 0) == 1)
                {
                    CloseConnectionQuietly();
                    OnDisconnected?.Invoke();
                }
            }
        }

        private void CloseConnectionQuietly()
        {
            IsTlsActive = false;

            var cts = Interlocked.Exchange(ref _cts, null);
            if (cts != null)
            {
                try { cts.Cancel(); } catch { }
                try { cts.Dispose(); } catch { }
            }

            var stream = Interlocked.Exchange(ref _stream, null);
            try { stream?.Close(); } catch { }

            var client = Interlocked.Exchange(ref _client, null);
            try { client?.Close(); } catch { }
        }

        public void Dispose()
        {
            Disconnect();
        }
    }
}
