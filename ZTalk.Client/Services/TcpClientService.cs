using System;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using ZTalk.Shared.Protocol;

namespace ZTalk.Client.Services
{
    /// <summary>
    /// Quản lý TCP connection đến server.
    /// Nhận packet bằng async IOCP, gửi packet thread-safe.
    /// </summary>
    public class TcpClientService : ITcpClientService, IDisposable
    {
        private TcpClient _client;
        private NetworkStream _stream;
        private CancellationTokenSource _cts;
        private readonly object _sendLock = new object();
        private int _connectedFlag;

        public bool IsConnected => Volatile.Read(ref _connectedFlag) == 1;

        public event Action<Packet> OnPacketReceived;
        public event Action OnDisconnected;

        /// <summary>
        /// Kết nối đến server
        /// </summary>
        public async Task<bool> ConnectAsync(string host, int port)
        {
            // Clean up any previous connection before reconnecting
            CloseConnectionQuietly();

            try
            {
                var client = new TcpClient { NoDelay = true };
                await client.ConnectAsync(host, port).ConfigureAwait(false);
                var stream = client.GetStream();

                _client = client;
                _stream = stream;
                _cts = new CancellationTokenSource();
                Interlocked.Exchange(ref _connectedFlag, 1);

                var ct = _cts.Token;
                var _ = Task.Run(() => ReceiveLoopAsync(stream, ct));

                return true;
            }
            catch
            {
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
        /// Vòng lặp nhận packet bất đồng bộ từ server (không spawn Task.Run cho từng packet)
        /// </summary>
        private async Task ReceiveLoopAsync(NetworkStream stream, CancellationToken ct)
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
