using System;
using System.Collections.Concurrent;
using System.IO;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;

namespace ZTalk.Shared.Network
{
    /// <summary>
    /// Zero-Trust Public Edge Relay server designed to run on a public VPS (e.g. port 443 + control 8443).
    /// Bridges external clients over a TLS 1.2 reverse tunnel back to ZTalk.Server inside the company LAN
    /// without terminating client-to-server TLS (VPS never sees decrypted chat or credentials).
    /// </summary>
    public sealed class EdgeRelayServer : IDisposable
    {
        private readonly int _publicPort;
        private readonly int _controlPort;
        private readonly string _sharedSecret;
        private readonly X509Certificate2 _controlCert;
        private readonly bool _ownsCert;
        private readonly int _sessionBindTimeoutMs;
        private readonly int _maxPendingSessions;
        private readonly int _maxActiveBridges;

        private readonly object _lifecycleLock = new object();
        private readonly SemaphoreSlim _controlWriteLock = new SemaphoreSlim(1, 1);
        private readonly ConcurrentDictionary<Guid, PendingSession> _pendingSessions
            = new ConcurrentDictionary<Guid, PendingSession>();

        private TcpListener _publicListener;
        private TcpListener _controlListener;
        private CancellationTokenSource _cts;
        private volatile bool _isRunning;
        private Stream _activeControlStream;
        private TcpClient _activeControlTcp;
        private int _activeBridgeCount;

        public bool IsRunning => _isRunning;
        public bool IsAgentConnected => Volatile.Read(ref _activeControlStream) != null;
        public int ActiveBridgeCount => Volatile.Read(ref _activeBridgeCount);
        public string ControlCertThumbprint { get; }

        public event Action<string> OnLog;

        public EdgeRelayServer(
            int publicPort,
            int controlPort,
            string sharedSecret,
            X509Certificate2 controlTlsCert,
            bool ownsCert = false,
            int sessionBindTimeoutMs = 10000,
            int maxPendingSessions = 100,
            int maxActiveBridges = 300)
        {
            if (string.IsNullOrWhiteSpace(sharedSecret))
                throw new ArgumentException("Edge relay shared secret is required.", nameof(sharedSecret));
            if (controlTlsCert == null)
                throw new ArgumentNullException(nameof(controlTlsCert));

            _publicPort = publicPort;
            _controlPort = controlPort;
            _sharedSecret = sharedSecret;
            _controlCert = controlTlsCert;
            _ownsCert = ownsCert;
            _sessionBindTimeoutMs = Math.Max(1000, sessionBindTimeoutMs);
            _maxPendingSessions = Math.Max(10, maxPendingSessions);
            _maxActiveBridges = Math.Max(10, maxActiveBridges);
            ControlCertThumbprint = TlsHelper.GetCertSha256Thumbprint(controlTlsCert);
        }

        public void Start()
        {
            lock (_lifecycleLock)
            {
                if (_isRunning) return;

                _cts?.Dispose();
                _cts = new CancellationTokenSource();

                _controlListener = new TcpListener(IPAddress.Any, _controlPort);
                _controlListener.Start();

                _publicListener = new TcpListener(IPAddress.Any, _publicPort);
                _publicListener.Start();

                _isRunning = true;
                var ct = _cts.Token;

                Log($"EdgeRelay started | PublicPort: {_publicPort} | ControlPort (TLS): {_controlPort} | ControlPin: {ControlCertThumbprint}");

                Task.Run(() => AcceptControlLoopAsync(ct));
                Task.Run(() => AcceptPublicLoopAsync(ct));
            }
        }

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
                try { _publicListener?.Stop(); } catch { }
                try { _controlListener?.Stop(); } catch { }

                CloseControlChannel();

                foreach (var kvp in _pendingSessions)
                {
                    kvp.Value.Tcs.TrySetCanceled();
                }
                _pendingSessions.Clear();
            }

            ctsToDispose?.Dispose();
            Log("EdgeRelay stopped");
        }

        private async Task AcceptControlLoopAsync(CancellationToken ct)
        {
            while (!ct.IsCancellationRequested)
            {
                try
                {
                    var tcp = await _controlListener.AcceptTcpClientAsync().ConfigureAwait(false);
                    tcp.NoDelay = true;
                    var handleTask = Task.Run(() => HandleControlOrDataConnectionAsync(tcp, ct));
                }
                catch (ObjectDisposedException)
                {
                    break;
                }
                catch (Exception ex)
                {
                    if (!ct.IsCancellationRequested)
                        Log($"[CONTROL] Accept error: {ex.Message}");
                }
            }
        }

        private async Task HandleControlOrDataConnectionAsync(TcpClient tcp, CancellationToken ct)
        {
            SslStream sslStream = null;
            bool ownershipTransferred = false;
            string remote = SafeEndPoint(tcp);

            try
            {
                sslStream = await TlsHelper.AuthenticateAsServerAsync(tcp.GetStream(), _controlCert, ct, 5000).ConfigureAwait(false);

                // Send 32B CSPRNG challenge nonce
                byte[] nonce = ReverseTunnelProtocol.GenerateNonce();
                var challengeFrame = new byte[1 + ReverseTunnelProtocol.NonceLength];
                challengeFrame[0] = ReverseTunnelProtocol.OpChallenge;
                Buffer.BlockCopy(nonce, 0, challengeFrame, 1, ReverseTunnelProtocol.NonceLength);

                await sslStream.WriteAsync(challengeFrame, 0, challengeFrame.Length, ct).ConfigureAwait(false);
                await sslStream.FlushAsync(ct).ConfigureAwait(false);

                // Read 1-byte opcode with 5s auth timeout
                var opBuf = new byte[1];
                using (var authCts = CancellationTokenSource.CreateLinkedTokenSource(ct))
                {
                    authCts.CancelAfter(5000);
                    if (!await ReverseTunnelProtocol.ReadExactAsync(sslStream, opBuf, 1, authCts.Token).ConfigureAwait(false))
                        return;

                    if (opBuf[0] == ReverseTunnelProtocol.OpControlAuth)
                    {
                        var providedHmac = new byte[ReverseTunnelProtocol.HmacLength];
                        if (!await ReverseTunnelProtocol.ReadExactAsync(sslStream, providedHmac, providedHmac.Length, authCts.Token).ConfigureAwait(false))
                            return;

                        if (!ReverseTunnelProtocol.VerifyControlHmac(_sharedSecret, nonce, providedHmac))
                        {
                            Log($"[SECURITY] Rejected control agent from {remote}: invalid HMAC");
                            return;
                        }

                        await sslStream.WriteAsync(new[] { ReverseTunnelProtocol.OpControlAuthOk }, 0, 1, authCts.Token).ConfigureAwait(false);
                        await sslStream.FlushAsync(authCts.Token).ConfigureAwait(false);

                        // Activate this control channel (replaces any stale agent)
                        ReplaceControlChannel(tcp, sslStream);
                        ownershipTransferred = true;
                        Log($"[CONTROL] Authenticated LAN agent connected from {remote}");

                        await RunControlChannelLoopAsync(tcp, sslStream, ct).ConfigureAwait(false);
                    }
                    else if (opBuf[0] == ReverseTunnelProtocol.OpDataBind)
                    {
                        var bindPayload = new byte[ReverseTunnelProtocol.SessionIdLength + ReverseTunnelProtocol.HmacLength];
                        if (!await ReverseTunnelProtocol.ReadExactAsync(sslStream, bindPayload, bindPayload.Length, authCts.Token).ConfigureAwait(false))
                            return;

                        var sessionIdBytes = new byte[ReverseTunnelProtocol.SessionIdLength];
                        var providedHmac = new byte[ReverseTunnelProtocol.HmacLength];
                        Buffer.BlockCopy(bindPayload, 0, sessionIdBytes, 0, ReverseTunnelProtocol.SessionIdLength);
                        Buffer.BlockCopy(bindPayload, ReverseTunnelProtocol.SessionIdLength, providedHmac, 0, ReverseTunnelProtocol.HmacLength);

                        if (!ReverseTunnelProtocol.VerifyDataHmac(_sharedSecret, sessionIdBytes, nonce, providedHmac))
                        {
                            Log($"[SECURITY] Rejected data tunnel bind from {remote}: invalid HMAC");
                            return;
                        }

                        var sessionId = new Guid(sessionIdBytes);
                        PendingSession pending;
                        if (!_pendingSessions.TryRemove(sessionId, out pending))
                        {
                            Log($"[TUNNEL] Late or unknown session bind {sessionId:N} from {remote}");
                            return;
                        }

                        await sslStream.WriteAsync(new[] { ReverseTunnelProtocol.OpDataBindOk }, 0, 1, authCts.Token).ConfigureAwait(false);
                        await sslStream.FlushAsync(authCts.Token).ConfigureAwait(false);

                        if (pending.Tcs.TrySetResult(new BoundTunnel(tcp, sslStream)))
                        {
                            ownershipTransferred = true;
                        }
                    }
                    else
                    {
                        Log($"[SECURITY] Unknown control opcode 0x{opBuf[0]:X2} from {remote}");
                    }
                }
            }
            catch (OperationCanceledException) { }
            catch (Exception ex)
            {
                if (!ct.IsCancellationRequested)
                    Log($"[CONTROL] Connection error ({remote}): {ex.Message}");
            }
            finally
            {
                if (!ownershipTransferred)
                {
                    try { sslStream?.Dispose(); } catch { }
                    try { tcp.Close(); } catch { }
                }
            }
        }

        private async Task RunControlChannelLoopAsync(TcpClient tcp, Stream controlStream, CancellationToken ct)
        {
            var opBuf = new byte[1];
            try
            {
                using (var pingCts = CancellationTokenSource.CreateLinkedTokenSource(ct))
                {
                    var pingTask = SendControlPingsAsync(controlStream, pingCts.Token);

                    while (!ct.IsCancellationRequested && ReferenceEquals(Volatile.Read(ref _activeControlStream), controlStream))
                    {
                        if (!await ReverseTunnelProtocol.ReadExactAsync(controlStream, opBuf, 1, ct).ConfigureAwait(false))
                            break;

                        if (opBuf[0] == ReverseTunnelProtocol.OpPing)
                        {
                            await SendControlFrameAsync(controlStream, new[] { ReverseTunnelProtocol.OpPong }, ct).ConfigureAwait(false);
                        }
                    }

                    pingCts.Cancel();
                    try { await pingTask.ConfigureAwait(false); } catch { }
                }
            }
            catch { }
            finally
            {
                if (ReferenceEquals(Interlocked.CompareExchange(ref _activeControlStream, null, controlStream), controlStream))
                {
                    Interlocked.CompareExchange(ref _activeControlTcp, null, tcp);
                    Log("[CONTROL] LAN agent disconnected");
                }
                try { controlStream.Dispose(); } catch { }
                try { tcp.Close(); } catch { }
            }
        }

        private async Task SendControlPingsAsync(Stream controlStream, CancellationToken ct)
        {
            var ping = new[] { ReverseTunnelProtocol.OpPing };
            while (!ct.IsCancellationRequested && ReferenceEquals(Volatile.Read(ref _activeControlStream), controlStream))
            {
                try
                {
                    await Task.Delay(15000, ct).ConfigureAwait(false);
                    await SendControlFrameAsync(controlStream, ping, ct).ConfigureAwait(false);
                }
                catch
                {
                    break;
                }
            }
        }

        private async Task AcceptPublicLoopAsync(CancellationToken ct)
        {
            while (!ct.IsCancellationRequested)
            {
                try
                {
                    var externalClient = await _publicListener.AcceptTcpClientAsync().ConfigureAwait(false);
                    externalClient.NoDelay = true;
                    var handleTask = Task.Run(() => HandleExternalClientAsync(externalClient, ct));
                }
                catch (ObjectDisposedException)
                {
                    break;
                }
                catch (Exception ex)
                {
                    if (!ct.IsCancellationRequested)
                        Log($"[PUBLIC] Accept error: {ex.Message}");
                }
            }
        }

        private async Task HandleExternalClientAsync(TcpClient externalClient, CancellationToken ct)
        {
            string remote = SafeEndPoint(externalClient);
            var controlStream = Volatile.Read(ref _activeControlStream);

            if (controlStream == null)
            {
                Log($"[PUBLIC] Rejected {remote}: no LAN tunnel agent connected");
                try { externalClient.Close(); } catch { }
                return;
            }

            if (_pendingSessions.Count >= _maxPendingSessions || ActiveBridgeCount >= _maxActiveBridges)
            {
                Log($"[PUBLIC] Rejected {remote}: relay capacity reached");
                try { externalClient.Close(); } catch { }
                return;
            }

            var sessionId = Guid.NewGuid();
            var pending = new PendingSession();
            _pendingSessions[sessionId] = pending;

            BoundTunnel boundTunnel = null;
            try
            {
                // Request LAN agent to open a reverse data tunnel for this sessionId
                var openFrame = new byte[1 + ReverseTunnelProtocol.SessionIdLength];
                openFrame[0] = ReverseTunnelProtocol.OpOpenSession;
                Buffer.BlockCopy(sessionId.ToByteArray(), 0, openFrame, 1, ReverseTunnelProtocol.SessionIdLength);

                await SendControlFrameAsync(controlStream, openFrame, ct).ConfigureAwait(false);

                // Wait for LAN agent to open and authenticate the data tunnel
                using (var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct))
                {
                    var delayTask = Task.Delay(_sessionBindTimeoutMs, timeoutCts.Token);
                    var completed = await Task.WhenAny(pending.Tcs.Task, delayTask).ConfigureAwait(false);
                    if (completed == delayTask)
                    {
                        PendingSession removed;
                        _pendingSessions.TryRemove(sessionId, out removed);
                        Log($"[PUBLIC] Timeout waiting for LAN agent data tunnel ({remote})");
                        return;
                    }
                    timeoutCts.Cancel();
                }

                boundTunnel = await pending.Tcs.Task.ConfigureAwait(false);
                Interlocked.Increment(ref _activeBridgeCount);
                try
                {
                    using (var externalStream = externalClient.GetStream())
                    {
                        await ReverseTunnelProtocol.BridgeBidirectionalAsync(externalStream, boundTunnel.Stream, ct).ConfigureAwait(false);
                    }
                }
                finally
                {
                    Interlocked.Decrement(ref _activeBridgeCount);
                }
            }
            catch (OperationCanceledException) { }
            catch (Exception ex)
            {
                if (!ct.IsCancellationRequested)
                    Log($"[PUBLIC] Bridge error ({remote}): {ex.Message}");
            }
            finally
            {
                PendingSession removed;
                _pendingSessions.TryRemove(sessionId, out removed);
                boundTunnel?.Dispose();
                try { externalClient.Close(); } catch { }
            }
        }

        private async Task SendControlFrameAsync(Stream controlStream, byte[] frame, CancellationToken ct)
        {
            await _controlWriteLock.WaitAsync(ct).ConfigureAwait(false);
            try
            {
                await controlStream.WriteAsync(frame, 0, frame.Length, ct).ConfigureAwait(false);
                await controlStream.FlushAsync(ct).ConfigureAwait(false);
            }
            finally
            {
                _controlWriteLock.Release();
            }
        }

        private void ReplaceControlChannel(TcpClient newTcp, Stream newStream)
        {
            var oldStream = Interlocked.Exchange(ref _activeControlStream, newStream);
            var oldTcp = Interlocked.Exchange(ref _activeControlTcp, newTcp);
            try { oldStream?.Dispose(); } catch { }
            try { oldTcp?.Close(); } catch { }
        }

        private void CloseControlChannel()
        {
            var oldStream = Interlocked.Exchange(ref _activeControlStream, null);
            var oldTcp = Interlocked.Exchange(ref _activeControlTcp, null);
            try { oldStream?.Dispose(); } catch { }
            try { oldTcp?.Close(); } catch { }
        }

        private static string SafeEndPoint(TcpClient tcp)
        {
            try { return tcp?.Client?.RemoteEndPoint?.ToString() ?? "unknown"; }
            catch { return "unknown"; }
        }

        private void Log(string message)
        {
            OnLog?.Invoke($"[{DateTime.Now:HH:mm:ss}] [EdgeRelay] {message}");
        }

        public void Dispose()
        {
            Stop();
            _controlWriteLock.Dispose();
            if (_ownsCert)
                _controlCert?.Dispose();
        }

        private sealed class PendingSession
        {
            public readonly TaskCompletionSource<BoundTunnel> Tcs
                = new TaskCompletionSource<BoundTunnel>(TaskCreationOptions.RunContinuationsAsynchronously);
        }

        private sealed class BoundTunnel : IDisposable
        {
            public readonly TcpClient Tcp;
            public readonly Stream Stream;

            public BoundTunnel(TcpClient tcp, Stream stream)
            {
                Tcp = tcp;
                Stream = stream;
            }

            public void Dispose()
            {
                try { Stream?.Dispose(); } catch { }
                try { Tcp?.Close(); } catch { }
            }
        }
    }
}
