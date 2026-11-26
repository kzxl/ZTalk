using System;
using System.IO;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace ZTalk.Shared.Network
{
    /// <summary>
    /// Outbound Zero-Trust Reverse Tunnel agent running inside the company LAN alongside ZTalk.Server.
    /// Maintains a persistent TLS 1.2 control channel to EdgeRelayServer (zero inbound firewall ports required)
    /// and bridges each external client directly into local ZTalk.Server preserving end-to-end TLS.
    /// </summary>
    public sealed class ReverseTunnelAgent : IDisposable
    {
        private readonly string _relayHost;
        private readonly int _relayControlPort;
        private readonly string _sharedSecret;
        private readonly string _localTargetHost;
        private readonly int _localTargetPort;
        private readonly string _relayCertPinSha256;
        private readonly bool _allowSelfSignedRelayCert;
        private readonly string _relayTlsTargetHost;

        private readonly object _lifecycleLock = new object();
        private CancellationTokenSource _cts;
        private volatile bool _isRunning;
        private volatile bool _isControlConnected;
        private int _activeTunnelCount;

        public bool IsRunning => _isRunning;
        public bool IsControlConnected => _isControlConnected;
        public int ActiveTunnelCount => Volatile.Read(ref _activeTunnelCount);

        public event Action<string> OnLog;
        public event Action<bool> OnControlStateChanged;

        public ReverseTunnelAgent(
            string relayHost,
            int relayControlPort,
            string sharedSecret,
            string localTargetHost,
            int localTargetPort,
            string relayCertPinSha256 = null,
            bool allowSelfSignedRelayCert = false,
            string relayTlsTargetHost = null)
        {
            if (string.IsNullOrWhiteSpace(relayHost))
                throw new ArgumentException("Edge relay host is required.", nameof(relayHost));
            if (string.IsNullOrWhiteSpace(sharedSecret))
                throw new ArgumentException("Tunnel shared secret is required.", nameof(sharedSecret));

            _relayHost = relayHost;
            _relayControlPort = relayControlPort;
            _sharedSecret = sharedSecret;
            _localTargetHost = string.IsNullOrWhiteSpace(localTargetHost) ? "127.0.0.1" : localTargetHost;
            _localTargetPort = localTargetPort;
            _relayCertPinSha256 = relayCertPinSha256;
            _allowSelfSignedRelayCert = allowSelfSignedRelayCert;
            _relayTlsTargetHost = string.IsNullOrWhiteSpace(relayTlsTargetHost) ? relayHost : relayTlsTargetHost;
        }

        public void Start()
        {
            lock (_lifecycleLock)
            {
                if (_isRunning) return;

                _cts?.Dispose();
                _cts = new CancellationTokenSource();
                _isRunning = true;

                var ct = _cts.Token;
                Log($"Starting outbound reverse tunnel -> {_relayHost}:{_relayControlPort} (local target {_localTargetHost}:{_localTargetPort})");
                Task.Run(() => ControlSupervisorLoopAsync(ct));
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
            }

            ctsToDispose?.Dispose();
            SetControlConnected(false);
            Log("Reverse tunnel agent stopped");
        }

        private async Task ControlSupervisorLoopAsync(CancellationToken ct)
        {
            int backoffMs = 1000;
            const int maxBackoffMs = 30000;

            while (!ct.IsCancellationRequested && _isRunning)
            {
                TcpClient controlTcp = null;
                Stream controlStream = null;
                try
                {
                    controlTcp = new TcpClient { NoDelay = true };
                    await ConnectWithTimeoutAsync(controlTcp, _relayHost, _relayControlPort, 5000, ct).ConfigureAwait(false);

                    controlStream = await TlsHelper.AuthenticateAsClientAsync(
                        controlTcp.GetStream(),
                        _relayTlsTargetHost,
                        _relayCertPinSha256,
                        _allowSelfSignedRelayCert,
                        ct,
                        5000).ConfigureAwait(false);

                    // 1. Read challenge [0x01][32B nonce]
                    var challengeFrame = new byte[1 + ReverseTunnelProtocol.NonceLength];
                    if (!await ReverseTunnelProtocol.ReadExactAsync(controlStream, challengeFrame, challengeFrame.Length, ct).ConfigureAwait(false)
                        || challengeFrame[0] != ReverseTunnelProtocol.OpChallenge)
                    {
                        throw new IOException("Invalid tunnel challenge from EdgeRelay.");
                    }

                    var nonce = new byte[ReverseTunnelProtocol.NonceLength];
                    Buffer.BlockCopy(challengeFrame, 1, nonce, 0, ReverseTunnelProtocol.NonceLength);

                    // 2. Send [0x02][32B HMAC]
                    byte[] hmac = ReverseTunnelProtocol.ComputeControlHmac(_sharedSecret, nonce);
                    var authFrame = new byte[1 + ReverseTunnelProtocol.HmacLength];
                    authFrame[0] = ReverseTunnelProtocol.OpControlAuth;
                    Buffer.BlockCopy(hmac, 0, authFrame, 1, ReverseTunnelProtocol.HmacLength);

                    await controlStream.WriteAsync(authFrame, 0, authFrame.Length, ct).ConfigureAwait(false);
                    await controlStream.FlushAsync(ct).ConfigureAwait(false);

                    // 3. Expect [0x03] OK
                    var ack = new byte[1];
                    if (!await ReverseTunnelProtocol.ReadExactAsync(controlStream, ack, 1, ct).ConfigureAwait(false)
                        || ack[0] != ReverseTunnelProtocol.OpControlAuthOk)
                    {
                        throw new UnauthorizedAccessException("EdgeRelay rejected control tunnel authentication.");
                    }

                    backoffMs = 1000;
                    SetControlConnected(true);
                    Log($"Control channel established with EdgeRelay {_relayHost}:{_relayControlPort}");

                    // 4. Listen for session open requests and keepalive pings
                    var opBuf = new byte[1];
                    var sessionIdBuf = new byte[ReverseTunnelProtocol.SessionIdLength];
                    var pong = new[] { ReverseTunnelProtocol.OpPong };

                    while (!ct.IsCancellationRequested && _isRunning)
                    {
                        if (!await ReverseTunnelProtocol.ReadExactAsync(controlStream, opBuf, 1, ct).ConfigureAwait(false))
                            break;

                        if (opBuf[0] == ReverseTunnelProtocol.OpOpenSession)
                        {
                            if (!await ReverseTunnelProtocol.ReadExactAsync(controlStream, sessionIdBuf, sessionIdBuf.Length, ct).ConfigureAwait(false))
                                break;

                            var sessionCopy = new byte[ReverseTunnelProtocol.SessionIdLength];
                            Buffer.BlockCopy(sessionIdBuf, 0, sessionCopy, 0, sessionCopy.Length);
                            var dataTask = Task.Run(() => OpenDataTunnelAndBridgeAsync(sessionCopy, ct));
                        }
                        else if (opBuf[0] == ReverseTunnelProtocol.OpPing)
                        {
                            await controlStream.WriteAsync(pong, 0, 1, ct).ConfigureAwait(false);
                            await controlStream.FlushAsync(ct).ConfigureAwait(false);
                        }
                    }
                }
                catch (OperationCanceledException)
                {
                    break;
                }
                catch (Exception ex)
                {
                    if (!ct.IsCancellationRequested)
                        Log($"Control channel error: {ex.Message}. Reconnecting in {backoffMs}ms...");
                }
                finally
                {
                    SetControlConnected(false);
                    try { controlStream?.Dispose(); } catch { }
                    try { controlTcp?.Close(); } catch { }
                }

                if (!ct.IsCancellationRequested && _isRunning)
                {
                    try { await Task.Delay(backoffMs, ct).ConfigureAwait(false); }
                    catch (OperationCanceledException) { break; }
                    backoffMs = Math.Min(maxBackoffMs, backoffMs * 2);
                }
            }
        }

        private async Task OpenDataTunnelAndBridgeAsync(byte[] sessionId, CancellationToken ct)
        {
            TcpClient relayTcp = null;
            Stream relayStream = null;
            TcpClient localTcp = null;

            try
            {
                // 1. Connect to local ZTalk.Server inside LAN
                localTcp = new TcpClient { NoDelay = true };
                await ConnectWithTimeoutAsync(localTcp, _localTargetHost, _localTargetPort, 5000, ct).ConfigureAwait(false);

                // 2. Open outbound TLS 1.2 data tunnel to EdgeRelay
                relayTcp = new TcpClient { NoDelay = true };
                await ConnectWithTimeoutAsync(relayTcp, _relayHost, _relayControlPort, 5000, ct).ConfigureAwait(false);

                relayStream = await TlsHelper.AuthenticateAsClientAsync(
                    relayTcp.GetStream(),
                    _relayTlsTargetHost,
                    _relayCertPinSha256,
                    _allowSelfSignedRelayCert,
                    ct,
                    5000).ConfigureAwait(false);

                // 3. Read challenge [0x01][32B nonce]
                var challengeFrame = new byte[1 + ReverseTunnelProtocol.NonceLength];
                if (!await ReverseTunnelProtocol.ReadExactAsync(relayStream, challengeFrame, challengeFrame.Length, ct).ConfigureAwait(false)
                    || challengeFrame[0] != ReverseTunnelProtocol.OpChallenge)
                {
                    return;
                }

                var nonce = new byte[ReverseTunnelProtocol.NonceLength];
                Buffer.BlockCopy(challengeFrame, 1, nonce, 0, ReverseTunnelProtocol.NonceLength);

                // 4. Send [0x04][16B sessionId][32B HMAC]
                byte[] hmac = ReverseTunnelProtocol.ComputeDataHmac(_sharedSecret, sessionId, nonce);
                var bindFrame = new byte[1 + ReverseTunnelProtocol.SessionIdLength + ReverseTunnelProtocol.HmacLength];
                bindFrame[0] = ReverseTunnelProtocol.OpDataBind;
                Buffer.BlockCopy(sessionId, 0, bindFrame, 1, ReverseTunnelProtocol.SessionIdLength);
                Buffer.BlockCopy(hmac, 0, bindFrame, 1 + ReverseTunnelProtocol.SessionIdLength, ReverseTunnelProtocol.HmacLength);

                await relayStream.WriteAsync(bindFrame, 0, bindFrame.Length, ct).ConfigureAwait(false);
                await relayStream.FlushAsync(ct).ConfigureAwait(false);

                // 5. Expect [0x05] BOUND
                var ack = new byte[1];
                if (!await ReverseTunnelProtocol.ReadExactAsync(relayStream, ack, 1, ct).ConfigureAwait(false)
                    || ack[0] != ReverseTunnelProtocol.OpDataBindOk)
                {
                    return;
                }

                // 6. Full-duplex bridge between external client (via relayStream) and local ZTalk.Server
                Interlocked.Increment(ref _activeTunnelCount);
                try
                {
                    using (var localStream = localTcp.GetStream())
                    {
                        await ReverseTunnelProtocol.BridgeBidirectionalAsync(localStream, relayStream, ct).ConfigureAwait(false);
                    }
                }
                finally
                {
                    Interlocked.Decrement(ref _activeTunnelCount);
                }
            }
            catch (OperationCanceledException) { }
            catch (Exception ex)
            {
                if (!ct.IsCancellationRequested)
                    Log($"Data tunnel error: {ex.Message}");
            }
            finally
            {
                try { relayStream?.Dispose(); } catch { }
                try { relayTcp?.Close(); } catch { }
                try { localTcp?.Close(); } catch { }
            }
        }

        private static async Task ConnectWithTimeoutAsync(TcpClient client, string host, int port, int timeoutMs, CancellationToken ct)
        {
            using (var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct))
            {
                var connectTask = client.ConnectAsync(host, port);
                var delayTask = Task.Delay(timeoutMs, timeoutCts.Token);
                if (await Task.WhenAny(connectTask, delayTask).ConfigureAwait(false) == delayTask)
                {
                    try { client.Close(); } catch { }
                    ct.ThrowIfCancellationRequested();
                    throw new TimeoutException($"Timed out connecting to {host}:{port}");
                }

                timeoutCts.Cancel();
                await connectTask.ConfigureAwait(false);
            }
        }

        private void SetControlConnected(bool connected)
        {
            if (_isControlConnected != connected)
            {
                _isControlConnected = connected;
                OnControlStateChanged?.Invoke(connected);
            }
        }

        private void Log(string message)
        {
            OnLog?.Invoke($"[{DateTime.Now:HH:mm:ss}] [TunnelAgent] {message}");
        }

        public void Dispose()
        {
            Stop();
        }
    }
}
