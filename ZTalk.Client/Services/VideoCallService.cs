using System;
using System.Threading.Tasks;
using ZTalk.Shared.DTOs;
using ZTalk.Shared.Protocol;

namespace ZTalk.Client.Services
{
    /// <summary>
    /// Quản lý video call: P2P UDP với STUN NAT traversal.
    /// Fallback về server relay (TCP) khi P2P thất bại.
    /// </summary>
    public class VideoCallService : IVideoCallService, IDisposable
    {
        private readonly TcpClientService _tcpService;
        private readonly ChatService _chatService;
        private readonly object _stateLock = new object();
        private UdpPeerService _udpPeer;
        private IVideoSource _videoSource;

        private volatile bool _isInCall;
        private volatile bool _useRelay;
        private volatile bool _isVideoEnabled = true;

        public bool IsInCall
        {
            get => _isInCall;
            private set => _isInCall = value;
        }

        public string CurrentCallPartner { get; private set; }
        public string CurrentUserId => _chatService?.CurrentUserId;
        public bool IsP2PConnected => _udpPeer?.IsConnected ?? false;

        public bool UseRelay
        {
            get => _useRelay;
            private set => _useRelay = value;
        }

        public bool IsVideoEnabled
        {
            get => _isVideoEnabled;
            set => _isVideoEnabled = value;
        }

        public event Action<string> OnIncomingCall;        // callerUserId
        public event Action OnCallAccepted;
        public event Action<string> OnCallRejected;        // reason
        public event Action OnCallEnded;
        public event Action<byte[]> OnVideoFrameReceived;
        public event Action<byte[]> OnLocalFrameCaptured;  // local camera / PIP
        public event Action<string> OnLog;                 // log message

        // Lưu endpoint info của peer (nhận từ signaling)
        private string _peerPublicIp;
        private int _peerPublicPort;
        private string _peerLocalIp;
        private int _peerLocalPort;

        public VideoCallService(TcpClientService tcpService, ChatService chatService)
        {
            _tcpService = tcpService;
            _chatService = chatService;
        }

        /// <summary>
        /// Thay đổi nguồn phát video (Synthetic / Screen Share / Webcam)
        /// </summary>
        public void SetVideoSource(IVideoSource source)
        {
            lock (_stateLock)
            {
                if (_videoSource != null)
                {
                    _videoSource.OnFrameCaptured -= HandleLocalFrameCaptured;
                    _videoSource.Stop();
                    _videoSource.Dispose();
                }

                _videoSource = source;
                if (_videoSource != null)
                {
                    _videoSource.OnFrameCaptured += HandleLocalFrameCaptured;
                    if (IsInCall)
                    {
                        _videoSource.Start(320, 240, 15);
                    }
                }
            }
        }

        /// <summary>
        /// Enable or disable camera transmission
        /// </summary>
        public void ToggleVideo(bool enabled)
        {
            IsVideoEnabled = enabled;
            Log(enabled ? "📷 Camera enabled" : "📷 Camera disabled");
        }

        private void StartCapturing()
        {
            lock (_stateLock)
            {
                if (_videoSource == null)
                {
                    _videoSource = new SyntheticVideoSource(_chatService.CurrentUserId);
                    _videoSource.OnFrameCaptured += HandleLocalFrameCaptured;
                }

                if (!_videoSource.IsRunning)
                {
                    _videoSource.Start(320, 240, 15);
                    Log($"▶ Video source started: {_videoSource.SourceName}");
                }
            }
        }

        private void StopCapturing()
        {
            lock (_stateLock)
            {
                if (_videoSource != null && _videoSource.IsRunning)
                {
                    _videoSource.Stop();
                    Log("⏹ Video source stopped");
                }
            }
        }

        private void HandleLocalFrameCaptured(byte[] frameData)
        {
            OnLocalFrameCaptured?.Invoke(frameData);

            if (IsInCall && IsVideoEnabled)
            {
                SendVideoFrame(frameData);
            }
        }

        /// <summary>
        /// Initiate video call request. Discover endpoint via STUN first.
        /// </summary>
        public void StartCall(string targetUserId)
        {
            if (IsInCall) return;

            CurrentCallPartner = targetUserId;
            Log("Discovering network endpoint (STUN)...");

            Task.Run(() =>
            {
                InitializeUdpPeer();
                var peer = _udpPeer;
                if (peer == null) return;

                var signal = new VideoSignalDTO
                {
                    SignalType = "Request",
                    LocalIp = peer.LocalEndPoint?.Address?.ToString() ?? "",
                    LocalPort = peer.LocalEndPoint?.Port ?? 0,
                    PublicIp = peer.PublicEndPoint?.Address?.ToString() ?? "",
                    PublicPort = peer.PublicEndPoint?.Port ?? 0
                };

                if (!string.IsNullOrEmpty(signal.PublicIp))
                    Log($"Public endpoint: {signal.PublicIp}:{signal.PublicPort}");
                else
                    Log("Cannot discover public endpoint (STUN failed)");

                Log($"Local endpoint: {signal.LocalIp}:{signal.LocalPort}");

                var packet = new Packet(PacketType.VideoCallRequest, _chatService.CurrentUserId, targetUserId, PacketSerializer.ToJson(signal));
                _tcpService.SendPacket(packet);

                Log("Video call request sent...");
            });
        }

        /// <summary>
        /// Accept incoming call. Discover endpoint, reply, and begin UDP hole punching.
        /// </summary>
        public void AcceptCall(string callerUserId)
        {
            CurrentCallPartner = callerUserId;
            Log("Preparing connection...");

            Task.Run(async () =>
            {
                InitializeUdpPeer();
                var peer = _udpPeer;
                if (peer == null) return;

                var signal = new VideoSignalDTO
                {
                    SignalType = "Accept",
                    LocalIp = peer.LocalEndPoint?.Address?.ToString() ?? "",
                    LocalPort = peer.LocalEndPoint?.Port ?? 0,
                    PublicIp = peer.PublicEndPoint?.Address?.ToString() ?? "",
                    PublicPort = peer.PublicEndPoint?.Port ?? 0
                };

                var packet = new Packet(PacketType.VideoCallAccept, _chatService.CurrentUserId, callerUserId, PacketSerializer.ToJson(signal));
                _tcpService.SendPacket(packet);

                IsInCall = true;
                StartCapturing();
                OnCallAccepted?.Invoke();

                await AttemptP2PConnection().ConfigureAwait(false);
            });
        }

        /// <summary>
        /// Từ chối cuộc gọi
        /// </summary>
        public void RejectCall(string callerUserId)
        {
            var signal = new VideoSignalDTO { SignalType = "Reject" };
            var packet = new Packet(PacketType.VideoCallReject, _chatService.CurrentUserId, callerUserId, PacketSerializer.ToJson(signal));
            _tcpService.SendPacket(packet);
        }

        /// <summary>
        /// Kết thúc cuộc gọi
        /// </summary>
        public void EndCall()
        {
            string partner;
            lock (_stateLock)
            {
                if (!IsInCall && CurrentCallPartner == null) return;
                partner = CurrentCallPartner;
            }

            if (partner != null)
            {
                var signal = new VideoSignalDTO { SignalType = "End" };
                var packet = new Packet(PacketType.VideoCallEnd, _chatService.CurrentUserId, partner, PacketSerializer.ToJson(signal));
                _tcpService.SendPacket(packet);
            }

            Cleanup();
            OnCallEnded?.Invoke();
        }

        /// <summary>
        /// Gửi video frame đến peer (P2P hoặc relay)
        /// </summary>
        public void SendVideoFrame(byte[] frameData)
        {
            if (!IsInCall || frameData == null || frameData.Length == 0) return;

            var peer = _udpPeer;
            if (peer != null && peer.IsConnected && !UseRelay)
            {
                // P2P UDP
                peer.SendData(frameData);
            }
            else
            {
                string partner = CurrentCallPartner;
                if (string.IsNullOrEmpty(partner)) return;

                // Server relay (TCP)
                var base64 = Convert.ToBase64String(frameData);
                var packet = new Packet(PacketType.VideoFrame, _chatService.CurrentUserId, partner, base64);
                _tcpService.SendPacket(packet);
            }
        }

        /// <summary>
        /// Xử lý signal nhận được từ server
        /// </summary>
        public void HandleVideoSignal(Packet packet)
        {
            switch (packet.Type)
            {
                case PacketType.VideoCallRequest:
                    SavePeerEndpoint(packet.Data);
                    OnIncomingCall?.Invoke(packet.SenderId);
                    break;

                case PacketType.VideoCallAccept:
                    SavePeerEndpoint(packet.Data);
                    IsInCall = true;
                    CurrentCallPartner = packet.SenderId;
                    StartCapturing();
                    OnCallAccepted?.Invoke();

                    Task.Run(() => AttemptP2PConnection());
                    break;

                case PacketType.VideoCallReject:
                    OnCallRejected?.Invoke("Call was rejected");
                    Cleanup();
                    break;

                case PacketType.VideoCallEnd:
                    Cleanup();
                    OnCallEnded?.Invoke();
                    break;

                case PacketType.VideoFrame:
                    if (!string.IsNullOrEmpty(packet.Data))
                    {
                        try
                        {
                            var frameData = Convert.FromBase64String(packet.Data);
                            OnVideoFrameReceived?.Invoke(frameData);
                        }
                        catch { }
                    }
                    break;
            }
        }

        #region Private Helpers

        private void InitializeUdpPeer()
        {
            var newPeer = new UdpPeerService();
            newPeer.OnDataReceived += data => OnVideoFrameReceived?.Invoke(data);
            newPeer.Initialize();

            UdpPeerService oldPeer;
            lock (_stateLock)
            {
                oldPeer = _udpPeer;
                _udpPeer = newPeer;
            }
            oldPeer?.Dispose();
        }

        /// <summary>
        /// Attempt P2P connection via UDP hole punching.
        /// If failed, fall back to Server Relay.
        /// </summary>
        private async Task AttemptP2PConnection()
        {
            var peer = _udpPeer;
            if (peer == null)
            {
                UseRelay = true;
                Log("⚠️ Using Server Relay (UDP not initialized)");
                return;
            }

            Log("🔗 Attempting P2P connection (UDP hole punching)...");

            bool success = await peer.HolePunchAsync(
                _peerPublicIp, _peerPublicPort,
                _peerLocalIp, _peerLocalPort).ConfigureAwait(false);

            if (!IsInCall) return;

            if (success)
            {
                UseRelay = false;
                peer.StartReceiving();
                Log("✅ P2P connected successfully! Direct UDP streaming");
            }
            else
            {
                UseRelay = true;
                Log("⚠️ P2P failed, falling back to Server Relay (TCP)");
            }
        }

        private void SavePeerEndpoint(string data)
        {
            var signal = PacketSerializer.FromJson<VideoSignalDTO>(data);
            if (signal == null) return;

            _peerLocalIp = signal.LocalIp;
            _peerLocalPort = signal.LocalPort;
            _peerPublicIp = signal.PublicIp;
            _peerPublicPort = signal.PublicPort;
        }

        private void Cleanup()
        {
            StopCapturing();

            UdpPeerService peerToDispose;
            lock (_stateLock)
            {
                IsInCall = false;
                CurrentCallPartner = null;
                UseRelay = false;
                _peerPublicIp = null;
                _peerPublicPort = 0;
                _peerLocalIp = null;
                _peerLocalPort = 0;

                peerToDispose = _udpPeer;
                _udpPeer = null;
            }

            peerToDispose?.Dispose();
        }

        private void Log(string message)
        {
            OnLog?.Invoke(message);
        }

        public void Dispose()
        {
            Cleanup();

            IVideoSource sourceToDispose;
            lock (_stateLock)
            {
                sourceToDispose = _videoSource;
                _videoSource = null;
            }

            if (sourceToDispose != null)
            {
                sourceToDispose.OnFrameCaptured -= HandleLocalFrameCaptured;
                sourceToDispose.Dispose();
            }
        }

        #endregion
    }
}
