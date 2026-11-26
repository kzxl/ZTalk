using System;
using System.Collections;
using System.Collections.Generic;
using System.Drawing;
using System.Media;
using System.Threading.Tasks;
using System.Windows.Forms;
using ZTalk.Client.Services;
using ZTalk.Shared.Crypto;
using ZTalk.Shared.DTOs;
using ZTalk.Shared.Protocol;

namespace ZTalk.Client.Forms
{
    /// <summary>
    /// Main chat interface - displays online users, handles messaging, file transfer, and video calls.
    /// </summary>
    public partial class frmChat : Form
    {
        private const int MaxChatChars = 100000;

        private readonly TcpClientService _tcpService;
        private readonly ConnectionPipeline _pipeline;
        private readonly ChatService _chatService;
        private readonly FileTransferService _fileTransferService;
        private readonly FileReceiveService _fileReceiveService;
        private readonly VideoCallService _videoCallService;
        private readonly MessageHistoryService _historyService;
        private readonly string _currentUserId;
        private readonly string _currentDisplayName;

        private string _selectedUserId;
        private string _selectedUserName;
        private bool _isGroupChatMode;
        private bool _suppressSelectionEvent;

        // Diffie-Hellman management per peer: TargetUserId -> DH helper
        private readonly Dictionary<string, DiffieHellmanHelper> _dhInstances = new Dictionary<string, DiffieHellmanHelper>();

        // Online user list: UserId -> DisplayName
        private readonly Dictionary<string, string> _onlineUsers = new Dictionary<string, string>();
        private readonly List<string> _onlineUserOrder = new List<string>();

        // Unread message badge: UserId -> count
        private readonly Dictionary<string, int> _unreadCounts = new Dictionary<string, int>();

        // Active video call form instance
        private frmVideoCall _activeVideoCallForm;

        // Cached emoji picker popup (avoids leaking ContextMenuStrip + 18 Fonts per click)
        private ContextMenuStrip _emojiMenu;
        private Font _emojiFont;

        // Typing indicator timers
        private readonly Timer _typingSendTimer;
        private readonly Timer _typingDisplayTimer;

        /// <summary>Common emojis</summary>
        private static readonly string[] CommonEmojis = new[]
        {
            "😀", "😂", "😍", "👍", "👎", "🎉",
            "🔥", "❤️", "😎", "🤔", "😢", "👏",
            "🙏", "🚀", "💡", "💯", "✨", "☕"
        };

        public frmChat(TcpClientService tcpService, string userId, string displayName, ConnectionPipeline pipeline = null)
        {
            InitializeComponent();

            _tcpService = tcpService;
            _pipeline = pipeline;
            _currentUserId = userId;
            _currentDisplayName = displayName;

            _chatService = new ChatService(tcpService);
            _chatService.CurrentUserId = userId;

            _fileTransferService = new FileTransferService(tcpService, _chatService);
            _fileReceiveService = new FileReceiveService();
            _videoCallService = new VideoCallService(tcpService, _chatService);
            _historyService = new MessageHistoryService();

            // File transfer progress listeners (thread-safe UI marshaling via AppendSystem)
            _fileTransferService.OnSendProgress += (fileName, current, total) =>
            {
                if (total > 0 && (current == total || current % 5 == 0))
                {
                    AppendSystem($"📤 Sending \"{fileName}\": {current}/{total} chunks ({(current * 100 / total)}%)");
                }
            };
            _fileReceiveService.OnReceiveProgress += (transferId, current, total) =>
            {
                if (total > 0 && (current == total || current % 5 == 0))
                {
                    AppendSystem($"📥 Receiving file: {current}/{total} chunks ({(current * 100 / total)}%)");
                }
            };

            lblCurrentUser.Text = $"💬 ZTalk - Signed in as: {displayName}";
            this.Text = $"ZTalk - {displayName}";

            // Subscribe packet handler
            _tcpService.OnPacketReceived += HandlePacket;
            _tcpService.OnDisconnected += HandleDisconnected;

            // Enable resilient LAN/WAN auto-reconnect pipeline when provided
            if (_pipeline != null)
            {
                _pipeline.OnReconnecting += HandlePipelineReconnecting;
                _pipeline.OnReconnected += HandlePipelineReconnected;
                _pipeline.OnReconnectFailed += HandlePipelineReconnectFailed;
                _pipeline.EnableAutoReconnect();
                this.Text = $"ZTalk - {displayName} [{_pipeline.ActiveEndpointLabel}]";
            }

            // Video call events
            _videoCallService.OnIncomingCall += HandleIncomingCall;
            _videoCallService.OnCallAccepted += HandleCallAccepted;
            _videoCallService.OnCallEnded += HandleCallEnded;
            _videoCallService.OnCallRejected += HandleCallRejected;

            // Typing indicator timer: sends every 2s while typing
            _typingSendTimer = new Timer { Interval = 2000 };
            _typingSendTimer.Tick += (s, args) => _typingSendTimer.Stop();

            // Timer to hide typing indicator after 3s
            _typingDisplayTimer = new Timer { Interval = 3000 };
            _typingDisplayTimer.Tick += (s, args) =>
            {
                _typingDisplayTimer.Stop();
                lblTyping.Text = "";
            };

            // Request online user list via Heartbeat when shown
            this.Shown += frmChat_Shown;
        }

        private void MarshalToUi(Action action)
        {
            if (IsDisposed || Disposing || !IsHandleCreated) return;

            if (InvokeRequired)
            {
                try
                {
                    BeginInvoke(action);
                }
                catch (ObjectDisposedException) { }
                catch (InvalidOperationException) { }
                return;
            }

            action();
        }

        private void frmChat_Shown(object sender, EventArgs e)
        {
            // Send Heartbeat to request online user list from server
            var heartbeat = new Packet(PacketType.Heartbeat, _currentUserId, null, null);
            _tcpService.SendPacket(heartbeat);
        }

        #region Packet Handling

        private void HandlePacket(Packet packet)
        {
            MarshalToUi(() => ProcessPacketOnUi(packet));
        }

        private void ProcessPacketOnUi(Packet packet)
        {
            if (packet == null || IsDisposed) return;

            switch (packet.Type)
            {
                case PacketType.UserList:
                    HandleUserList(packet);
                    break;

                case PacketType.Message:
                    HandleMessage(packet);
                    break;

                case PacketType.KeyExchange:
                    HandleKeyExchange(packet);
                    break;

                case PacketType.KeyExchangeResponse:
                    HandleKeyExchangeResponse(packet);
                    break;

                case PacketType.FileHeader:
                    HandleFileHeader(packet);
                    break;

                case PacketType.FileChunk:
                    HandleFileChunk(packet);
                    break;

                case PacketType.FileComplete:
                    HandleFileComplete(packet);
                    break;

                case PacketType.VideoCallRequest:
                case PacketType.VideoCallAccept:
                case PacketType.VideoCallReject:
                case PacketType.VideoCallEnd:
                case PacketType.VideoFrame:
                    _videoCallService.HandleVideoSignal(packet);
                    break;

                case PacketType.TypingIndicator:
                    HandleTypingIndicator(packet);
                    break;

                case PacketType.GroupMessage:
                    HandleGroupMessage(packet);
                    break;

                case PacketType.ChatHistoryResponse:
                    HandleChatHistoryResponse(packet);
                    break;
            }
        }

        private void HandleUserList(Packet packet)
        {
            string previousSelectedId = _selectedUserId;

            _onlineUsers.Clear();
            _onlineUserOrder.Clear();

            if (!string.IsNullOrEmpty(packet.Data))
            {
                var users = packet.Data.Split(',');
                foreach (var user in users)
                {
                    var parts = user.Split('|');
                    if (parts.Length >= 2)
                    {
                        string uid = parts[0];
                        string name = parts[1];

                        if (uid == _currentUserId) continue; // Skip self

                        if (!_onlineUsers.ContainsKey(uid))
                        {
                            _onlineUserOrder.Add(uid);
                        }
                        _onlineUsers[uid] = name;
                    }
                }
            }

            lblUsers.Text = $"👥 Online ({_onlineUsers.Count})";

            // Check if active chat/call partner went offline
            if (!string.IsNullOrEmpty(previousSelectedId) && !_onlineUsers.ContainsKey(previousSelectedId))
            {
                AppendSystem($"⚠️ {_selectedUserName ?? previousSelectedId} went offline");

                if (_videoCallService.IsInCall && _videoCallService.CurrentCallPartner == previousSelectedId)
                {
                    _videoCallService.EndCall();
                    CloseVideoCallForm();
                    AppendSystem("📹 Video call ended because peer went offline");
                }

                _selectedUserId = null;
                _selectedUserName = null;
                lblChatWith.Text = "Select a user to start chat";
            }

            RefreshUserListBadges(preserveSelection: true);
        }

        private void HandleMessage(Packet packet)
        {
            var msgDto = PacketSerializer.FromJson<MessageDTO>(packet.Data);
            if (msgDto == null) return;

            string displayContent = _chatService.DecryptMessage(packet.SenderId, msgDto.Content, msgDto.IsEncrypted);
            string senderName = GetUserName(packet.SenderId);

            AppendChat(senderName, displayContent, Color.FromArgb(100, 200, 255));
            PlayNotificationSound();

            // Count unread if not currently active user
            if (packet.SenderId != _selectedUserId)
            {
                int count;
                _unreadCounts.TryGetValue(packet.SenderId, out count);
                _unreadCounts[packet.SenderId] = count + 1;
                RefreshUserListBadges(preserveSelection: true);
            }

            // Save history
            _historyService.SaveMessage(packet.SenderId, packet.SenderId, senderName, displayContent, false);
        }

        private void HandleKeyExchange(Packet packet)
        {
            var otherPublicKey = packet.Data;
            var dh = new DiffieHellmanHelper();
            var sharedSecret = dh.DeriveSharedSecret(otherPublicKey);
            var myPublicKey = dh.GetPublicKey();

            _chatService.SetSharedKey(packet.SenderId, sharedSecret);
            SetDhInstance(packet.SenderId, dh);

            // Send public key response
            var responsePacket = new Packet(PacketType.KeyExchangeResponse, _currentUserId, packet.SenderId, myPublicKey);
            _tcpService.SendPacket(responsePacket);

            AppendSystem($"🔐 Encrypted channel established with {GetUserName(packet.SenderId)}");
        }

        private void HandleKeyExchangeResponse(Packet packet)
        {
            DiffieHellmanHelper dh;
            if (_dhInstances.TryGetValue(packet.SenderId, out dh))
            {
                var sharedSecret = dh.DeriveSharedSecret(packet.Data);
                _chatService.SetSharedKey(packet.SenderId, sharedSecret);

                AppendSystem($"🔐 Encrypted channel established with {GetUserName(packet.SenderId)}");
            }
        }

        private void SetDhInstance(string peerId, DiffieHellmanHelper newDh)
        {
            DiffieHellmanHelper oldDh;
            if (_dhInstances.TryGetValue(peerId, out oldDh) && !ReferenceEquals(oldDh, newDh))
            {
                oldDh.Dispose();
            }
            _dhInstances[peerId] = newDh;
        }

        private void HandleFileHeader(Packet packet)
        {
            var dto = PacketSerializer.FromJson<FileTransferDTO>(packet.Data);
            if (dto == null) return;

            string senderName = GetUserName(packet.SenderId);
            _fileReceiveService.HandleFileHeader(packet.SenderId, senderName, dto.FileName, dto.FileSize, dto.TotalChunks, dto.TransferId);

            string sizeText = FormatFileSize(dto.FileSize);
            AppendSystem($"📎 {senderName} is sending file: {FileReceiveService.SanitizeFileName(dto.FileName)} ({sizeText})");
        }

        private void HandleFileChunk(Packet packet)
        {
            var dto = PacketSerializer.FromJson<FileTransferDTO>(packet.Data);
            if (dto == null || string.IsNullOrEmpty(dto.ChunkData)) return;

            if (dto.IsEncrypted)
            {
                try
                {
                    byte[] encryptedBytes = Convert.FromBase64String(dto.ChunkData);
                    byte[] decryptedBytes;
                    if (_chatService.TryDecryptBytes(packet.SenderId, encryptedBytes, out decryptedBytes))
                    {
                        _fileReceiveService.HandleFileChunk(dto.TransferId, dto.ChunkIndex, decryptedBytes);
                    }
                }
                catch { }
            }
            else
            {
                _fileReceiveService.HandleFileChunk(dto.TransferId, dto.ChunkIndex, dto.ChunkData);
            }
        }

        private void HandleFileComplete(Packet packet)
        {
            var dto = PacketSerializer.FromJson<FileTransferDTO>(packet.Data);
            if (dto == null) return;

            string savedPath = _fileReceiveService.HandleFileComplete(dto.TransferId);

            if (savedPath != null)
            {
                string fileName = System.IO.Path.GetFileName(savedPath);
                string senderName = GetUserName(packet.SenderId);

                AppendSystem($"✅ Received file from {senderName}: {fileName}");

                string ext = System.IO.Path.GetExtension(savedPath).ToLowerInvariant();
                bool isImage = ext == ".jpg" || ext == ".jpeg" || ext == ".png" || ext == ".gif" || ext == ".bmp";

                if (isImage)
                {
                    try
                    {
                        var preview = new frmImagePreview(savedPath);
                        preview.Show(this);
                    }
                    catch
                    {
                        FileReceiveService.OpenFile(savedPath);
                    }
                }
                else
                {
                    var result = MessageBox.Show(
                        $"Received file \"{fileName}\" from {senderName}.\n\nDo you want to open the file?",
                        "File Received", MessageBoxButtons.YesNo, MessageBoxIcon.Information);

                    if (result == DialogResult.Yes)
                    {
                        FileReceiveService.OpenFile(savedPath);
                    }
                }

                // Save to history
                _historyService.SaveMessage(packet.SenderId, packet.SenderId, senderName,
                    $"[File] {fileName}", true);
            }
            else
            {
                AppendSystem($"❌ Error receiving file from {GetUserName(packet.SenderId)}");
            }
        }

        private void HandleTypingIndicator(Packet packet)
        {
            string senderName = GetUserName(packet.SenderId);
            lblTyping.Text = $"✏️ {senderName} is typing...";
            _typingDisplayTimer.Stop();
            _typingDisplayTimer.Start(); // Hide after 3s
        }

        private void HandleGroupMessage(Packet packet)
        {
            var msgDto = PacketSerializer.FromJson<MessageDTO>(packet.Data);
            if (msgDto == null) return;

            string senderName = GetUserName(packet.SenderId);
            AppendChat($"[Group] {senderName}", msgDto.Content, Color.FromArgb(255, 180, 100));
            PlayNotificationSound();

            // Save to group history
            _historyService.SaveMessage("__group__", packet.SenderId, senderName, msgDto.Content, false);
        }

        private void HandleChatHistoryResponse(Packet packet)
        {
            var payload = PacketSerializer.FromJson<Dictionary<string, object>>(packet.Data);
            rtbChat.Clear();

            if (payload == null)
            {
                AppendSystem("No message history");
                return;
            }

            string partnerId = payload.ContainsKey("PartnerId") ? payload["PartnerId"]?.ToString() : null;
            var messagesObj = payload.ContainsKey("Messages") ? payload["Messages"] as IEnumerable : null;
            if (messagesObj == null)
            {
                AppendSystem("No message history");
                return;
            }

            bool isGroup = partnerId == "__group__";
            int count = 0;

            foreach (var entry in messagesObj)
            {
                var item = entry as Dictionary<string, object>;
                if (item == null) continue;

                string senderId = item.ContainsKey("SenderId") ? item["SenderId"]?.ToString() : null;
                string senderName2 = item.ContainsKey("SenderName") ? item["SenderName"]?.ToString() : null;
                string content2 = item.ContainsKey("Content") ? item["Content"]?.ToString() : null;

                bool isMine = senderId == _currentUserId;
                var color = isMine ? Color.LimeGreen : (isGroup ? Color.FromArgb(255, 180, 100) : Color.FromArgb(100, 200, 255));
                var name = isMine ? _currentDisplayName : (senderName2 ?? senderId ?? "Unknown");
                if (isGroup && !isMine) name = $"[Group] {name}";

                AppendChat(name, content2 ?? "", color);
                count++;
            }

            if (count == 0)
            {
                AppendSystem("No message history");
            }
        }

        private void HandleIncomingCall(string callerUserId)
        {
            MarshalToUi(() =>
            {
                string callerName = GetUserName(callerUserId);
                var result = MessageBox.Show(
                    $"📹 {callerName} is calling you with video.\nDo you want to accept?",
                    "Incoming Video Call", MessageBoxButtons.YesNo, MessageBoxIcon.Question);

                if (result == DialogResult.Yes)
                {
                    _videoCallService.AcceptCall(callerUserId);
                }
                else
                {
                    _videoCallService.RejectCall(callerUserId);
                }
            });
        }

        private void HandleCallAccepted()
        {
            MarshalToUi(() =>
            {
                string partnerName = GetUserName(_videoCallService.CurrentCallPartner);
                AppendSystem($"📹 Video call connected with {partnerName}");
                OpenVideoCallForm(partnerName);
            });
        }

        private void HandleCallRejected(string reason)
        {
            MarshalToUi(() =>
            {
                AppendSystem($"📹 {reason}");
                CloseVideoCallForm();
            });
        }

        private void HandleCallEnded()
        {
            MarshalToUi(() =>
            {
                AppendSystem("📹 Video call ended");
                CloseVideoCallForm();
            });
        }

        private void HandleDisconnected()
        {
            MarshalToUi(() =>
            {
                if (_videoCallService.IsInCall)
                {
                    _videoCallService.EndCall();
                    CloseVideoCallForm();
                }

                if (_pipeline != null && _pipeline.IsAutoReconnectEnabled)
                {
                    AppendSystem("⚠️ Mất kết nối máy chủ — đang tự động kết nối lại...");
                    this.Text = $"ZTalk - {_currentDisplayName} [Reconnecting...]";
                }
                else
                {
                    AppendSystem("⚠️ Connection to server lost!");
                    MessageBox.Show("Connection to server lost!", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                }
            });
        }

        private void HandlePipelineReconnecting(int attempt, int delayMs)
        {
            MarshalToUi(() =>
            {
                AppendSystem($"🔄 Đang thử kết nối lại lần #{attempt} (sau {delayMs / 1000.0:F1}s)...");
            });
        }

        private void HandlePipelineReconnected(string endpointLabel)
        {
            MarshalToUi(() =>
            {
                this.Text = $"ZTalk - {_currentDisplayName} [{endpointLabel}]";
                AppendSystem($"✅ Đã kết nối lại thành công qua {endpointLabel}");
                var heartbeat = new Packet(PacketType.Heartbeat, _currentUserId, null, null);
                _tcpService.SendPacket(heartbeat);
            });
        }

        private void HandlePipelineReconnectFailed(string reason)
        {
            MarshalToUi(() =>
            {
                this.Text = $"ZTalk - {_currentDisplayName} [Disconnected]";
                AppendSystem($"❌ Không thể tự động kết nối lại: {reason}");
                MessageBox.Show($"Không thể kết nối lại: {reason}", "Mất kết nối", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            });
        }

        #endregion

        #region UI Events

        private void lstUsers_SelectedIndexChanged(object sender, EventArgs e)
        {
            if (_suppressSelectionEvent) return;
            int selectedIndex = lstUsers.SelectedIndex;
            if (selectedIndex < 0 || selectedIndex >= _onlineUserOrder.Count) return;

            string userId = _onlineUserOrder[selectedIndex];
            string displayName = GetUserName(userId);

            // Exit group chat mode when selecting a specific user
            if (_isGroupChatMode)
            {
                _isGroupChatMode = false;
                btnGroupChat.BackColor = Color.FromArgb(60, 100, 160);
                btnGroupChat.Text = "📢 Group Chat";
            }

            _selectedUserId = userId;
            _selectedUserName = displayName;
            lblChatWith.Text = $"💬 Chat with {displayName}";

            // Clear unread badge while preserving current selection
            if (_unreadCounts.Remove(userId))
            {
                RefreshUserListBadges(preserveSelection: true);
            }

            // Load chat history from server
            rtbChat.Clear();
            AppendSystem("Loading...");
            var histReq = new Packet(PacketType.ChatHistoryRequest, _currentUserId, _selectedUserId, null);
            _tcpService.SendPacket(histReq);

            // Initiate DH key exchange if not established yet
            if (!_chatService.HasSharedKey(_selectedUserId))
            {
                InitiateKeyExchange(_selectedUserId);
            }
        }

        private void btnSend_Click(object sender, EventArgs e)
        {
            SendMessage();
        }

        private void txtMessage_KeyDown(object sender, KeyEventArgs e)
        {
            if (e.KeyCode == Keys.Enter)
            {
                e.SuppressKeyPress = true;
                SendMessage();
            }
            else if (!string.IsNullOrEmpty(_selectedUserId) && !_typingSendTimer.Enabled)
            {
                // Send typing indicator (throttle 2s)
                _typingSendTimer.Start();
                var typingPacket = new Packet(PacketType.TypingIndicator, _currentUserId, _selectedUserId, null);
                _tcpService.SendPacket(typingPacket);
            }
        }

        private void btnEmoji_Click(object sender, EventArgs e)
        {
            if (_emojiMenu == null)
            {
                _emojiFont = new Font("Segoe UI Emoji", 14F);
                _emojiMenu = new ContextMenuStrip
                {
                    BackColor = Color.FromArgb(45, 45, 50),
                    ForeColor = Color.White,
                    ShowImageMargin = false
                };

                var flowPanel = new FlowLayoutPanel
                {
                    AutoSize = true,
                    MaximumSize = new Size(240, 200),
                    BackColor = Color.FromArgb(45, 45, 50),
                    Padding = new Padding(5)
                };

                foreach (var emoji in CommonEmojis)
                {
                    var btn = new Button
                    {
                        Text = emoji,
                        Font = _emojiFont,
                        Size = new Size(36, 36),
                        FlatStyle = FlatStyle.Flat,
                        BackColor = Color.FromArgb(55, 55, 60),
                        ForeColor = Color.White,
                        Margin = new Padding(2),
                        Cursor = Cursors.Hand
                    };
                    btn.FlatAppearance.BorderSize = 0;
                    btn.Click += (s, args) =>
                    {
                        txtMessage.Text += ((Button)s).Text;
                        txtMessage.SelectionStart = txtMessage.Text.Length;
                        txtMessage.Focus();
                        _emojiMenu.Close();
                    };
                    flowPanel.Controls.Add(btn);
                }

                var host = new ToolStripControlHost(flowPanel)
                {
                    AutoSize = true
                };
                _emojiMenu.Items.Add(host);
            }

            _emojiMenu.Show(btnEmoji, new Point(0, -210));
        }

        private void btnGroupChat_Click(object sender, EventArgs e)
        {
            _isGroupChatMode = !_isGroupChatMode;

            if (_isGroupChatMode)
            {
                _suppressSelectionEvent = true;
                try { lstUsers.ClearSelected(); }
                finally { _suppressSelectionEvent = false; }

                _selectedUserId = null;
                _selectedUserName = null;
                lblChatWith.Text = "📢 Group Chat (All online users)";
                btnGroupChat.BackColor = Color.FromArgb(200, 100, 50);
                btnGroupChat.Text = "📢 In Group Chat";

                // Load group history from server
                rtbChat.Clear();
                AppendSystem("Loading...");
                var histReq = new Packet(PacketType.ChatHistoryRequest, _currentUserId, "__group__", null);
                _tcpService.SendPacket(histReq);
            }
            else
            {
                lblChatWith.Text = "Select a user to start chat";
                btnGroupChat.BackColor = Color.FromArgb(60, 100, 160);
                btnGroupChat.Text = "📢 Group Chat";
                rtbChat.Clear();
            }
        }

        private async void btnSendFile_Click(object sender, EventArgs e)
        {
            if (string.IsNullOrEmpty(_selectedUserId))
            {
                MessageBox.Show("Please select a user to send a file to.", "Notice", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }

            string targetUserId = _selectedUserId;
            using (var ofd = new OpenFileDialog())
            {
                ofd.Title = "Select file to send";
                ofd.Filter = "All Files|*.*|Images|*.jpg;*.png;*.gif;*.bmp";
                if (ofd.ShowDialog() == DialogResult.OK)
                {
                    string selectedPath = ofd.FileName;
                    string fileName = System.IO.Path.GetFileName(selectedPath);
                    AppendSystem($"📎 Sending file: {fileName}");

                    btnSendFile.Enabled = false;
                    try
                    {
                        await Task.Run(() => _fileTransferService.SendFile(targetUserId, selectedPath));
                        _historyService.SaveMessage(targetUserId, _currentUserId, _currentDisplayName,
                            $"[File] {fileName}", true);
                    }
                    catch (Exception ex)
                    {
                        AppendSystem($"❌ Failed to send file: {ex.Message}");
                    }
                    finally
                    {
                        if (!IsDisposed && !Disposing)
                            btnSendFile.Enabled = true;
                    }
                }
            }
        }

        private void btnVideoCall_Click(object sender, EventArgs e)
        {
            if (string.IsNullOrEmpty(_selectedUserId))
            {
                MessageBox.Show("Please select a user to start a video call.", "Notice", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }

            if (_videoCallService.IsInCall)
            {
                MessageBox.Show("You are already in a video call!", "Notice", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }

            _videoCallService.StartCall(_selectedUserId);
            AppendSystem($"📹 Calling {_selectedUserName}...");
        }

        private void frmChat_FormClosing(object sender, FormClosingEventArgs e)
        {
            if (_pipeline != null)
            {
                _pipeline.OnReconnecting -= HandlePipelineReconnecting;
                _pipeline.OnReconnected -= HandlePipelineReconnected;
                _pipeline.OnReconnectFailed -= HandlePipelineReconnectFailed;
                _pipeline.Dispose();
            }

            _tcpService.OnPacketReceived -= HandlePacket;
            _tcpService.OnDisconnected -= HandleDisconnected;

            _videoCallService.OnIncomingCall -= HandleIncomingCall;
            _videoCallService.OnCallAccepted -= HandleCallAccepted;
            _videoCallService.OnCallEnded -= HandleCallEnded;
            _videoCallService.OnCallRejected -= HandleCallRejected;

            // End video call and release media/UDP resources
            if (_videoCallService.IsInCall)
            {
                _videoCallService.EndCall();
            }
            CloseVideoCallForm();
            _videoCallService.Dispose();

            // Send disconnect packet
            var packet = new Packet(PacketType.Disconnect, _currentUserId, null, null);
            _tcpService.SendPacket(packet);
            _tcpService.Dispose();

            // Dispose timers, emoji popup, and DH instances
            _typingSendTimer?.Stop();
            _typingSendTimer?.Dispose();
            _typingDisplayTimer?.Stop();
            _typingDisplayTimer?.Dispose();

            _emojiMenu?.Dispose();
            _emojiMenu = null;
            _emojiFont?.Dispose();
            _emojiFont = null;

            foreach (var dh in _dhInstances.Values)
            {
                dh.Dispose();
            }
            _dhInstances.Clear();
        }

        #endregion

        #region Video Call Helpers

        private void OpenVideoCallForm(string partnerName)
        {
            CloseVideoCallForm(); // Close existing form if any

            _activeVideoCallForm = new frmVideoCall(_videoCallService);
            _activeVideoCallForm.Text = $"📹 Video Call - {partnerName}";
            _activeVideoCallForm.FormClosed += (s, args) =>
            {
                _activeVideoCallForm = null;
            };
            _activeVideoCallForm.Show(this); // Show as modeless, owner = frmChat
        }

        private void CloseVideoCallForm()
        {
            if (_activeVideoCallForm != null && !_activeVideoCallForm.IsDisposed)
            {
                _activeVideoCallForm.Close();
                _activeVideoCallForm = null;
            }
        }

        #endregion

        #region Helpers

        private void SendMessage()
        {
            if (string.IsNullOrWhiteSpace(txtMessage.Text))
                return;

            string message = txtMessage.Text.Trim();

            if (_isGroupChatMode)
            {
                // Send a single broadcast GroupMessage packet (server fans out once and stores once)
                var dto = new MessageDTO { Content = message, IsEncrypted = false, SentAt = DateTime.Now };
                var packet = new Packet(PacketType.GroupMessage, _currentUserId, null, PacketSerializer.ToJson(dto));
                _tcpService.SendPacket(packet);

                AppendChat(_currentDisplayName, message, Color.LimeGreen);
                _historyService.SaveMessage("__group__", _currentUserId, _currentDisplayName, message, false);
            }
            else
            {
                if (string.IsNullOrEmpty(_selectedUserId)) return;

                _chatService.SendMessage(_selectedUserId, message);
                AppendChat(_currentDisplayName, message, Color.LimeGreen);
                _historyService.SaveMessage(_selectedUserId, _currentUserId, _currentDisplayName, message, false);
            }

            txtMessage.Clear();
            txtMessage.Focus();
        }

        private void InitiateKeyExchange(string targetUserId)
        {
            var dh = new DiffieHellmanHelper();
            SetDhInstance(targetUserId, dh);

            var publicKey = dh.GetPublicKey();
            var packet = new Packet(PacketType.KeyExchange, _currentUserId, targetUserId, publicKey);
            _tcpService.SendPacket(packet);

            AppendSystem($"🔑 Performing key exchange with {GetUserName(targetUserId)}...");
        }

        private void TrimChatIfNeeded()
        {
            if (rtbChat.TextLength > MaxChatChars)
            {
                rtbChat.Select(0, rtbChat.TextLength / 2);
                rtbChat.SelectedText = string.Empty;
            }
        }

        private void AppendChat(string sender, string message, Color color)
        {
            MarshalToUi(() =>
            {
                TrimChatIfNeeded();
                var timestamp = DateTime.Now.ToString("HH:mm");

                rtbChat.SelectionStart = rtbChat.TextLength;
                rtbChat.SelectionLength = 0;

                // Timestamp
                rtbChat.SelectionColor = Color.Gray;
                rtbChat.AppendText($"[{timestamp}] ");

                // Sender name
                rtbChat.SelectionColor = color;
                rtbChat.AppendText($"{sender}: ");

                // Message
                rtbChat.SelectionColor = Color.White;
                rtbChat.AppendText($"{message}\n");

                rtbChat.ScrollToCaret();
            });
        }

        private void AppendSystem(string message)
        {
            MarshalToUi(() =>
            {
                TrimChatIfNeeded();
                rtbChat.SelectionStart = rtbChat.TextLength;
                rtbChat.SelectionLength = 0;
                rtbChat.SelectionColor = Color.FromArgb(255, 200, 100);
                rtbChat.AppendText($"  {message}\n");
                rtbChat.ScrollToCaret();
            });
        }

        private string GetUserName(string userId)
        {
            if (string.IsNullOrEmpty(userId)) return "Unknown";
            string name;
            return _onlineUsers.TryGetValue(userId, out name) ? name : userId;
        }

        private static string FormatFileSize(long bytes)
        {
            if (bytes < 1024) return $"{bytes} B";
            if (bytes < 1024 * 1024) return $"{bytes / 1024.0:F1} KB";
            if (bytes < 1024 * 1024 * 1024) return $"{bytes / (1024.0 * 1024):F1} MB";
            return $"{bytes / (1024.0 * 1024 * 1024):F1} GB";
        }

        #endregion

        #region Badge & Sound

        private void RefreshUserListBadges(bool preserveSelection = false)
        {
            _suppressSelectionEvent = true;
            lstUsers.BeginUpdate();
            try
            {
                lstUsers.Items.Clear();
                int selectedIdx = -1;

                for (int i = 0; i < _onlineUserOrder.Count; i++)
                {
                    string uid = _onlineUserOrder[i];
                    string name = _onlineUsers[uid];
                    int unread;
                    _unreadCounts.TryGetValue(uid, out unread);
                    string badge = unread > 0 ? $" ({unread})" : "";
                    lstUsers.Items.Add($"🟢 {name}{badge}");

                    if (preserveSelection && uid == _selectedUserId)
                    {
                        selectedIdx = i;
                    }
                }

                if (selectedIdx >= 0)
                {
                    lstUsers.SelectedIndex = selectedIdx;
                }
            }
            finally
            {
                lstUsers.EndUpdate();
                _suppressSelectionEvent = false;
            }
        }

        private void PlayNotificationSound()
        {
            try
            {
                SystemSounds.Asterisk.Play();
            }
            catch { }
        }

        #endregion
    }
}
