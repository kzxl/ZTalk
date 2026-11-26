using System;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using ZTalk.Client.Config;
using ZTalk.Client.Services;
using ZTalk.Shared.DTOs;
using ZTalk.Shared.Protocol;

namespace ZTalk.Client.Forms
{
    /// <summary>
    /// Login and registration form with TLS 1.2 pinning support and optional enterprise config.
    /// </summary>
    public partial class frmLogin : Form
    {
        private readonly TcpClientService _tcpService;
        private readonly ClientSecurityConfig _securityConfig;
        private readonly ConnectionPipeline _pipeline;
        private readonly string _autoLoginUser;
        private bool _autoLoginTriggered;

        public string LoggedInUserId { get; private set; }
        public string LoggedInDisplayName { get; private set; }
        public TcpClientService TcpService => _tcpService;
        public ConnectionPipeline Pipeline => _pipeline;

        public frmLogin(string autoLoginUser = null)
        {
            InitializeComponent();
            _autoLoginUser = autoLoginUser;
            _tcpService = new TcpClientService();
            _securityConfig = ClientSecurityConfig.LoadOrDefault();
            _pipeline = new ConnectionPipeline(_tcpService, _securityConfig);

            if (!string.IsNullOrWhiteSpace(_securityConfig.ServerHost))
                txtServer.Text = _securityConfig.ServerHost;
            if (_securityConfig.ServerPort > 0 && _securityConfig.ServerPort <= 65535)
                nudPort.Value = _securityConfig.ServerPort;
            if (_securityConfig.HideDemoAccounts)
                pnlDemo.Visible = false;
        }

        protected override void OnShown(EventArgs e)
        {
            base.OnShown(e);
            TryAutoLogin();
        }

        private async void TryAutoLogin()
        {
            if (_autoLoginTriggered || string.IsNullOrEmpty(_autoLoginUser)) return;
            _autoLoginTriggered = true;

            string username = _autoLoginUser.Replace("demo_", "").Trim().ToLower();
            txtUsername.Text = username;
            txtPassword.Text = "123";
            await Task.Delay(200);
            if (!IsDisposed && !Disposing)
            {
                await DoAuth(PacketType.Login);
            }
        }

        private async void btnLogin_Click(object sender, EventArgs e)
        {
            await DoAuth(PacketType.Login);
        }

        private async void btnRegister_Click(object sender, EventArgs e)
        {
            await DoAuth(PacketType.Register);
        }

        private async void btnDemoAlice_Click(object sender, EventArgs e)
        {
            txtUsername.Text = "alice";
            txtPassword.Text = "123";
            await DoAuth(PacketType.Login);
        }

        private async void btnDemoBob_Click(object sender, EventArgs e)
        {
            txtUsername.Text = "bob";
            txtPassword.Text = "123";
            await DoAuth(PacketType.Login);
        }

        private async void btnDemoCharlie_Click(object sender, EventArgs e)
        {
            txtUsername.Text = "charlie";
            txtPassword.Text = "123";
            await DoAuth(PacketType.Login);
        }

        private async Task DoAuth(PacketType authType)
        {
            if (string.IsNullOrWhiteSpace(txtUsername.Text) || string.IsNullOrWhiteSpace(txtPassword.Text))
            {
                lblStatus.Text = "Please enter username and password";
                lblStatus.ForeColor = System.Drawing.Color.Orange;
                return;
            }

            btnLogin.Enabled = false;
            btnRegister.Enabled = false;
            pnlDemo.Enabled = false;
            lblStatus.Text = "Connecting to server...";
            lblStatus.ForeColor = System.Drawing.Color.Gray;

            Action<Packet> handler = null;
            try
            {
                // 1. Establish connection via Dual-Endpoint Pipeline (LAN fast probe -> WAN Edge fallback)
                if (!_tcpService.IsConnected)
                {
                    var connected = await _pipeline.ConnectSmartAsync(txtServer.Text.Trim(), (int)nudPort.Value);
                    if (IsDisposed || Disposing) return;

                    if (!connected)
                    {
                        lblStatus.Text = _securityConfig.UseTls
                            ? "Cannot establish TLS connection (check LAN/WAN server or certificate pin)"
                            : "Cannot connect to server";
                        lblStatus.ForeColor = System.Drawing.Color.Red;
                        return;
                    }
                }

                // 2. Hash password
                string passwordHash;
                using (var sha256 = SHA256.Create())
                {
                    var bytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(txtPassword.Text));
                    passwordHash = Convert.ToBase64String(bytes);
                }

                // 3. Send Login/Register packet using typed DTO
                var authPayload = new LoginRequestDTO
                {
                    Username = txtUsername.Text.Trim(),
                    PasswordHash = passwordHash
                };

                var data = PacketSerializer.ToJson(authPayload);
                var packet = new Packet(authType, null, null, data);

                var tcs = new TaskCompletionSource<Packet>();
                handler = p =>
                {
                    if (p.Type == PacketType.LoginResponse || p.Type == PacketType.RegisterResponse)
                    {
                        _tcpService.OnPacketReceived -= handler;
                        tcs.TrySetResult(p);
                    }
                };
                _tcpService.OnPacketReceived += handler;

                _tcpService.SendPacket(packet);
                lblStatus.Text = authType == PacketType.Login ? "Signing in..." : "Registering...";

                // 4. Wait for response (10s timeout)
                var timeoutTask = Task.Delay(10000);
                var completedTask = await Task.WhenAny(tcs.Task, timeoutTask);
                if (IsDisposed || Disposing) return;

                if (completedTask == timeoutTask)
                {
                    _tcpService.OnPacketReceived -= handler;
                    lblStatus.Text = "Timeout - Server did not respond";
                    lblStatus.ForeColor = System.Drawing.Color.Red;
                    return;
                }

                var response = await tcs.Task;

                // 5. Parse response via typed DTO
                var respDto = PacketSerializer.FromJson<LoginResponseDTO>(response.Data);
                if (respDto != null && respDto.Success)
                {
                    _pipeline.SetSessionCredentials(authPayload.Username, authPayload.PasswordHash);
                    LoggedInUserId = respDto.UserId;
                    LoggedInDisplayName = respDto.DisplayName;
                    this.DialogResult = DialogResult.OK;
                    this.Close();
                }
                else
                {
                    lblStatus.Text = respDto?.Message ?? "Authentication failed";
                    lblStatus.ForeColor = System.Drawing.Color.Red;
                }
            }
            catch (Exception ex)
            {
                if (!IsDisposed && !Disposing)
                {
                    lblStatus.Text = $"Error: {ex.Message}";
                    lblStatus.ForeColor = System.Drawing.Color.Red;
                }
            }
            finally
            {
                if (handler != null)
                {
                    _tcpService.OnPacketReceived -= handler;
                }

                if (!IsDisposed && !Disposing)
                {
                    btnLogin.Enabled = true;
                    btnRegister.Enabled = true;
                    pnlDemo.Enabled = true;
                }
            }
        }
    }
}
