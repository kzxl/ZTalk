using System;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using System.Windows.Forms;
using ZTalk.Server.Config;
using ZTalk.Server.Data;
using ZTalk.Server.Services;
using ZTalk.Shared.Network;

namespace ZTalk.Server.Forms
{
    /// <summary>
    /// Server dashboard - monitors server status, active connections, and activity logs.
    /// </summary>
    public partial class frmServer : Form
    {
        private const int MaxLogChars = 60000;

        private readonly ServerSecurityConfig _securityConfig;
        private readonly TcpServerService _serverService;
        private readonly UserStore _userStore;
        private readonly bool _autoStart;
        private readonly string _cachedLocalIp;

        public frmServer(bool autoStart = false, bool forceTls = false)
        {
            InitializeComponent();
            _autoStart = autoStart;
            _securityConfig = ServerSecurityConfig.LoadOrDefault(enterpriseDefault: false);
            if (forceTls)
                _securityConfig.EnableTls = true;

            _userStore = new UserStore(seedDemoUsers: _securityConfig.SeedDemoUsers);
            _serverService = new TcpServerService(_userStore, _securityConfig);

            // Subscribe events
            _serverService.OnLog += AppendLog;
            _serverService.OnClientListChanged += RefreshClientList;

            // Cache local IP once instead of creating a UDP socket every second in tmrStats_Tick
            _cachedLocalIp = StunClient.GetLocalIPAddress()?.ToString() ?? "127.0.0.1";
            if (_securityConfig.Port > 0 && _securityConfig.Port <= 65535)
                nudPort.Value = _securityConfig.Port;

            string tlsTag = _securityConfig.EnableTls ? "🔒 TLS" : "🔓 Plain";
            lblStats.Text = $"⏱ Uptime: --:--:-- | 📦 Routed Packets: 0 | {tlsTag} | 🌐 Local IP: {_cachedLocalIp}:{(int)nudPort.Value}";
        }

        protected override void OnShown(EventArgs e)
        {
            base.OnShown(e);
            if (_autoStart)
            {
                btnStart_Click(this, EventArgs.Empty);
            }
        }

        private void btnStart_Click(object sender, EventArgs e)
        {
            try
            {
                int port = (int)nudPort.Value;
                _serverService.Start(port);

                btnStart.Enabled = false;
                btnStop.Enabled = true;
                nudPort.Enabled = false;
                lblStatus.Text = "● Server Running";
                lblStatus.ForeColor = System.Drawing.Color.LimeGreen;

                tmrStats.Start();
                tmrStats_Tick(this, EventArgs.Empty);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Cannot start server: {ex.Message}",
                    "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void btnStop_Click(object sender, EventArgs e)
        {
            tmrStats.Stop();
            _serverService.Stop();
            btnStart.Enabled = true;
            btnStop.Enabled = false;
            nudPort.Enabled = true;
            lblStatus.Text = "● Server Stopped";
            lblStatus.ForeColor = System.Drawing.Color.Gray;
            RefreshClientList();
            lblStats.Text = "⏱ Uptime: --:--:-- | 📦 Routed Packets: 0 | 🌐 Server Stopped";
        }

        private void AppendLog(string message)
        {
            if (IsDisposed || Disposing || !IsHandleCreated) return;

            if (txtLog.InvokeRequired)
            {
                try
                {
                    txtLog.BeginInvoke(new Action<string>(AppendLog), message);
                }
                catch (ObjectDisposedException) { }
                catch (InvalidOperationException) { }
                return;
            }

            // Cap log buffer to avoid unbounded UI memory growth on long-running server
            if (txtLog.TextLength > MaxLogChars)
            {
                txtLog.Select(0, txtLog.TextLength / 2);
                txtLog.SelectedText = string.Empty;
            }

            txtLog.AppendText(message + Environment.NewLine);
            txtLog.ScrollToCaret();
        }

        private void RefreshClientList()
        {
            if (IsDisposed || Disposing || !IsHandleCreated) return;

            if (lvClients.InvokeRequired)
            {
                try
                {
                    lvClients.BeginInvoke(new Action(RefreshClientList));
                }
                catch (ObjectDisposedException) { }
                catch (InvalidOperationException) { }
                return;
            }

            lvClients.BeginUpdate();
            try
            {
                lvClients.Items.Clear();

                var clients = _serverService.GetClientsSnapshot();
                int authenticatedCount = 0;

                foreach (var client in clients)
                {
                    if (client.IsAuthenticated) authenticatedCount++;

                    var item = new ListViewItem(client.IsAuthenticated ? "🟢 Online" : "🟡 Connecting");
                    item.Tag = client.UserId;
                    item.SubItems.Add(client.Username ?? client.UserId);
                    item.SubItems.Add(client.DisplayName ?? "-");
                    item.SubItems.Add(client.EndPoint);
                    item.SubItems.Add(client.ConnectedAt.ToString("HH:mm:ss"));
                    item.SubItems.Add($"{client.PacketsReceived} / {client.PacketsSent}");

                    if (!client.IsAuthenticated)
                        item.ForeColor = System.Drawing.Color.Gold;

                    lvClients.Items.Add(item);
                }

                lblClients.Text = $"📡 Clients Online ({authenticatedCount})";
            }
            finally
            {
                lvClients.EndUpdate();
            }
        }

        private void tsmiKick_Click(object sender, EventArgs e)
        {
            if (lvClients.SelectedItems.Count == 0) return;

            var selectedItem = lvClients.SelectedItems[0];
            string userId = selectedItem.Tag as string;
            string userName = selectedItem.SubItems[1].Text;

            if (!string.IsNullOrEmpty(userId))
            {
                var confirm = MessageBox.Show(
                    $"Are you sure you want to disconnect client '{userName}'?",
                    "Confirm Disconnect", MessageBoxButtons.YesNo, MessageBoxIcon.Warning);

                if (confirm == DialogResult.Yes)
                {
                    _serverService.DisconnectClient(userId);
                    AppendLog($"[ADMIN] Disconnected client: {userName} (ID: {userId})");
                }
            }
        }

        private void tsmiRefresh_Click(object sender, EventArgs e)
        {
            RefreshClientList();
        }

        private void btnClearLog_Click(object sender, EventArgs e)
        {
            txtLog.Clear();
        }

        private async void btnLaunchClients_Click(object sender, EventArgs e)
        {
            try
            {
                string clientExe = ResolveClientExePath();
                if (clientExe == null)
                {
                    MessageBox.Show("ZTalk.Client.exe not found. Please build the solution first.",
                        "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    return;
                }

                // Launch Alice
                System.Diagnostics.Process.Start(clientExe, "demo_alice");
                AppendLog("[ADMIN] Dispatched launch command for 2 demo clients (Alice & Bob)");

                // Launch Bob after 400ms
                await Task.Delay(400);
                if (!IsDisposed)
                {
                    System.Diagnostics.Process.Start(clientExe, "demo_bob");
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error launching clients: {ex.Message}", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private static string ResolveClientExePath()
        {
            string[] candidates =
            {
                Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "ZTalk.Client.exe"),
                Path.GetFullPath(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, @"..\..\..\ZTalk.Client\bin\Release\ZTalk.Client.exe")),
                Path.GetFullPath(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, @"..\..\..\ZTalk.Client\bin\Debug\ZTalk.Client.exe"))
            };

            return candidates.FirstOrDefault(File.Exists);
        }

        private void tmrStats_Tick(object sender, EventArgs e)
        {
            if (_serverService.IsRunning && _serverService.StartTime.HasValue)
            {
                var uptime = DateTime.Now - _serverService.StartTime.Value;
                string uptimeStr = string.Format("{0:D2}:{1:D2}:{2:D2}", (int)uptime.TotalHours, uptime.Minutes, uptime.Seconds);
                lblStats.Text = $"⏱ Uptime: {uptimeStr} | 📦 Routed Packets: {_serverService.TotalMessagesRouted} | 👥 Connected: {_serverService.ConnectedCount} | 🌐 Local IP: {_cachedLocalIp}:{(int)nudPort.Value}";
            }
        }

        private void frmServer_FormClosing(object sender, FormClosingEventArgs e)
        {
            if (_serverService.IsRunning)
            {
                var result = MessageBox.Show(
                    "Server is running. Are you sure you want to stop and exit?",
                    "Confirm Exit", MessageBoxButtons.YesNo, MessageBoxIcon.Question);

                if (result == DialogResult.No)
                {
                    e.Cancel = true;
                    return;
                }
            }

            tmrStats.Stop();
            _serverService.OnLog -= AppendLog;
            _serverService.OnClientListChanged -= RefreshClientList;
            _serverService.Dispose();
        }
    }
}
