using System;
using System.Windows.Forms;

namespace ZTalk.Client
{
    static class Program
    {
        [STAThread]
        static void Main(string[] args)
        {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);

            string autoLoginUser = args != null && args.Length > 0 ? args[0] : null;

            // 1. Hiển thị form đăng nhập
            using (var loginForm = new Forms.frmLogin(autoLoginUser))
            {
                var result = loginForm.ShowDialog();

                if (result == DialogResult.OK)
                {
                    // 2. Đăng nhập thành công → mở form chat với ConnectionPipeline (LAN/WAN + Auto-Reconnect)
                    Application.Run(new Forms.frmChat(
                        loginForm.TcpService,
                        loginForm.LoggedInUserId,
                        loginForm.LoggedInDisplayName,
                        loginForm.Pipeline));
                }
                else
                {
                    loginForm.Pipeline?.Dispose();
                    loginForm.TcpService?.Dispose();
                }
            }
        }
    }
}
