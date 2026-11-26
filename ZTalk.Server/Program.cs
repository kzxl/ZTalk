using System;
using System.IO;
using System.Threading;
using System.Windows.Forms;
using ZTalk.Server.Config;
using ZTalk.Server.Data;
using ZTalk.Server.Services;
using ZTalk.Shared.Network;

namespace ZTalk.Server
{
    static class Program
    {
        [STAThread]
        static void Main(string[] args)
        {
            if (args != null && args.Length > 0)
            {
                if (HasFlag(args, "--gen-cert"))
                {
                    RunGenCertCommand(args);
                    return;
                }

                if (HasFlag(args, "--create-user"))
                {
                    RunCreateUserCommand(args);
                    return;
                }

                if (HasFlag(args, "--edge-relay"))
                {
                    RunEdgeRelayServer(args);
                    return;
                }

                if (HasFlag(args, "--headless"))
                {
                    RunHeadlessServer(args);
                    return;
                }
            }

            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);

            bool autoStart = args != null && HasFlag(args, "autostart");
            bool forceTls = args != null && HasFlag(args, "--tls");

            Application.Run(new Forms.frmServer(autoStart, forceTls));
        }

        private static void RunEdgeRelayServer(string[] args)
        {
            int publicPort = ParseIntArg(args, "--public-port", 443);
            int controlPort = ParseIntArg(args, "--control-port", 8443);
            string secret = GetArgValue(args, "--secret") ?? Environment.GetEnvironmentVariable("ZTALK_TUNNEL_SECRET");
            if (string.IsNullOrWhiteSpace(secret))
            {
                Console.WriteLine("Usage: ZTalk.Server.exe --edge-relay --secret <shared-secret> [--public-port 443] [--control-port 8443] [--cert certs\\edge-control.pfx] [--password \"\"] [--cn edge.congty.vn]");
                return;
            }

            string certPath = GetArgValue(args, "--cert")
                ?? Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "certs", "edge-control.pfx");
            string certPassword = GetArgValue(args, "--password") ?? "";
            string cn = GetArgValue(args, "--cn") ?? "ZTalk-EdgeRelay";

            var cert = File.Exists(certPath)
                ? TlsHelper.LoadCertificate(certPath, certPassword)
                : TlsHelper.GenerateAndSaveSelfSignedPfx(certPath, certPassword, cn);

            using (var relay = new EdgeRelayServer(publicPort, controlPort, secret, cert, ownsCert: true))
            using (var shutdownSignal = new ManualResetEventSlim(false))
            {
                relay.OnLog += msg => Console.WriteLine(msg);
                Console.CancelKeyPress += (s, e) =>
                {
                    e.Cancel = true;
                    shutdownSignal.Set();
                };
                AppDomain.CurrentDomain.ProcessExit += (s, e) => shutdownSignal.Set();

                relay.Start();
                shutdownSignal.Wait();
                relay.Stop();
            }
        }

        private static int ParseIntArg(string[] args, string flag, int defaultValue)
        {
            int parsed;
            return int.TryParse(GetArgValue(args, flag), out parsed) && parsed > 0 && parsed <= 65535
                ? parsed
                : defaultValue;
        }

        private static void RunHeadlessServer(string[] args)
        {
            var config = ServerSecurityConfig.LoadOrDefault(enterpriseDefault: true);
            if (HasFlag(args, "--tls")) config.EnableTls = true;
            if (HasFlag(args, "--no-tls")) config.EnableTls = false;

            string portArg = GetArgValue(args, "--port");
            int parsedPort;
            if (int.TryParse(portArg, out parsedPort) && parsedPort > 0 && parsedPort <= 65535)
                config.Port = parsedPort;

            var userStore = new UserStore(seedDemoUsers: config.SeedDemoUsers);
            using (var server = new TcpServerService(userStore, config))
            using (var shutdownSignal = new ManualResetEventSlim(false))
            {
                server.OnLog += msg => Console.WriteLine(msg);
                Console.CancelKeyPress += (s, e) =>
                {
                    e.Cancel = true;
                    shutdownSignal.Set();
                };
                AppDomain.CurrentDomain.ProcessExit += (s, e) => shutdownSignal.Set();

                server.Start(config.Port);
                shutdownSignal.Wait();
                server.Stop();
            }
        }

        private static void RunCreateUserCommand(string[] args)
        {
            int idx = FindFlagIndex(args, "--create-user");
            if (idx < 0 || idx + 2 >= args.Length)
            {
                Console.WriteLine("Usage: ZTalk.Server.exe --create-user <username> <password> [displayName]");
                return;
            }

            string username = args[idx + 1];
            string password = args[idx + 2];
            string displayName = idx + 3 < args.Length ? args[idx + 3] : username;

            var config = ServerSecurityConfig.LoadOrDefault(enterpriseDefault: true);
            var store = new UserStore(seedDemoUsers: config.SeedDemoUsers);
            var account = store.ProvisionAccount(username, password, displayName);
            Console.WriteLine($"Provisioned user '{account.Username}' (ID: {account.UserId}, DisplayName: {account.DisplayName})");
        }

        private static void RunGenCertCommand(string[] args)
        {
            var config = ServerSecurityConfig.LoadOrDefault(enterpriseDefault: true);
            string cn = GetArgValue(args, "--cn") ?? config.TlsSubjectCn;
            string pfxPath = GetArgValue(args, "--out") ?? config.ResolveCertPath();
            string password = GetArgValue(args, "--password") ?? config.TlsCertPassword;

            using (var cert = TlsHelper.GenerateAndSaveSelfSignedPfx(pfxPath, password, cn))
            {
                string thumbprint = TlsHelper.GetCertSha256Thumbprint(cert);
                Console.WriteLine($"Certificate saved: {Path.GetFullPath(pfxPath)}");
                Console.WriteLine($"SHA-256 Pin Thumbprint: {thumbprint}");
            }
        }

        private static bool HasFlag(string[] args, string flag)
        {
            return FindFlagIndex(args, flag) >= 0;
        }

        private static int FindFlagIndex(string[] args, string flag)
        {
            if (args == null) return -1;
            for (int i = 0; i < args.Length; i++)
            {
                if (string.Equals(args[i], flag, StringComparison.OrdinalIgnoreCase))
                    return i;
            }
            return -1;
        }

        private static string GetArgValue(string[] args, string flag)
        {
            int idx = FindFlagIndex(args, flag);
            return (idx >= 0 && idx + 1 < args.Length) ? args[idx + 1] : null;
        }
    }
}
