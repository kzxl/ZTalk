using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using ZTalk.Client.Config;
using ZTalk.Client.Services;
using ZTalk.Server.Config;
using ZTalk.Server.Data;
using ZTalk.Server.Services;
using ZTalk.Shared.DTOs;
using ZTalk.Shared.Network;
using ZTalk.Shared.Protocol;

namespace ZTalk.Tests
{
    public static class PipelineTests
    {
        public static void RunAll()
        {
            TestReverseTunnelRejectsUnauthorizedAgent();
            TestZeroTrustReverseTunnelDualEndpointLanToWanFailover();
            TestAutoReconnectWithTransparentReauthentication();
        }

        private static void TestReverseTunnelRejectsUnauthorizedAgent()
        {
            int publicPort = GetFreeTcpPort();
            int controlPort = GetFreeTcpPort();
            int dummyLocalPort = GetFreeTcpPort();

            using (var relayCert = TlsHelper.CreateSelfSignedCertificate("localhost"))
            using (var relay = new EdgeRelayServer(publicPort, controlPort, "Correct-Secret-2026", relayCert))
            {
                relay.Start();
                using (var rogueAgent = new ReverseTunnelAgent(
                    "127.0.0.1", controlPort, "Wrong-Secret", "127.0.0.1", dummyLocalPort,
                    relayCertPinSha256: relay.ControlCertThumbprint, relayTlsTargetHost: "localhost"))
                {
                    rogueAgent.Start();
                    Thread.Sleep(500);
                    Assert.False(relay.IsAgentConnected, "EdgeRelay must reject tunnel agent with wrong HMAC secret");
                    Assert.False(rogueAgent.IsControlConnected, "Unauthorized agent must not report connected");
                }
                relay.Stop();
            }
        }

        private static void TestZeroTrustReverseTunnelDualEndpointLanToWanFailover()
        {
            string tempDir = Path.Combine(Path.GetTempPath(), $"ztalk_pipe_{Guid.NewGuid():N}");
            Directory.CreateDirectory(tempDir);
            string userDb = Path.Combine(tempDir, "users.json");
            string logDir = Path.Combine(tempDir, "logs");

            int lanPort = GetFreeTcpPort();
            int deadLanPort = GetFreeTcpPort();
            int edgePublicPort = GetFreeTcpPort();
            int edgeControlPort = GetFreeTcpPort();
            const string tunnelSecret = "Corp-ZeroTrust-Tunnel-Secret-2026!";

            var userStore = new UserStore(userDb, seedDemoUsers: false);
            userStore.ProvisionAccount("remote_emp", "RemotePass!2026", "Remote Employee");

            // Distinct certificates: EdgeRelay VPS NEVER possesses lanServerCert's private key
            using (var edgeControlCert = TlsHelper.CreateSelfSignedCertificate("localhost"))
            using (var lanServerCert = TlsHelper.CreateSelfSignedCertificate("localhost"))
            using (var edgeRelay = new EdgeRelayServer(edgePublicPort, edgeControlPort, tunnelSecret, edgeControlCert))
            {
                edgeRelay.Start();

                var serverConfig = new ServerSecurityConfig
                {
                    Port = lanPort,
                    EnableTls = true,
                    AllowPublicRegistration = false,
                    SeedDemoUsers = false,
                    AuditLogDirectory = logDir,
                    EnableReverseTunnel = true,
                    EdgeRelayHost = "127.0.0.1",
                    EdgeRelayControlPort = edgeControlPort,
                    EdgeRelaySecret = tunnelSecret,
                    EdgeRelayCertPinSha256 = edgeRelay.ControlCertThumbprint
                };

                using (var server = new TcpServerService(userStore, serverConfig, lanServerCert))
                {
                    server.Start(lanPort);

                    // Wait for outbound reverse tunnel from LAN Server -> VPS EdgeRelay
                    Assert.True(WaitUntil(() => server.IsReverseTunnelConnected && edgeRelay.IsAgentConnected, 5000),
                        "LAN server must establish outbound TLS reverse tunnel to EdgeRelay");

                    // External client has unreachable LAN port as primary -> must automatically fail over to EdgeRelay WAN port
                    // AND validate TLS 1.2 SHA-256 pin against LAN Server's certificate directly (Zero-Trust E2E TLS)
                    var clientConfig = new ClientSecurityConfig
                    {
                        ServerHost = "127.0.0.1",
                        ServerPort = deadLanPort, // Unreachable LAN endpoint
                        FallbackServerHost = "127.0.0.1",
                        FallbackServerPort = edgePublicPort, // Public VPS EdgeRelay
                        LanConnectTimeoutMs = 400,
                        ConnectTimeoutMs = 4000,
                        UseTls = true,
                        TlsTargetHost = "localhost",
                        PinnedCertSha256 = server.ActiveTlsThumbprint, // Pinned to LAN server cert, NOT Edge cert
                        AutoReconnect = false
                    };

                    using (var tcpClient = new TcpClientService())
                    using (var pipeline = new ConnectionPipeline(tcpClient, clientConfig))
                    {
                        bool connected = pipeline.ConnectSmartAsync().GetAwaiter().GetResult();
                        Assert.True(connected, "Dual-Endpoint pipeline must fail over from dead LAN to WAN EdgeRelay");
                        Assert.True(pipeline.IsUsingFallback, "Pipeline must report active WAN Edge fallback route");
                        Assert.True(tcpClient.IsTlsActive, "Connection through EdgeRelay must preserve end-to-end TLS 1.2");

                        // Login over the zero-trust reverse tunnel
                        var loginResp = SendAndAwait(tcpClient,
                            new Packet(PacketType.Login, null, null, PacketSerializer.ToJson(new LoginRequestDTO
                            {
                                Username = "remote_emp",
                                PasswordHash = UserStore.HashPassword("RemotePass!2026")
                            })),
                            PacketType.LoginResponse);

                        var dto = PacketSerializer.FromJson<LoginResponseDTO>(loginResp.Data);
                        Assert.NotNull(dto);
                        Assert.True(dto.Success, "Remote employee must authenticate cleanly over reverse tunnel");
                        Assert.Equal("Remote Employee", dto.DisplayName);
                    }

                    server.Stop();
                }

                edgeRelay.Stop();
            }

            try { if (Directory.Exists(tempDir)) Directory.Delete(tempDir, true); } catch { }
        }

        private static void TestAutoReconnectWithTransparentReauthentication()
        {
            string tempDir = Path.Combine(Path.GetTempPath(), $"ztalk_reconn_{Guid.NewGuid():N}");
            Directory.CreateDirectory(tempDir);
            string userDb = Path.Combine(tempDir, "users.json");
            string logDir = Path.Combine(tempDir, "logs");

            int port = GetFreeTcpPort();
            var userStore = new UserStore(userDb, seedDemoUsers: false);
            userStore.ProvisionAccount("mobile_emp", "MobilePass!2026", "Mobile Employee");

            var serverConfig = new ServerSecurityConfig
            {
                Port = port,
                EnableTls = true,
                AllowPublicRegistration = false,
                SeedDemoUsers = false,
                AuditLogDirectory = logDir
            };

            using (var serverCert = TlsHelper.CreateSelfSignedCertificate("localhost"))
            using (var server = new TcpServerService(userStore, serverConfig, serverCert))
            {
                server.Start(port);

                var clientConfig = new ClientSecurityConfig
                {
                    ServerHost = "127.0.0.1",
                    ServerPort = port,
                    UseTls = true,
                    TlsTargetHost = "localhost",
                    PinnedCertSha256 = server.ActiveTlsThumbprint,
                    AutoReconnect = true,
                    ReconnectInitialDelayMs = 250,
                    ReconnectMaxDelayMs = 1000
                };

                using (var tcpClient = new TcpClientService())
                using (var pipeline = new ConnectionPipeline(tcpClient, clientConfig))
                {
                    bool connected = pipeline.ConnectSmartAsync().GetAwaiter().GetResult();
                    Assert.True(connected);

                    string passHash = UserStore.HashPassword("MobilePass!2026");
                    var loginResp = SendAndAwait(tcpClient,
                        new Packet(PacketType.Login, null, null, PacketSerializer.ToJson(new LoginRequestDTO
                        {
                            Username = "mobile_emp",
                            PasswordHash = passHash
                        })),
                        PacketType.LoginResponse);
                    var loginDto = PacketSerializer.FromJson<LoginResponseDTO>(loginResp.Data);
                    Assert.True(loginDto != null && loginDto.Success);

                    pipeline.SetSessionCredentials("mobile_emp", passHash);
                    var reconnectedEvent = new ManualResetEventSlim(false);
                    pipeline.OnReconnected += _ => reconnectedEvent.Set();
                    pipeline.EnableAutoReconnect();

                    // Simulate sudden network drop / server restart
                    server.Stop();
                    Thread.Sleep(250);
                    server.Start(port);

                    Assert.True(reconnectedEvent.Wait(6000), "ConnectionPipeline must auto-reconnect and re-authenticate after server restart");
                    Assert.True(tcpClient.IsConnected);

                    // Verify session is genuinely re-authenticated on server by sending Heartbeat -> UserList
                    var userListResp = SendAndAwait(tcpClient,
                        new Packet(PacketType.Heartbeat, loginDto.UserId, null, null),
                        PacketType.UserList);
                    Assert.NotNull(userListResp);
                    Assert.True(userListResp.Data != null && userListResp.Data.Contains("Mobile Employee"),
                        "Re-authenticated session must receive authenticated UserList after reconnect");
                }

                server.Stop();
            }

            try { if (Directory.Exists(tempDir)) Directory.Delete(tempDir, true); } catch { }
        }

        private static bool WaitUntil(Func<bool> predicate, int timeoutMs)
        {
            var deadline = DateTime.UtcNow.AddMilliseconds(timeoutMs);
            while (DateTime.UtcNow < deadline)
            {
                if (predicate()) return true;
                Thread.Sleep(30);
            }
            return predicate();
        }

        private static Packet SendAndAwait(TcpClientService client, Packet request, PacketType expectedType)
        {
            var tcs = new TaskCompletionSource<Packet>();
            Action<Packet> handler = null;
            handler = p =>
            {
                if (p.Type == expectedType)
                {
                    client.OnPacketReceived -= handler;
                    tcs.TrySetResult(p);
                }
            };
            client.OnPacketReceived += handler;
            client.SendPacket(request);

            if (!tcs.Task.Wait(5000))
            {
                client.OnPacketReceived -= handler;
                throw new TimeoutException($"Timed out waiting for {expectedType}");
            }
            return tcs.Task.Result;
        }

        private static int GetFreeTcpPort()
        {
            var listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();
            int port = ((IPEndPoint)listener.LocalEndpoint).Port;
            listener.Stop();
            return port;
        }
    }
}
