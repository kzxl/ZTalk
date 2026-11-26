using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using ZTalk.Client.Services;
using ZTalk.Server.Config;
using ZTalk.Server.Data;
using ZTalk.Server.Services;
using ZTalk.Shared.Crypto;
using ZTalk.Shared.DTOs;
using ZTalk.Shared.Network;
using ZTalk.Shared.Protocol;

namespace ZTalk.Tests
{
    public static class SecurityTests
    {
        public static void RunAll()
        {
            TestAesEncryptThenMacRejectsTampering();
            TestPasswordHasherSaltingAndLegacyMigration();
            TestAuthRateLimiterLockoutAndReset();
            TestAuditLoggerWritesEntries();
            TestEndToEndTlsPinningAndEnterpriseGates();
        }

        private static void TestAesEncryptThenMacRejectsTampering()
        {
            var aes = new AesHelper();
            byte[] key = AesHelper.GenerateRandomKey();
            byte[] wrongKey = AesHelper.GenerateRandomKey();
            byte[] plain = Encoding.UTF8.GetBytes("Confidential quarterly report #2026");

            byte[] encrypted = aes.EncryptBytes(plain, key);

            // Flip a bit in ciphertext body
            byte[] tamperedCipher = (byte[])encrypted.Clone();
            tamperedCipher[20] ^= 0x01;
            AssertThrowsCrypto(() => aes.DecryptBytes(tamperedCipher, key), "Tampered ciphertext must fail MAC verification");

            // Flip a bit in IV
            byte[] tamperedIv = (byte[])encrypted.Clone();
            tamperedIv[5] ^= 0x80;
            AssertThrowsCrypto(() => aes.DecryptBytes(tamperedIv, key), "Tampered IV must fail MAC verification");

            // Flip a bit in HMAC tag
            byte[] tamperedMac = (byte[])encrypted.Clone();
            tamperedMac[tamperedMac.Length - 1] ^= 0xFF;
            AssertThrowsCrypto(() => aes.DecryptBytes(tamperedMac, key), "Tampered MAC must fail verification");

            // Wrong key
            AssertThrowsCrypto(() => aes.DecryptBytes(encrypted, wrongKey), "Wrong key must fail MAC verification");

            // Untampered decrypts identically
            byte[] decrypted = aes.DecryptBytes(encrypted, key);
            Assert.Equal(Encoding.UTF8.GetString(plain), Encoding.UTF8.GetString(decrypted));
        }

        private static void AssertThrowsCrypto(Action action, string message)
        {
            bool threw = false;
            try { action(); }
            catch (CryptographicException) { threw = true; }
            Assert.True(threw, message);
        }

        private static void TestPasswordHasherSaltingAndLegacyMigration()
        {
            string h1 = PasswordHasher.Hash("MySecretPass123!");
            string h2 = PasswordHasher.Hash("MySecretPass123!");

            Assert.False(h1 == h2, "PBKDF2 hashes of identical secret must use unique random salts");
            Assert.True(h1.StartsWith("pbkdf2$sha256$", StringComparison.Ordinal));
            Assert.True(PasswordHasher.Verify("MySecretPass123!", h1));
            Assert.False(PasswordHasher.Verify("WrongPass", h1));
            Assert.False(PasswordHasher.NeedsRehash(h1));

            // Test legacy unsalted SHA-256 migration in UserStore
            string tempDb = Path.Combine(Path.GetTempPath(), $"users_mig_{Guid.NewGuid():N}.json");
            try
            {
                string legacyHash = UserStore.HashPassword("legacyPass");
                File.WriteAllText(tempDb,
                    "[{\"UserId\":\"u_leg\",\"Username\":\"legacy\",\"PasswordHash\":\"" + legacyHash + "\",\"DisplayName\":\"Legacy User\"}]",
                    Encoding.UTF8);

                var store = new UserStore(tempDb, seedDemoUsers: false);
                Assert.True(store.GetByUsername("alice") == null, "Demo accounts must not be seeded when seedDemoUsers=false");

                var authUser = store.Authenticate("legacy", legacyHash);
                Assert.NotNull(authUser, "Legacy user must authenticate during migration");
                Assert.True(authUser.PasswordHash.StartsWith("pbkdf2$sha256$", StringComparison.Ordinal),
                    "Successful login must auto-upgrade legacy hash to salted PBKDF2-SHA256");

                // Reload from disk and verify upgraded PBKDF2 hash still authenticates
                var reloaded = new UserStore(tempDb, seedDemoUsers: false);
                Assert.NotNull(reloaded.Authenticate("legacy", legacyHash));
            }
            finally
            {
                if (File.Exists(tempDb)) File.Delete(tempDb);
            }
        }

        private static void TestAuthRateLimiterLockoutAndReset()
        {
            var limiter = new AuthRateLimiter(maxFailures: 3, lockoutMinutes: 5);
            TimeSpan remaining;

            Assert.False(limiter.IsLockedOut("alice", "10.0.0.5", out remaining));
            limiter.RecordFailure("alice", "10.0.0.5");
            limiter.RecordFailure("alice", "10.0.0.5");
            Assert.False(limiter.IsLockedOut("alice", "10.0.0.5", out remaining));

            limiter.RecordFailure("alice", "10.0.0.5");
            Assert.True(limiter.IsLockedOut("alice", "10.0.0.5", out remaining), "3rd failure must trigger lockout");
            Assert.True(remaining.TotalSeconds > 0);

            limiter.RecordSuccess("alice", "10.0.0.5");
            Assert.False(limiter.IsLockedOut("alice", "10.0.0.5", out remaining), "Successful login must clear lockout state");
        }

        private static void TestAuditLoggerWritesEntries()
        {
            string tempLogDir = Path.Combine(Path.GetTempPath(), $"ztalk_audit_{Guid.NewGuid():N}");
            try
            {
                using (var logger = new AuditLogger(tempLogDir))
                {
                    logger.Write("LOGIN_OK", "user=corp_user ip=127.0.0.1 tls=True");
                }

                var files = Directory.GetFiles(tempLogDir, "audit-*.log");
                Assert.True(files.Length == 1, "AuditLogger must create daily audit log file");
                string content = File.ReadAllText(files[0], Encoding.UTF8);
                Assert.True(content.Contains("[LOGIN_OK]") && content.Contains("user=corp_user"));
            }
            finally
            {
                if (Directory.Exists(tempLogDir)) Directory.Delete(tempLogDir, true);
            }
        }

        private static void TestEndToEndTlsPinningAndEnterpriseGates()
        {
            string tempDir = Path.Combine(Path.GetTempPath(), $"ztalk_tls_e2e_{Guid.NewGuid():N}");
            Directory.CreateDirectory(tempDir);
            string userDb = Path.Combine(tempDir, "users.json");
            string logDir = Path.Combine(tempDir, "logs");

            int port = GetFreeTcpPort();
            var userStore = new UserStore(userDb, seedDemoUsers: false);
            userStore.ProvisionAccount("corp_alice", "StrongPass!2026", "Alice Corp");

            var config = new ServerSecurityConfig
            {
                Port = port,
                EnableTls = true,
                AllowPublicRegistration = false,
                SeedDemoUsers = false,
                MaxConnections = 10,
                MaxConnectionsPerIp = 10,
                AuthTimeoutSeconds = 10,
                MaxFailedLoginAttempts = 2,
                LockoutMinutes = 5,
                AuditLogDirectory = logDir
            };

            using (var serverCert = TlsHelper.CreateSelfSignedCertificate("localhost"))
            using (var server = new TcpServerService(userStore, config, serverCert))
            {
                server.Start(port);
                Assert.True(server.IsTlsEnabled, "Server must report TLS enabled");
                Assert.NotNull(server.ActiveTlsThumbprint, "Server must expose active SHA-256 certificate pin");

                // 1. Wrong certificate pin MUST be rejected
                using (var badPinClient = new TcpClientService())
                {
                    string wrongPin = new string('A', 64);
                    bool connected = badPinClient.ConnectAsync("127.0.0.1", port, useTls: true, pinnedCertSha256: wrongPin, tlsTargetHost: "localhost", connectTimeoutMs: 3000)
                        .GetAwaiter().GetResult();
                    Assert.False(connected, "Client with mismatched SHA-256 certificate pin must reject server");
                }

                // 2. Matching SHA-256 pin MUST succeed over TLS 1.2
                using (var client = new TcpClientService())
                {
                    bool connected = client.ConnectAsync("127.0.0.1", port, useTls: true, pinnedCertSha256: server.ActiveTlsThumbprint, tlsTargetHost: "localhost", connectTimeoutMs: 5000)
                        .GetAwaiter().GetResult();
                    Assert.True(connected, "Client with matching SHA-256 pin must establish TLS 1.2 connection");
                    Assert.True(client.IsTlsActive, "Client must report active TLS transport");

                    // 3. Public registration MUST be blocked when AllowPublicRegistration = false
                    var regResp = SendAndAwaitResponse(client,
                        new Packet(PacketType.Register, null, null, PacketSerializer.ToJson(new LoginRequestDTO
                        {
                            Username = "intruder",
                            PasswordHash = UserStore.HashPassword("123456")
                        })),
                        PacketType.RegisterResponse);
                    var regDto = PacketSerializer.FromJson<LoginResponseDTO>(regResp.Data);
                    Assert.NotNull(regDto);
                    Assert.False(regDto.Success, "Public registration must be blocked in enterprise mode");

                    // 4. Failed logins trigger brute-force lockout (MaxFailedLoginAttempts = 2)
                    var fail1 = SendAndAwaitResponse(client,
                        new Packet(PacketType.Login, null, null, PacketSerializer.ToJson(new LoginRequestDTO
                        {
                            Username = "corp_alice",
                            PasswordHash = UserStore.HashPassword("wrong1")
                        })),
                        PacketType.LoginResponse);
                    Assert.False(PacketSerializer.FromJson<LoginResponseDTO>(fail1.Data).Success);

                    var fail2 = SendAndAwaitResponse(client,
                        new Packet(PacketType.Login, null, null, PacketSerializer.ToJson(new LoginRequestDTO
                        {
                            Username = "corp_alice",
                            PasswordHash = UserStore.HashPassword("wrong2")
                        })),
                        PacketType.LoginResponse);
                    Assert.False(PacketSerializer.FromJson<LoginResponseDTO>(fail2.Data).Success);

                    // 3rd attempt even with VALID password must be rejected due to active lockout
                    var lockedResp = SendAndAwaitResponse(client,
                        new Packet(PacketType.Login, null, null, PacketSerializer.ToJson(new LoginRequestDTO
                        {
                            Username = "corp_alice",
                            PasswordHash = UserStore.HashPassword("StrongPass!2026")
                        })),
                        PacketType.LoginResponse);
                    var lockedDto = PacketSerializer.FromJson<LoginResponseDTO>(lockedResp.Data);
                    Assert.False(lockedDto.Success, "Locked account must be rejected even with valid password");
                    Assert.True(lockedDto.Message.Contains("khóa"), "Response should indicate lockout");
                }

                // 5. Provisioned user login succeeds cleanly over TLS (fresh user not locked)
                userStore.ProvisionAccount("corp_bob", "BobPass!2026", "Bob Corp");
                // Use separate IP-independent server instance or verify directly with clean limiter
                server.Stop();
            }

            // Fresh server test for clean valid TLS login
            int port2 = GetFreeTcpPort();
            config.Port = port2;
            using (var serverCert2 = TlsHelper.CreateSelfSignedCertificate("localhost"))
            using (var server2 = new TcpServerService(userStore, config, serverCert2))
            {
                server2.Start(port2);
                using (var client2 = new TcpClientService())
                {
                    bool connected = client2.ConnectAsync("127.0.0.1", port2, useTls: true, pinnedCertSha256: server2.ActiveTlsThumbprint, tlsTargetHost: "localhost", connectTimeoutMs: 5000)
                        .GetAwaiter().GetResult();
                    Assert.True(connected);

                    var loginResp = SendAndAwaitResponse(client2,
                        new Packet(PacketType.Login, null, null, PacketSerializer.ToJson(new LoginRequestDTO
                        {
                            Username = "corp_bob",
                            PasswordHash = UserStore.HashPassword("BobPass!2026")
                        })),
                        PacketType.LoginResponse);
                    var loginDto = PacketSerializer.FromJson<LoginResponseDTO>(loginResp.Data);
                    Assert.NotNull(loginDto);
                    Assert.True(loginDto.Success, "Valid provisioned user must authenticate over TLS 1.2");
                    Assert.Equal("Bob Corp", loginDto.DisplayName);
                }
                server2.Stop();
            }

            try
            {
                if (Directory.Exists(tempDir)) Directory.Delete(tempDir, true);
            }
            catch { }
        }

        private static Packet SendAndAwaitResponse(TcpClientService client, Packet request, PacketType expectedType)
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
