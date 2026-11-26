using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using ZTalk.Client.Services;
using ZTalk.Server.Config;
using ZTalk.Server.Data;
using ZTalk.Server.Services;
using ZTalk.Shared.Constants;
using ZTalk.Shared.Crypto;
using ZTalk.Shared.DTOs;
using ZTalk.Shared.Network;
using ZTalk.Shared.Protocol;

namespace ZTalk.Tests
{
    public static class EnterpriseTests
    {
        public static void RunAll()
        {
            TestDiskStreamingFileReceiveAndPartCleanup();
            TestServerStorageEncryptionAtRest();
            TestDpapiClientHistoryEncryptionAtRest();
            TestEndToEndOfflineMessageQueueOverTls();
        }

        private static void TestDiskStreamingFileReceiveAndPartCleanup()
        {
            string tempDir = Path.Combine(Path.GetTempPath(), $"ztalk_part_{Guid.NewGuid():N}");
            try
            {
                // 210 KB payload split into 4 chunks (64KB, 64KB, 64KB, 18KB)
                int payloadSize = 210 * 1024;
                var original = new byte[payloadSize];
                new Random(2026).NextBytes(original);

                int chunkSize = AppConstants.FileChunkSize;
                int totalChunks = (int)Math.Ceiling((double)payloadSize / chunkSize);

                using (var receiver = new FileReceiveService(tempDir))
                {
                    string transferId = "stream_210k";
                    receiver.HandleFileHeader("u1", "Alice", "quarterly_deck.bin", payloadSize, totalChunks, transferId);

                    // Verify .part file is created on disk
                    string partDir = Path.Combine(tempDir, ".part");
                    Assert.True(Directory.GetFiles(partDir, "*.part").Length == 1, "Active transfer must stream into a .part file on disk");

                    // Deliver chunks completely out-of-order: 3, 1, 0, 2
                    int[] order = { 3, 1, 0, 2 };
                    foreach (int idx in order)
                    {
                        int offset = idx * chunkSize;
                        int len = Math.Min(chunkSize, payloadSize - offset);
                        var chunk = new byte[len];
                        Buffer.BlockCopy(original, offset, chunk, 0, len);
                        receiver.HandleFileChunk(transferId, idx, chunk);
                    }

                    string savedPath = receiver.HandleFileComplete(transferId);
                    Assert.NotNull(savedPath, "Completed disk-streamed file must return valid path");
                    Assert.True(Directory.GetFiles(partDir, "*.part").Length == 0, ".part file must be moved/removed on completion");

                    byte[] restored = File.ReadAllBytes(savedPath);
                    Assert.Equal(original.Length, restored.Length);
                    for (int i = 0; i < original.Length; i++)
                    {
                        if (original[i] != restored[i])
                            throw new Exception($"Byte mismatch at offset {i}");
                    }

                    // Test stale transfer cleanup removes abandoned .part file
                    receiver.HandleFileHeader("u1", "Alice", "abandoned.bin", 1024, 1, "abandoned_01");
                    Assert.Equal(1, receiver.ActiveTransferCount);
                    Thread.Sleep(25);
                    int cleaned = receiver.CleanupStaleTransfers(TimeSpan.FromMilliseconds(1));
                    Assert.Equal(1, cleaned, "CleanupStaleTransfers must evict abandoned transfer");
                    Assert.Equal(0, receiver.ActiveTransferCount);
                    Assert.True(Directory.GetFiles(partDir, "*.part").Length == 0, "Abandoned .part file must be deleted from disk");
                }
            }
            finally
            {
                try { if (Directory.Exists(tempDir)) Directory.Delete(tempDir, true); } catch { }
            }
        }

        private static void TestServerStorageEncryptionAtRest()
        {
            string tempDir = Path.Combine(Path.GetTempPath(), $"ztalk_enc_store_{Guid.NewGuid():N}");
            try
            {
                string keyPath = Path.Combine(tempDir, "storage.key");
                byte[] storageKey = StorageCipher.LoadOrCreateProtectedKey(keyPath);
                Assert.True(File.Exists(keyPath), "DPAPI-protected storage key must be persisted");
                Assert.Equal(32, storageKey.Length);

                // Reload key via DPAPI and ensure identical 256-bit key
                byte[] reloadedKey = StorageCipher.LoadOrCreateProtectedKey(keyPath);
                Assert.True(PasswordHasher.FixedTimeEquals(storageKey, reloadedKey), "Reloaded DPAPI key must match original");

                string dataDir = Path.Combine(tempDir, "ChatData");
                var store = new MessageStore(dataDir, storageKey);
                store.SaveMessage("alice", "bob", "Alice", "TopSecret-Payroll-2026", false, isEncrypted: false);

                // Inspect raw file on disk: must be AEAD ciphertext, never plaintext
                var files = Directory.GetFiles(dataDir, "*.json");
                Assert.Equal(1, files.Length);
                string rawOnDisk = File.ReadAllText(files[0], Encoding.UTF8);
                Assert.True(rawOnDisk.StartsWith(StorageCipher.AeadPrefix, StringComparison.Ordinal),
                    "Encrypted MessageStore file must carry AEAD prefix");
                Assert.False(rawOnDisk.Contains("TopSecret-Payroll-2026"),
                    "Plaintext message must never appear on disk when storage encryption is enabled");

                // Cold reload with same key decrypts identically
                var coldStore = new MessageStore(dataDir, reloadedKey);
                var history = coldStore.GetHistory("alice", "bob");
                Assert.Equal(1, history.Count);
                Assert.Equal("TopSecret-Payroll-2026", history[0].Content);
            }
            finally
            {
                try { if (Directory.Exists(tempDir)) Directory.Delete(tempDir, true); } catch { }
            }
        }

        private static void TestDpapiClientHistoryEncryptionAtRest()
        {
            string tempDir = Path.Combine(Path.GetTempPath(), $"ztalk_dpapi_hist_{Guid.NewGuid():N}");
            try
            {
                var historySvc = new MessageHistoryService(tempDir, encryptAtRest: true);
                historySvc.SaveMessage("user_bob", "user_alice", "Alice", "Confidential-M&A-Plan-2026", false);

                var files = Directory.GetFiles(tempDir, "history_*.json");
                Assert.Equal(1, files.Length);
                string rawOnDisk = File.ReadAllText(files[0], Encoding.UTF8);
                Assert.True(rawOnDisk.StartsWith(StorageCipher.DpapiPrefix, StringComparison.Ordinal),
                    "Local history line must be DPAPI protected");
                Assert.False(rawOnDisk.Contains("Confidential-M&A-Plan-2026"),
                    "Local history on disk must not expose plaintext");

                var restored = historySvc.GetHistory("user_bob");
                Assert.Equal(1, restored.Count);
                Assert.Equal("Confidential-M&A-Plan-2026", restored[0].Content);
            }
            finally
            {
                try { if (Directory.Exists(tempDir)) Directory.Delete(tempDir, true); } catch { }
            }
        }

        private static void TestEndToEndOfflineMessageQueueOverTls()
        {
            string tempDir = Path.Combine(Path.GetTempPath(), $"ztalk_offline_{Guid.NewGuid():N}");
            Directory.CreateDirectory(tempDir);

            int port = GetFreeTcpPort();
            var userStore = new UserStore(Path.Combine(tempDir, "users.json"), seedDemoUsers: false);
            var aliceAcc = userStore.ProvisionAccount("alice_off", "AlicePass!2026", "Alice Corp");
            var bobAcc = userStore.ProvisionAccount("bob_off", "BobPass!2026", "Bob Corp");

            var config = new ServerSecurityConfig
            {
                Port = port,
                EnableTls = true,
                AllowPublicRegistration = false,
                SeedDemoUsers = false,
                EnableStorageEncryption = true,
                StorageKeyPath = Path.Combine(tempDir, "storage.key"),
                OfflineQueueDirectory = Path.Combine(tempDir, "OfflineQueue"),
                AuditLogDirectory = Path.Combine(tempDir, "Logs")
            };

            using (var cert = TlsHelper.CreateSelfSignedCertificate("localhost"))
            using (var server = new TcpServerService(userStore, config, cert))
            {
                server.Start(port);

                // 1. Alice logs in while Bob is OFFLINE and sends Bob a message
                using (var aliceClient = new TcpClientService())
                {
                    bool ok = aliceClient.ConnectAsync("127.0.0.1", port, useTls: true, pinnedCertSha256: server.ActiveTlsThumbprint, tlsTargetHost: "localhost")
                        .GetAwaiter().GetResult();
                    Assert.True(ok);

                    var loginResp = SendAndAwait(aliceClient,
                        new Packet(PacketType.Login, null, null, PacketSerializer.ToJson(new LoginRequestDTO
                        {
                            Username = "alice_off",
                            PasswordHash = UserStore.HashPassword("AlicePass!2026")
                        })),
                        PacketType.LoginResponse);
                    Assert.True(PacketSerializer.FromJson<LoginResponseDTO>(loginResp.Data).Success);

                    var msgDto = new MessageDTO { Content = "Hey Bob, review Q4 budget!", IsEncrypted = false };
                    aliceClient.SendPacket(new Packet(PacketType.Message, aliceAcc.UserId, bobAcc.UserId, PacketSerializer.ToJson(msgDto)));

                    // Give server brief moment to persist queued message before Alice disconnects
                    Thread.Sleep(250);
                }

                // 2. Bob comes online later (Alice already disconnected) -> must automatically receive queued message!
                using (var bobClient = new TcpClientService())
                {
                    var receivedOfflineMsg = new TaskCompletionSource<Packet>();
                    bobClient.OnPacketReceived += p =>
                    {
                        if (p.Type == PacketType.Message)
                            receivedOfflineMsg.TrySetResult(p);
                    };

                    bool ok = bobClient.ConnectAsync("127.0.0.1", port, useTls: true, pinnedCertSha256: server.ActiveTlsThumbprint, tlsTargetHost: "localhost")
                        .GetAwaiter().GetResult();
                    Assert.True(ok);

                    var loginResp = SendAndAwait(bobClient,
                        new Packet(PacketType.Login, null, null, PacketSerializer.ToJson(new LoginRequestDTO
                        {
                            Username = "bob_off",
                            PasswordHash = UserStore.HashPassword("BobPass!2026")
                        })),
                        PacketType.LoginResponse);
                    Assert.True(PacketSerializer.FromJson<LoginResponseDTO>(loginResp.Data).Success);

                    Assert.True(receivedOfflineMsg.Task.Wait(4000), "Bob must automatically receive offline queued message upon login");
                    var deliveredDto = PacketSerializer.FromJson<MessageDTO>(receivedOfflineMsg.Task.Result.Data);
                    Assert.NotNull(deliveredDto);
                    Assert.Equal("Hey Bob, review Q4 budget!", deliveredDto.Content);
                    Assert.Equal(aliceAcc.UserId, receivedOfflineMsg.Task.Result.SenderId);
                }

                server.Stop();
            }

            try { if (Directory.Exists(tempDir)) Directory.Delete(tempDir, true); } catch { }
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
