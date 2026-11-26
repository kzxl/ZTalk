# 🌌 ZTalk — Sovereign Enterprise Real-Time P2P & E2EE Communication Suite

[![Type: Desktop Application](https://img.shields.io/badge/Type-Desktop%20Application%20(Client%20%26%20Server)-007ACC?style=flat-square&logo=windows)](https://github.com/kzxl/ZTalk)
[![Ecosystem](https://img.shields.io/badge/Ecosystem-ZeroUniverse-8A2BE2?style=flat-square)](https://github.com/kzxl/ZeroUniverse)
[![Platform](https://img.shields.io/badge/Platform-Windows%20Forms%20%2B%20Headless%20Service-blueviolet.svg?style=flat-square)](https://dotnet.microsoft.com/)
[![Distribution](https://img.shields.io/badge/Distribution-Standalone%20Executables-2ea44f?style=flat-square)](https://github.com/kzxl/ZTalk)
[![.NET Framework 4.8](https://img.shields.io/badge/.NET%20Framework-4.8-blue.svg?style=flat-square)](https://dotnet.microsoft.com/)
[![Dependencies](https://img.shields.io/badge/NuGet-Zero%20Dependencies-brightgreen.svg?style=flat-square)]()
[![Tests](https://img.shields.io/badge/Tests-12%2F12%20Suites%20Passing-success?style=flat-square)]()
[![License](https://img.shields.io/badge/License-MIT-green.svg?style=flat-square)](LICENSE)

**ZTalk** is a sovereign, self-hosted real-time communication platform engineered for enterprise LANs and hybrid/remote teams (~100+ users). Operating with **zero external NuGet package dependencies**, it runs purely on C# and native .NET Framework 4.8 Base Class Libraries (BCL). Part of the **ZeroUniverse** ecosystem, it combines authenticated encryption, TLS 1.2 certificate pinning, a zero-trust reverse tunnel for external clients, offline message queuing, disk-streamed file transfers, and low-latency P2P multimedia streaming.

---

## 📸 Interface Showcase

| Real-Time Chat & Direct Messaging | P2P Video Call & Synthetic Camera HUD |
| :---: | :---: |
| ![Real-Time Chat](docs/images/client_chat.png) | ![Video Call HUD](docs/images/video_call.png) |

| Server Management & Telemetry Console | 1-Click Demo & Enterprise Authentication |
| :---: | :---: |
| ![Server Dashboard](docs/images/server_dashboard.png) | ![Login Screen](docs/images/login_screen.png) |

---

## 🌟 Key Capabilities

### 1. Enterprise Security Core (Zero Third-Party Dependencies)
- **TLS 1.2 Transport & SHA-256 Certificate Pinning (`TlsHelper`)**: Mandatory `SslStream` encryption with handshake timeouts, pure-BCL RSA-2048 self-signed X.509 certificate generation (`--gen-cert`), and strict SHA-256 thumbprint pinning on clients.
- **Authenticated End-to-End Encryption (`AesHelper`, `DiffieHellmanHelper`)**: Per-session ECDH P-256 key exchange paired with **Encrypt-then-MAC (`AES-256-CBC + HMAC-SHA256`)** using domain-separated encryption/authentication subkeys and constant-time MAC verification to defeat tampering and padding oracle attacks.
- **PBKDF2-HMAC-SHA256 Authentication (`PasswordHasher`, `UserStore`)**: 100,000-iteration salted PBKDF2 storage with 16-byte CSPRNG salts, constant-time verification, automatic legacy hash migration, and admin account provisioning (`--create-user`).
- **Brute-Force & DoS Protection (`AuthRateLimiter`, `TcpServerService`)**: Per-username and per-IP login lockout, global and per-IP connection caps, 10-second pre-auth timeout, 64 KB pre-auth packet cap, and `AllowPublicRegistration = false` enterprise gating.
- **Encryption-at-Rest & Audit Logging (`StorageCipher`, `AuditLogger`)**: Server `MessageStore` and `OfflineMessageQueue` encrypted on disk with AEAD (protected by a Windows DPAPI-bound 256-bit key), client local chat history protected by Windows DPAPI (`CurrentUser`), and daily rotating UTC security audit logs (10 MB rollover / 30-file retention).

### 2. Zero-Trust External Client Pipeline (No Open Company Firewall Ports)
- **Zero-Trust Reverse Tunnel (`EdgeRelayServer` + `ReverseTunnelAgent`)**: Deploy `ZTalk.Server.exe --edge-relay` on a public VPS (`:443` public / `:8443` TLS control). The LAN server maintains an outbound TLS 1.2 reverse tunnel authenticated by 32-byte CSPRNG challenge-response **HMAC-SHA256**. Client-to-server TLS 1.2 is bridged raw end-to-end — the VPS never holds the company server's private key and cannot inspect traffic.
- **Smart Dual-Endpoint Failover (`ConnectionPipeline`)**: Clients probe the office LAN endpoint first (fast `1.2s` timeout) and automatically fail over to the external WAN EdgeRelay (`:443`) when working remotely.
- **Automatic Reconnect & Transparent Re-Auth**: Exponential backoff with jitter (`1.5s` → `30s`) automatically restores dropped sessions across Wi-Fi/4G handoffs and re-authenticates transparently without forcing users back to the login screen.

### 3. Enterprise 100-User Messaging & Disk-Streamed File Transfers
- **IOCP Async Networking**: Non-blocking `Stream.ReadAsync` packet loop, single-buffer length-prefixed framing (`FramePacket`), per-client write locks preventing frame interleaving, and single-serialization broadcast fan-out.
- **Persistent Offline Message Queue (`OfflineMessageQueue`)**: Messages sent to offline recipients are durably queued (encrypted at rest, up to 500/user) and automatically delivered upon next login.
- **O(1) RAM Disk-Streaming File Receive (`FileReceiveService`)**: Incoming E2EE file chunks write directly to offset-addressed `.part` files on disk (supporting out-of-order delivery, strict path-traversal sandboxing, completeness verification, and stale `.part` eviction).
- **E2EE Local History Continuity**: Decrypted 1-on-1 messages persist locally under Windows DPAPI so history remains readable across ECDH session key rotations.

### 4. Pluggable Video & Voice Streaming Pipeline
- **Synthetic Camera & Screen Sharing**: `SyntheticVideoSource` (cached static backdrop + recycled GDI+ resources at 15–20 FPS) and `ScreenCaptureVideoSource` with leak-free GDI+ bitmap management.
- **STUN NAT Traversal (RFC 5389) & TCP Relay Fallback**: Cryptographic 96-bit STUN transaction IDs, strict bounds checking, IPv4 resolution filtering, UDP hole punching, and seamless TCP relay fallback.
- **Voice Frame Streaming & VAD (`VoiceCallSessionService`)**: Zero-extra-allocation 18-byte binary header encoding, monotonic `Stopwatch` timestamps, RMS voice activity detection, and out-of-order packet loss tracking.

### 5. Automated Regression & Integration Test Suite (`ZTalk.Tests` — 12/12 Suites)
Custom zero-dependency test harness verifying:
1. Protocol framing, BigEndian single-buffer framing, UTF-8 encoding, and concurrent `ThreadLocal` serialization.
2. AES-256-CBC + HMAC-SHA256 round-trips, short-input rejection, and ECDH key exchange.
3. `UserStore` O(1) auth, duplicate checks, and `MessageStore` path-traversal defense + caching.
4. Synthetic video frame generation and JPEG SOI validation.
5. STUN RFC 5389 binary decoding, spoofing rejection, and out-of-bounds length protection.
6. File chunking BVA, out-of-order reassembly, path-traversal blocking, and incomplete transfer rejection.
7. Cryptographic invariants (ECDH commutativity/distinctness, IV entropy).
8. Radar sweep trigonometric periodic geometry.
9. Voice call audio header uint16 round-trip, VAD silence suppression, and out-of-order sequence tracking.
10. **Security Core**: AEAD tamper detection, PBKDF2 salting & legacy migration, brute-force lockout, audit logging, and live TLS 1.2 SHA-256 pinning.
11. **External Pipeline**: Unauthorized HMAC agent rejection, end-to-end Zero-Trust Reverse Tunnel with dual TLS pinning, LAN→WAN failover, and auto-reconnect + re-auth.
12. **Enterprise 100-User**: `.part` disk-streaming + stale cleanup, server AEAD encryption-at-rest, DPAPI local history, and end-to-end offline message delivery over TLS 1.2.

---

## 🏛️ System Architecture

```text
ZTalk.sln
│
├── ZTalk.Shared/                         # Core BCL Library (Shared across Server, EdgeRelay & Client)
│   ├── Constants/AppConstants.cs         # Default ports, buffer limits, chunk sizes
│   ├── Crypto/                           # AesHelper (Encrypt-then-MAC), DiffieHellmanHelper,
│   │                                     # PasswordHasher (PBKDF2-SHA256), StorageCipher (AEAD + DPAPI)
│   ├── DTOs/                             # Typed network transfer contracts
│   ├── Network/                          # TlsHelper (TLS 1.2 + Pinning), StunClient (RFC 5389),
│   │                                     # ReverseTunnelProtocol, EdgeRelayServer, ReverseTunnelAgent
│   └── Protocol/                         # Packet, PacketType, thread-safe PacketSerializer (Stream)
│
├── ZTalk.Server/                         # WinForms Dashboard + Headless Service + EdgeRelay Host
│   ├── Config/ServerSecurityConfig.cs    # server.security.json enterprise policy & tunnel config
│   ├── Data/                             # UserStore (PBKDF2), MessageStore (AEAD), OfflineMessageQueue
│   ├── Models/                           # ConnectedClient (per-client send lock), UserAccount
│   ├── Services/                         # TcpServerService, AuthService, AuthRateLimiter,
│   │                                     # AuditLogger, MessageRouter
│   ├── Forms/frmServer.cs                # Live telemetry HUD, client directory, admin kick
│   └── Program.cs                        # CLI modes: GUI, --headless, --edge-relay, --create-user, --gen-cert
│
├── ZTalk.Client/                         # WinForms Desktop Client
│   ├── Config/ClientSecurityConfig.cs    # client.config.json (LAN/WAN endpoints, TLS pin, auto-reconnect)
│   ├── Forms/                            # frmLogin, frmChat, frmVideoCall, frmImagePreview
│   ├── Helpers/VideoRecorder.cs          # Recording integration hooks
│   └── Services/                         # TcpClientService (TLS 1.2), ConnectionPipeline (LAN->WAN + Reconnect),
│                                         # ChatService, FileTransferService (E2EE), FileReceiveService (.part),
│                                         # MessageHistoryService (DPAPI), VideoCallService, VoiceCallSessionService
│
└── ZTalk.Tests/                          # Standalone Automated Test Runner (.NET 4.8)
    ├── Program.cs                        # 12-suite test harness (exit code 0/1)
    ├── ProtocolTests.cs                  # Framing & concurrent serialization tests
    ├── CryptoTests.cs                    # AEAD & ECDH tests
    ├── StorageTests.cs                   # Persistence & path-traversal tests
    ├── VideoSourceTests.cs               # Synthetic camera & JPEG tests
    ├── AlgorithmTests.cs                 # STUN, chunking, crypto invariants, geometry, voice VAD
    ├── SecurityTests.cs                  # Phase 1: AEAD tamper, PBKDF2, lockout, audit, live TLS 1.2 pinning
    ├── PipelineTests.cs                  # Phase 2: Zero-Trust Reverse Tunnel, LAN->WAN failover, auto-reconnect
    ├── EnterpriseTests.cs                # Phase 3: .part disk streaming, offline queue, AEAD/DPAPI at-rest
    └── DemoScreenshotGenerator.cs        # Documentation screenshot generator
```

---

## 🌐 Enterprise Self-Host Topology (LAN + Remote Clients)

```text
[Remote Employee (4G / Home Wi-Fi)]
       │  End-to-End TLS 1.2 (Pinned to LAN Server Cert, Port 443)
       ▼
[Public VPS: ZTalk.Server.exe --edge-relay]
       ▲  Outbound TLS 1.2 Reverse Tunnel (HMAC-SHA256 Auth, Port 8443)
       │  (Zero inbound firewall ports required at company office)
[Office LAN: ZTalk.Server.exe --headless]  ◀── Direct LAN TLS 1.2 ──  [Office Employee]
```

### Production Deployment Guide (~100 Users)

#### 1. Start the Zero-Trust EdgeRelay on a Public VPS
```powershell
ZTalk.Server.exe --edge-relay --public-port 443 --control-port 8443 --secret "ReplaceWith32CharStrongSecret!" --cn chat.company.com
# Copy the printed ControlPin (SHA-256 thumbprint) for step 3
```

#### 2. Generate LAN Server Certificate & Provision Employee Accounts
```powershell
# Generate LAN server TLS certificate & note the printed SHA-256 Pin Thumbprint
ZTalk.Server.exe --gen-cert --cn chat.company.com

# Provision employee accounts (stored with salted PBKDF2-SHA256)
ZTalk.Server.exe --create-user alice.nguyen "StrongPass!2026" "Alice Nguyen"
ZTalk.Server.exe --create-user bob.tran "StrongPass!2026" "Bob Tran"
```

#### 3. Configure `server.security.json` & Launch 24/7 Headless Server inside LAN
```json
{
  "Port": 9000,
  "EnableTls": true,
  "AllowPublicRegistration": false,
  "SeedDemoUsers": false,
  "EnableStorageEncryption": true,
  "MaxConnections": 250,
  "MaxConnectionsPerIp": 25,
  "AuthTimeoutSeconds": 10,
  "MaxFailedLoginAttempts": 5,
  "LockoutMinutes": 5,
  "EnableReverseTunnel": true,
  "EdgeRelayHost": "chat.company.com",
  "EdgeRelayControlPort": 8443,
  "EdgeRelaySecret": "ReplaceWith32CharStrongSecret!",
  "EdgeRelayCertPinSha256": "<EDGE-CONTROL-SHA256-PIN>"
}
```
```powershell
ZTalk.Server.exe --headless
```

#### 4. Distribute `client.config.json` Alongside `ZTalk.Client.exe`
```json
{
  "ServerHost": "192.168.1.10",
  "ServerPort": 9000,
  "FallbackServerHost": "chat.company.com",
  "FallbackServerPort": 443,
  "LanConnectTimeoutMs": 1200,
  "UseTls": true,
  "TlsTargetHost": "chat.company.com",
  "PinnedCertSha256": "<LAN-SERVER-SHA256-PIN>",
  "AutoReconnect": true,
  "HideDemoAccounts": true
}
```

---

## 🚀 Quick Start (Local Development & Demo)

### Prerequisites
- **OS**: Windows 10 / 11 / Windows Server 2016+
- **Runtime**: .NET Framework 4.8 (pre-installed on modern Windows)
- **Build Tools**: MSBuild (Visual Studio 2022) or .NET SDK

### Automated 1-Command Demo Launcher
```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\run-demo.ps1
```
*(In `Debug` mode, demo accounts `alice`, `bob`, `charlie` are pre-seeded with password `123`; demo seeding is automatically disabled in `Release` enterprise mode.)*

### Build & Run Tests Manually
```powershell
msbuild ZTalk.sln /p:Configuration=Release /t:Rebuild /v:minimal
.\ZTalk.Tests\bin\Release\ZTalk.Tests.exe
```

---

## 📦 Build & Release Packaging

```powershell
# Publish both Full and Lite standalone distributions into publish/full and publish/lite:
powershell -ExecutionPolicy Bypass -File .\publish.ps1 -Mode All -Configuration Release

# Or build, verify all 12 test suites, and create versioned zip archives:
powershell -ExecutionPolicy Bypass -File .\scripts\publish-app.ps1 -Mode Lite -Version 2.0.0
powershell -ExecutionPolicy Bypass -File .\scripts\publish-app.ps1 -Mode Full -Version 2.0.0
```

---

## 📄 License
This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details. Part of the **ZeroUniverse** ecosystem.
