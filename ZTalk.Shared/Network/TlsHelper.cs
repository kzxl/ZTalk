using System;
using System.IO;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using ZTalk.Shared.Crypto;

namespace ZTalk.Shared.Network
{
    /// <summary>
    /// Enterprise TLS 1.2 helper for SslStream authentication, SHA-256 certificate pinning,
    /// and pure-BCL self-signed X.509 certificate generation (.NET Framework 4.8).
    /// </summary>
    public static class TlsHelper
    {
        public const SslProtocols DefaultProtocols = SslProtocols.Tls12;

        /// <summary>
        /// Compute uppercase hex SHA-256 thumbprint of a certificate's raw DER bytes.
        /// </summary>
        public static string GetCertSha256Thumbprint(X509Certificate cert)
        {
            if (cert == null) throw new ArgumentNullException(nameof(cert));

            using (var sha256 = SHA256.Create())
            {
                byte[] hash = sha256.ComputeHash(cert.GetRawCertData());
                var sb = new StringBuilder(hash.Length * 2);
                for (int i = 0; i < hash.Length; i++)
                {
                    sb.Append(hash[i].ToString("X2"));
                }
                return sb.ToString();
            }
        }

        /// <summary>
        /// Normalize thumbprint by stripping colons, hyphens, spaces and converting to uppercase.
        /// </summary>
        public static string NormalizeThumbprint(string thumbprint)
        {
            if (string.IsNullOrWhiteSpace(thumbprint)) return null;

            var sb = new StringBuilder(thumbprint.Length);
            for (int i = 0; i < thumbprint.Length; i++)
            {
                char c = thumbprint[i];
                if (c != ':' && c != '-' && !char.IsWhiteSpace(c))
                    sb.Append(char.ToUpperInvariant(c));
            }
            return sb.Length > 0 ? sb.ToString() : null;
        }

        /// <summary>
        /// Load an X.509 PFX certificate from disk with private key usable by Windows Schannel.
        /// </summary>
        public static X509Certificate2 LoadCertificate(string pfxPath, string password)
        {
            if (string.IsNullOrWhiteSpace(pfxPath) || !File.Exists(pfxPath))
                throw new FileNotFoundException("TLS certificate file not found.", pfxPath);

            return new X509Certificate2(
                pfxPath,
                password ?? string.Empty,
                X509KeyStorageFlags.Exportable | X509KeyStorageFlags.UserKeySet);
        }

        /// <summary>
        /// Generate a 2048-bit RSA SHA-256 self-signed X.509 certificate in pure .NET 4.8 BCL
        /// and re-import from PFX bytes so Schannel SslStream can bind its private key on Windows.
        /// </summary>
        public static X509Certificate2 CreateSelfSignedCertificate(
            string subjectCn = "ZTalk-Server",
            string[] sanDnsNames = null,
            int validDays = 3650,
            string exportPassword = "")
        {
            using (var rsa = RSA.Create(2048))
            {
                var subject = new X500DistinguishedName($"CN={subjectCn}");
                var request = new CertificateRequest(subject, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

                request.CertificateExtensions.Add(
                    new X509BasicConstraintsExtension(false, false, 0, true));
                request.CertificateExtensions.Add(
                    new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, true));
                request.CertificateExtensions.Add(
                    new X509EnhancedKeyUsageExtension(
                        new OidCollection { new Oid("1.3.6.1.5.5.7.3.1") }, // Server Authentication
                        false));

                var sanBuilder = new SubjectAlternativeNameBuilder();
                sanBuilder.AddDnsName("localhost");
                sanBuilder.AddIpAddress(IPAddress.Loopback);
                if (!string.IsNullOrWhiteSpace(subjectCn))
                {
                    IPAddress ip;
                    if (IPAddress.TryParse(subjectCn, out ip))
                        sanBuilder.AddIpAddress(ip);
                    else if (!subjectCn.Equals("localhost", StringComparison.OrdinalIgnoreCase))
                        sanBuilder.AddDnsName(subjectCn);
                }

                if (sanDnsNames != null)
                {
                    foreach (var name in sanDnsNames)
                    {
                        if (string.IsNullOrWhiteSpace(name)) continue;
                        IPAddress ip;
                        if (IPAddress.TryParse(name, out ip))
                            sanBuilder.AddIpAddress(ip);
                        else
                            sanBuilder.AddDnsName(name);
                    }
                }
                request.CertificateExtensions.Add(sanBuilder.Build());

                var now = DateTimeOffset.UtcNow;
                using (var ephemeral = request.CreateSelfSigned(now.AddMinutes(-5), now.AddDays(validDays)))
                {
                    byte[] pfxBytes = ephemeral.Export(X509ContentType.Pfx, exportPassword ?? string.Empty);
                    return new X509Certificate2(
                        pfxBytes,
                        exportPassword ?? string.Empty,
                        X509KeyStorageFlags.Exportable | X509KeyStorageFlags.UserKeySet);
                }
            }
        }

        /// <summary>
        /// Generate and save a self-signed PFX certificate to disk, returning the loaded certificate.
        /// </summary>
        public static X509Certificate2 GenerateAndSaveSelfSignedPfx(
            string pfxPath,
            string password,
            string subjectCn = "ZTalk-Server",
            string[] sanDnsNames = null)
        {
            string dir = Path.GetDirectoryName(Path.GetFullPath(pfxPath));
            if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir))
                Directory.CreateDirectory(dir);

            var cert = CreateSelfSignedCertificate(subjectCn, sanDnsNames, 3650, password ?? string.Empty);
            byte[] pfxBytes = cert.Export(X509ContentType.Pfx, password ?? string.Empty);
            File.WriteAllBytes(pfxPath, pfxBytes);
            return cert;
        }

        /// <summary>
        /// Authenticate a server-side SslStream with TLS 1.2 and handshake timeout.
        /// </summary>
        public static async Task<SslStream> AuthenticateAsServerAsync(
            NetworkStream rawStream,
            X509Certificate2 serverCert,
            CancellationToken ct,
            int handshakeTimeoutMs = 5000)
        {
            if (rawStream == null) throw new ArgumentNullException(nameof(rawStream));
            if (serverCert == null) throw new ArgumentNullException(nameof(serverCert));

            var sslStream = new SslStream(rawStream, leaveInnerStreamOpen: false);
            try
            {
                var authTask = sslStream.AuthenticateAsServerAsync(
                    serverCert,
                    clientCertificateRequired: false,
                    enabledSslProtocols: DefaultProtocols,
                    checkCertificateRevocation: false);

                await WaitWithTimeoutAsync(authTask, handshakeTimeoutMs, ct, "TLS server handshake timed out.").ConfigureAwait(false);
                return sslStream;
            }
            catch
            {
                sslStream.Dispose();
                throw;
            }
        }

        /// <summary>
        /// Authenticate a client-side SslStream with TLS 1.2 and optional SHA-256 certificate pinning.
        /// </summary>
        public static async Task<SslStream> AuthenticateAsClientAsync(
            NetworkStream rawStream,
            string targetHost,
            string pinnedSha256Thumbprint = null,
            bool allowSelfSigned = false,
            CancellationToken ct = default(CancellationToken),
            int handshakeTimeoutMs = 5000)
        {
            if (rawStream == null) throw new ArgumentNullException(nameof(rawStream));

            var callback = CreateClientValidationCallback(pinnedSha256Thumbprint, allowSelfSigned);
            var sslStream = new SslStream(rawStream, leaveInnerStreamOpen: false, userCertificateValidationCallback: callback);
            try
            {
                var authTask = sslStream.AuthenticateAsClientAsync(
                    targetHost ?? "localhost",
                    clientCertificates: null,
                    enabledSslProtocols: DefaultProtocols,
                    checkCertificateRevocation: false);

                await WaitWithTimeoutAsync(authTask, handshakeTimeoutMs, ct, "TLS client handshake timed out.").ConfigureAwait(false);
                return sslStream;
            }
            catch
            {
                sslStream.Dispose();
                throw;
            }
        }

        public static RemoteCertificateValidationCallback CreateClientValidationCallback(
            string pinnedSha256Thumbprint,
            bool allowSelfSigned)
        {
            string normalizedPin = NormalizeThumbprint(pinnedSha256Thumbprint);

            return (sender, certificate, chain, sslPolicyErrors) =>
            {
                if (certificate == null)
                    return false;

                // Strict SHA-256 certificate pinning takes highest precedence
                if (!string.IsNullOrEmpty(normalizedPin))
                {
                    string remoteThumbprint = GetCertSha256Thumbprint(certificate);
                    return PasswordHasher.FixedTimeEquals(remoteThumbprint, normalizedPin);
                }

                // Standard OS/CA trust store validation
                if (sslPolicyErrors == SslPolicyErrors.None)
                    return true;

                // Explicit opt-in for development/self-signed without pinning
                return allowSelfSigned;
            };
        }

        private static async Task WaitWithTimeoutAsync(Task task, int timeoutMs, CancellationToken ct, string timeoutMessage)
        {
            using (var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct))
            {
                var delayTask = Task.Delay(timeoutMs, timeoutCts.Token);
                var completed = await Task.WhenAny(task, delayTask).ConfigureAwait(false);
                if (completed == delayTask)
                {
                    ct.ThrowIfCancellationRequested();
                    throw new TimeoutException(timeoutMessage);
                }

                timeoutCts.Cancel();
                await task.ConfigureAwait(false);
            }
        }
    }
}
