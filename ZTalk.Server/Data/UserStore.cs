using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using ZTalk.Server.Models;
using ZTalk.Shared.Crypto;

namespace ZTalk.Server.Data
{
    /// <summary>
    /// Lưu trữ user accounts trên server với O(1) dictionary index,
    /// PBKDF2-HMAC-SHA256 có per-user salt và atomic persistence.
    /// </summary>
    public class UserStore
    {
        private readonly string _filePath;
        private readonly bool _seedDemoUsers;
        private List<UserAccount> _users;
        private Dictionary<string, UserAccount> _usersByUsername;
        private readonly object _lock = new object();

        public UserStore(string filePath = null, bool seedDemoUsers = true)
        {
            _filePath = filePath ?? Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "users.json");
            _seedDemoUsers = seedDemoUsers;
            LoadUsers();
        }

        /// <summary>
        /// Xác thực user bằng username và credential (O(1) lookup + PBKDF2 constant-time verify).
        /// Tự động nâng cấp hash SHA-256 cũ lên PBKDF2-SHA256 có salt khi đăng nhập thành công.
        /// </summary>
        public UserAccount Authenticate(string username, string passwordHash)
        {
            if (string.IsNullOrEmpty(username) || string.IsNullOrEmpty(passwordHash))
                return null;

            lock (_lock)
            {
                UserAccount user;
                if (_usersByUsername.TryGetValue(username, out user) &&
                    PasswordHasher.Verify(passwordHash, user.PasswordHash))
                {
                    // Transparently migrate legacy unsalted SHA-256 hash to salted PBKDF2-SHA256
                    if (PasswordHasher.NeedsRehash(user.PasswordHash))
                    {
                        user.PasswordHash = PasswordHasher.Hash(passwordHash);
                        SaveUsers();
                    }
                    return user;
                }
                return null;
            }
        }

        /// <summary>
        /// Đăng ký user mới (băm PBKDF2-SHA256 có CSPRNG salt trước khi lưu đĩa)
        /// </summary>
        public bool Register(string username, string passwordHash, string displayName)
        {
            if (string.IsNullOrWhiteSpace(username) || string.IsNullOrEmpty(passwordHash))
                return false;

            lock (_lock)
            {
                // O(1) duplicate username check
                if (_usersByUsername.ContainsKey(username))
                    return false;

                var user = new UserAccount
                {
                    UserId = Guid.NewGuid().ToString("N").Substring(0, 8),
                    Username = username,
                    PasswordHash = PasswordHasher.Hash(passwordHash),
                    DisplayName = displayName ?? username,
                    CreatedAt = DateTime.Now
                };

                _users.Add(user);
                _usersByUsername[username] = user;
                SaveUsers();
                return true;
            }
        }

        /// <summary>
        /// Provision hoặc reset tài khoản bởi quản trị viên (nhận raw password, tự băm chuẩn client+PBKDF2)
        /// </summary>
        public UserAccount ProvisionAccount(string username, string rawPassword, string displayName)
        {
            if (string.IsNullOrWhiteSpace(username) || string.IsNullOrEmpty(rawPassword))
                throw new ArgumentException("Username and password are required.");

            string clientDigest = HashPassword(rawPassword);
            string storedPbkdf2 = PasswordHasher.Hash(clientDigest);

            lock (_lock)
            {
                UserAccount user;
                if (_usersByUsername.TryGetValue(username, out user))
                {
                    user.PasswordHash = storedPbkdf2;
                    if (!string.IsNullOrWhiteSpace(displayName))
                        user.DisplayName = displayName;
                }
                else
                {
                    user = new UserAccount
                    {
                        UserId = "u_" + Guid.NewGuid().ToString("N").Substring(0, 8),
                        Username = username.Trim(),
                        PasswordHash = storedPbkdf2,
                        DisplayName = string.IsNullOrWhiteSpace(displayName) ? username.Trim() : displayName.Trim(),
                        CreatedAt = DateTime.Now
                    };
                    _users.Add(user);
                    _usersByUsername[user.Username] = user;
                }

                SaveUsers();
                return user;
            }
        }

        /// <summary>
        /// Lấy user theo username (O(1))
        /// </summary>
        public UserAccount GetByUsername(string username)
        {
            if (string.IsNullOrEmpty(username)) return null;

            lock (_lock)
            {
                UserAccount user;
                return _usersByUsername.TryGetValue(username, out user) ? user : null;
            }
        }

        /// <summary>
        /// Client-side SHA256 pre-hash helper (server always wraps with salted PBKDF2-SHA256)
        /// </summary>
        public static string HashPassword(string password)
        {
            using (var sha256 = SHA256.Create())
            {
                var bytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(password));
                return Convert.ToBase64String(bytes);
            }
        }

        private void LoadUsers()
        {
            _users = new List<UserAccount>();
            _usersByUsername = new Dictionary<string, UserAccount>(StringComparer.OrdinalIgnoreCase);

            bool fileExisted = File.Exists(_filePath);
            if (fileExisted)
            {
                try
                {
                    var json = File.ReadAllText(_filePath, Encoding.UTF8);
                    _users = ZTalk.Shared.Protocol.PacketSerializer.FromJson<List<UserAccount>>(json) ?? new List<UserAccount>();
                    foreach (var u in _users)
                    {
                        if (!string.IsNullOrEmpty(u?.Username))
                            _usersByUsername[u.Username] = u;
                    }
                }
                catch
                {
                    try
                    {
                        File.Copy(_filePath, _filePath + ".corrupt." + DateTime.UtcNow.Ticks, true);
                    }
                    catch { }
                    _users = new List<UserAccount>();
                    _usersByUsername.Clear();
                }
            }

            bool modified = false;
            if (_seedDemoUsers)
            {
                modified = EnsureDemoUsers();
            }

            if (modified || !fileExisted)
            {
                SaveUsers();
            }
        }

        private bool EnsureDemoUsers()
        {
            bool changed = false;
            changed |= EnsureUser("user_alice", "alice", "123", "Alice Johnson");
            changed |= EnsureUser("user_bob", "bob", "123", "Bob Williams");
            changed |= EnsureUser("user_charlie", "charlie", "123", "Charlie Davis");
            return changed;
        }

        private bool EnsureUser(string id, string username, string password, string displayName)
        {
            string clientDigest = HashPassword(password);
            UserAccount user;
            if (!_usersByUsername.TryGetValue(username, out user))
            {
                user = new UserAccount
                {
                    UserId = id,
                    Username = username,
                    PasswordHash = PasswordHasher.Hash(clientDigest),
                    DisplayName = displayName,
                    CreatedAt = DateTime.Now
                };
                _users.Add(user);
                _usersByUsername[username] = user;
                return true;
            }

            bool changed = false;
            if (!PasswordHasher.Verify(clientDigest, user.PasswordHash) || PasswordHasher.NeedsRehash(user.PasswordHash))
            {
                user.PasswordHash = PasswordHasher.Hash(clientDigest);
                changed = true;
            }
            if (string.IsNullOrEmpty(user.DisplayName))
            {
                user.DisplayName = displayName;
                changed = true;
            }
            return changed;
        }

        private void SaveUsers()
        {
            try
            {
                string dir = Path.GetDirectoryName(Path.GetFullPath(_filePath));
                if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir))
                    Directory.CreateDirectory(dir);

                var json = ZTalk.Shared.Protocol.PacketSerializer.ToJson(_users);
                string tempPath = _filePath + ".tmp";
                File.WriteAllText(tempPath, json, Encoding.UTF8);

                if (File.Exists(_filePath))
                    File.Replace(tempPath, _filePath, null);
                else
                    File.Move(tempPath, _filePath);
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"Error saving users: {ex.Message}");
            }
        }
    }
}
