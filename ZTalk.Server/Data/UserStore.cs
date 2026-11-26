using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using ZTalk.Server.Models;

namespace ZTalk.Server.Data
{
    /// <summary>
    /// Lưu trữ user accounts trên server với O(1) dictionary index và atomic persistence.
    /// </summary>
    public class UserStore
    {
        private readonly string _filePath;
        private List<UserAccount> _users;
        private Dictionary<string, UserAccount> _usersByUsername;
        private readonly object _lock = new object();

        public UserStore(string filePath = null)
        {
            _filePath = filePath ?? Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "users.json");
            LoadUsers();
        }

        /// <summary>
        /// Xác thực user bằng username và password hash (O(1) lookup + constant-time compare)
        /// </summary>
        public UserAccount Authenticate(string username, string passwordHash)
        {
            if (string.IsNullOrEmpty(username) || string.IsNullOrEmpty(passwordHash))
                return null;

            lock (_lock)
            {
                UserAccount user;
                if (_usersByUsername.TryGetValue(username, out user) &&
                    FixedTimeEquals(user.PasswordHash, passwordHash))
                {
                    return user;
                }
                return null;
            }
        }

        /// <summary>
        /// Đăng ký user mới
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
                    PasswordHash = passwordHash,
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
        /// Hash password bằng SHA256
        /// </summary>
        public static string HashPassword(string password)
        {
            using (var sha256 = SHA256.Create())
            {
                var bytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(password));
                return Convert.ToBase64String(bytes);
            }
        }

        private static bool FixedTimeEquals(string a, string b)
        {
            if (a == null || b == null || a.Length != b.Length)
                return false;

            int diff = 0;
            for (int i = 0; i < a.Length; i++)
            {
                diff |= a[i] ^ b[i];
            }
            return diff == 0;
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

            // Ensure default demo accounts (alice, bob, charlie) exist with password "123"
            bool modified = EnsureDemoUsers();
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
            string expectedHash = HashPassword(password);
            UserAccount user;
            if (!_usersByUsername.TryGetValue(username, out user))
            {
                user = new UserAccount
                {
                    UserId = id,
                    Username = username,
                    PasswordHash = expectedHash,
                    DisplayName = displayName,
                    CreatedAt = DateTime.Now
                };
                _users.Add(user);
                _usersByUsername[username] = user;
                return true;
            }

            bool changed = false;
            if (user.PasswordHash != expectedHash)
            {
                user.PasswordHash = expectedHash;
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
