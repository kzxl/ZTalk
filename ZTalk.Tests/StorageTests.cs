using System;
using System.IO;
using ZTalk.Server.Data;

namespace ZTalk.Tests
{
    public static class StorageTests
    {
        public static void RunAll()
        {
            TestUserStoreAuthentication();
            TestUserStoreDuplicateRegistration();
            TestMessageStoreSaveAndRetrieve();
            TestMessageStorePathTraversalAndPersistenceCache();
        }

        private static void TestUserStoreAuthentication()
        {
            string tempDb = Path.Combine(Path.GetTempPath(), $"users_{Guid.NewGuid():N}.json");
            try
            {
                var store = new UserStore(tempDb);

                // Default seed users
                Assert.NotNull(store.GetByUsername("alice"));
                Assert.NotNull(store.GetByUsername("bob"));
                Assert.NotNull(store.GetByUsername("charlie"));

                // Valid pass
                string passHash = UserStore.HashPassword("123");
                var user = store.Authenticate("alice", passHash);
                Assert.NotNull(user);
                Assert.Equal("alice", user.Username);

                // Invalid pass
                var failedUser = store.Authenticate("alice", UserStore.HashPassword("wrongpassword"));
                Assert.True(failedUser == null);
            }
            finally
            {
                if (File.Exists(tempDb)) File.Delete(tempDb);
            }
        }

        private static void TestUserStoreDuplicateRegistration()
        {
            string tempDb = Path.Combine(Path.GetTempPath(), $"users_{Guid.NewGuid():N}.json");
            try
            {
                var store = new UserStore(tempDb);
                bool added = store.Register("newUser", UserStore.HashPassword("pass"), "New User");
                Assert.True(added);

                // Duplicate username
                bool duplicateAdded = store.Register("newUser", UserStore.HashPassword("pass2"), "Another User");
                Assert.False(duplicateAdded, "Duplicate usernames should be rejected");
            }
            finally
            {
                if (File.Exists(tempDb)) File.Delete(tempDb);
            }
        }

        private static void TestMessageStoreSaveAndRetrieve()
        {
            string tempDir = Path.Combine(Path.GetTempPath(), $"chat_history_{Guid.NewGuid():N}");
            try
            {
                var msgStore = new MessageStore(tempDir);
                msgStore.SaveMessage("u1", "u2", "user1", "Hello u2!", false);
                msgStore.SaveMessage("u2", "u1", "user2", "Hey u1, received loud and clear.", false);

                var history = msgStore.GetHistory("u1", "u2");
                Assert.NotNull(history);
                Assert.Equal(2, history.Count);
                Assert.Equal("Hello u2!", history[0].Content);
                Assert.Equal("Hey u1, received loud and clear.", history[1].Content);
            }
            finally
            {
                if (Directory.Exists(tempDir)) Directory.Delete(tempDir, true);
            }
        }

        private static void TestMessageStorePathTraversalAndPersistenceCache()
        {
            string tempDir = Path.Combine(Path.GetTempPath(), $"chat_sec_{Guid.NewGuid():N}");
            try
            {
                var msgStore = new MessageStore(tempDir);
                msgStore.SaveMessage("u1", "../../escape_attempt", "user1", "Safe content", false);

                // Ensure no file escaped tempDir
                string parentDir = Directory.GetParent(tempDir).FullName;
                Assert.False(File.Exists(Path.Combine(parentDir, "escape_attempt.json")),
                    "MessageStore must block path traversal outside dataDir");

                // Verify persistence across cold reload (new MessageStore instance)
                var reloadedStore = new MessageStore(tempDir);
                var history = reloadedStore.GetHistory("u1", "../../escape_attempt");
                Assert.Equal(1, history.Count);
                Assert.Equal("Safe content", history[0].Content);
            }
            finally
            {
                if (Directory.Exists(tempDir)) Directory.Delete(tempDir, true);
            }
        }
    }
}
