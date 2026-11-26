using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using ZTalk.Server.Models;
using ZTalk.Shared.Protocol;

namespace ZTalk.Server.Services
{
    /// <summary>
    /// Routes packets to specific clients or broadcasts across the network.
    /// </summary>
    public class MessageRouter : IMessageRouter
    {
        private readonly ConcurrentDictionary<string, ConnectedClient> _clients;
        private readonly Action<string> _log;

        public MessageRouter(ConcurrentDictionary<string, ConnectedClient> clients, Action<string> log)
        {
            _clients = clients;
            _log = log;
        }

        public bool IsClientOnline(string userId)
        {
            if (string.IsNullOrEmpty(userId)) return false;
            ConnectedClient client;
            return _clients.TryGetValue(userId, out client) && client.IsAuthenticated;
        }

        /// <summary>
        /// Sends packet to a specific client (serialized per client socket)
        /// </summary>
        public void SendToClient(string userId, Packet packet)
        {
            if (string.IsNullOrEmpty(userId) || packet == null) return;

            ConnectedClient client;
            if (_clients.TryGetValue(userId, out client) && client.IsAuthenticated)
            {
                try
                {
                    client.SendPacket(packet);
                }
                catch (Exception ex)
                {
                    _log?.Invoke($"[ERROR] Failed to send packet to {userId}: {ex.Message}");
                }
            }
        }

        /// <summary>
        /// Broadcasts packet to all connected clients (except excluded user).
        /// Serializes and frames packet once to avoid N× JSON/UTF-8 allocation overhead.
        /// </summary>
        public void Broadcast(Packet packet, string excludeUserId = null)
        {
            if (packet == null) return;

            byte[] frame = PacketSerializer.FramePacket(packet);
            foreach (var kvp in _clients)
            {
                if (kvp.Key == excludeUserId) continue;
                if (!kvp.Value.IsAuthenticated) continue;

                try
                {
                    kvp.Value.SendRawFrame(frame);
                }
                catch (Exception ex)
                {
                    _log?.Invoke($"[ERROR] Broadcast to {kvp.Key} failed: {ex.Message}");
                }
            }
        }

        /// <summary>
        /// Broadcasts online user list to all connected clients.
        /// Data = "user1|DisplayName1,user2|DisplayName2,..."
        /// </summary>
        public void BroadcastUserList()
        {
            var packet = BuildUserListPacket();
            Broadcast(packet);
        }

        /// <summary>
        /// Sends online user list only to the requesting client (avoids O(N²) Heartbeat amplification).
        /// </summary>
        public void SendUserListToClient(ConnectedClient client)
        {
            if (client == null || !client.IsAuthenticated) return;

            try
            {
                var packet = BuildUserListPacket();
                client.SendPacket(packet);
            }
            catch (Exception ex)
            {
                _log?.Invoke($"[ERROR] Failed to send user list to {client.UserId}: {ex.Message}");
            }
        }

        private Packet BuildUserListPacket()
        {
            var onlineUsers = new List<string>();
            foreach (var kvp in _clients)
            {
                var c = kvp.Value;
                if (c.IsAuthenticated)
                {
                    onlineUsers.Add(c.UserId + "|" + c.DisplayName);
                }
            }

            var userListData = string.Join(",", onlineUsers);
            return new Packet(PacketType.UserList, "server", null, userListData);
        }
    }
}
