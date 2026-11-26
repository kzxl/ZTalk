using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;
using ZTalk.Shared.Protocol;

namespace ZTalk.Tests
{
    public static class ProtocolTests
    {
        public static void RunAll()
        {
            TestPacketFraming();
            TestJsonSerializationSpecialCharacters();
            TestPacketHeaderParsing();
            TestFramePacketAndConcurrentSerialization();
        }

        private static void TestPacketFraming()
        {
            var packet = new Packet(PacketType.Message, "alice", "bob", "Hello world! 🚀");
            string json = PacketSerializer.Serialize(packet);

            Assert.NotNull(json);
            Assert.True(json.Length > 0);

            var deserialized = PacketSerializer.Deserialize(json);
            Assert.NotNull(deserialized);
            Assert.Equal(PacketType.Message, deserialized.Type);
            Assert.Equal("alice", deserialized.SenderId);
            Assert.Equal("bob", deserialized.ReceiverId);
            Assert.Equal("Hello world! 🚀", deserialized.Data);
        }

        private static void TestJsonSerializationSpecialCharacters()
        {
            var dict = new Dictionary<string, object>
            {
                { "Quote", "Text with \"quotes\" and 'single' and \\backslashes\\" },
                { "NewLine", "Line1\r\nLine2\nLine3" },
                { "Unicode", "Tiếng Việt có dấu: Xin chào Việt Nam! 🇻🇳" }
            };

            string json = PacketSerializer.ToJson(dict);
            Assert.NotNull(json);

            var restored = PacketSerializer.FromJson<Dictionary<string, object>>(json);
            Assert.NotNull(restored);
            Assert.Equal("Text with \"quotes\" and 'single' and \\backslashes\\", restored["Quote"].ToString());
            Assert.Equal("Line1\r\nLine2\nLine3", restored["NewLine"].ToString());
            Assert.Equal("Tiếng Việt có dấu: Xin chào Việt Nam! 🇻🇳", restored["Unicode"].ToString());
        }

        private static void TestPacketHeaderParsing()
        {
            var packet = new Packet(PacketType.Login, "testuser", null, "{\"Username\":\"test\"}");
            string json = PacketSerializer.Serialize(packet);

            var parsed = PacketSerializer.Deserialize(json);
            Assert.Equal(PacketType.Login, parsed.Type);
            Assert.Equal("testuser", parsed.SenderId);
            Assert.Equal("{\"Username\":\"test\"}", parsed.Data);
        }

        private static void TestFramePacketAndConcurrentSerialization()
        {
            var packet = new Packet(PacketType.Message, "alice", "bob", "Single-buffer frame test 🚀");
            byte[] frame = PacketSerializer.FramePacket(packet);

            Assert.NotNull(frame);
            Assert.True(frame.Length > 4);

            int declaredLen = (frame[0] << 24) | (frame[1] << 16) | (frame[2] << 8) | frame[3];
            Assert.Equal(frame.Length - 4, declaredLen, "4-byte BigEndian length prefix must match UTF-8 payload length");

            string decodedJson = Encoding.UTF8.GetString(frame, 4, declaredLen);
            var restored = PacketSerializer.Deserialize(decodedJson);
            Assert.NotNull(restored);
            Assert.Equal(packet.Data, restored.Data);

            // Multi-threaded serialization stress check (ThreadLocal<JavaScriptSerializer>)
            Parallel.For(0, 64, i =>
            {
                var p = new Packet(PacketType.Message, "u" + i, "u" + (i + 1), "Payload #" + i);
                var f = PacketSerializer.FramePacket(p);
                int len = (f[0] << 24) | (f[1] << 16) | (f[2] << 8) | f[3];
                var back = PacketSerializer.Deserialize(Encoding.UTF8.GetString(f, 4, len));
                Assert.NotNull(back);
                Assert.Equal(p.Data, back.Data);
            });
        }
    }
}
