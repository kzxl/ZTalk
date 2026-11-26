using System;
using System.IO;
using ZTalk.Shared.Constants;
using ZTalk.Shared.DTOs;
using ZTalk.Shared.Protocol;

namespace ZTalk.Client.Services
{
    /// <summary>
    /// Truyền file qua TCP: chia chunk + mã hoá AES (khi đã trao đổi khoá ECDH)
    /// Flow: FileHeader → FileChunk x N → FileComplete
    /// </summary>
    public class FileTransferService : IFileTransferService
    {
        private readonly TcpClientService _tcpService;
        private readonly ChatService _chatService;

        public event Action<string, int, int> OnSendProgress; // fileName, current, total

        public FileTransferService(TcpClientService tcpService, ChatService chatService)
        {
            _tcpService = tcpService;
            _chatService = chatService;
        }

        /// <summary>
        /// Gửi file đến receiver. Chia thành chunk, mã hoá AES nếu có shared key.
        /// </summary>
        public void SendFile(string receiverId, string filePath)
        {
            if (string.IsNullOrEmpty(filePath) || !File.Exists(filePath)) return;

            var fileInfo = new FileInfo(filePath);
            int totalChunks = (int)Math.Ceiling((double)fileInfo.Length / AppConstants.FileChunkSize);
            string transferId = Guid.NewGuid().ToString("N").Substring(0, 8);

            // 1. Gửi FileHeader
            var headerDto = new FileTransferDTO
            {
                FileName = fileInfo.Name,
                FileSize = fileInfo.Length,
                TotalChunks = totalChunks,
                TransferId = transferId
            };
            var headerPacket = new Packet(PacketType.FileHeader, _chatService.CurrentUserId, receiverId, PacketSerializer.ToJson(headerDto));
            _tcpService.SendPacket(headerPacket);

            // 2. Gửi từng chunk (zero redundant Array.Copy on plaintext chunks; E2EE AES when shared key exists)
            using (var stream = File.OpenRead(filePath))
            {
                var buffer = new byte[AppConstants.FileChunkSize];
                int chunkIndex = 0;

                while (true)
                {
                    int bytesRead = stream.Read(buffer, 0, buffer.Length);
                    if (bytesRead == 0) break;

                    string base64Data;
                    bool isEncrypted;
                    byte[] encryptedBytes;

                    if (_chatService.TryEncryptBytes(receiverId, buffer, 0, bytesRead, out encryptedBytes))
                    {
                        base64Data = Convert.ToBase64String(encryptedBytes);
                        isEncrypted = true;
                    }
                    else
                    {
                        base64Data = Convert.ToBase64String(buffer, 0, bytesRead);
                        isEncrypted = false;
                    }

                    var chunkDto = new FileTransferDTO
                    {
                        TransferId = transferId,
                        ChunkIndex = chunkIndex,
                        ChunkData = base64Data,
                        IsEncrypted = isEncrypted
                    };

                    var chunkPacket = new Packet(PacketType.FileChunk, _chatService.CurrentUserId, receiverId, PacketSerializer.ToJson(chunkDto));
                    _tcpService.SendPacket(chunkPacket);

                    chunkIndex++;
                    OnSendProgress?.Invoke(fileInfo.Name, chunkIndex, totalChunks);
                }
            }

            // 3. Gửi FileComplete
            var completeDto = new FileTransferDTO { TransferId = transferId };
            var completePacket = new Packet(PacketType.FileComplete, _chatService.CurrentUserId, receiverId, PacketSerializer.ToJson(completeDto));
            _tcpService.SendPacket(completePacket);
        }
    }
}
