using System;
using System.Diagnostics;
using System.Threading;

namespace ZTalk.Client.Services
{
    public class AudioFrameHeader
    {
        public const int HeaderSize = 18;

        public uint SequenceNumber { get; set; }
        public uint TimestampMs { get; set; }
        public int SampleRate { get; set; } = 48000;
        public int Channels { get; set; } = 1;
        public int PayloadSize { get; set; }
        public bool IsVoiceDetected { get; set; }

        /// <summary>
        /// Zero-extra-allocation little-endian header encoding directly into destination buffer.
        /// Layout (18 bytes): [0..3] Seq(u32), [4..7] TsMs(u32), [8..11] SampleRate(i32),
        /// [12..13] Channels(u16), [14..15] PayloadSize(u16), [16] VoiceFlag(u8), [17] Reserved(0).
        /// </summary>
        public void WriteTo(byte[] destination, int offset = 0)
        {
            if (destination == null || destination.Length - offset < HeaderSize)
                throw new ArgumentException("Destination buffer is too small for audio frame header.", nameof(destination));

            WriteUInt32LE(destination, offset, SequenceNumber);
            WriteUInt32LE(destination, offset + 4, TimestampMs);
            WriteUInt32LE(destination, offset + 8, (uint)SampleRate);

            ushort ch = (ushort)Math.Max(0, Math.Min(ushort.MaxValue, Channels));
            ushort len = (ushort)Math.Max(0, Math.Min(ushort.MaxValue, PayloadSize));
            destination[offset + 12] = (byte)(ch & 0xFF);
            destination[offset + 13] = (byte)(ch >> 8);
            destination[offset + 14] = (byte)(len & 0xFF);
            destination[offset + 15] = (byte)(len >> 8);
            destination[offset + 16] = (byte)(IsVoiceDetected ? 1 : 0);
            destination[offset + 17] = 0;
        }

        public byte[] Serialize()
        {
            var header = new byte[HeaderSize];
            WriteTo(header, 0);
            return header;
        }

        public static AudioFrameHeader Deserialize(byte[] data, int offset = 0)
        {
            if (data == null || offset < 0 || data.Length - offset < HeaderSize)
            {
                throw new ArgumentException("Invalid audio frame header buffer size.");
            }

            return new AudioFrameHeader
            {
                SequenceNumber = ReadUInt32LE(data, offset),
                TimestampMs = ReadUInt32LE(data, offset + 4),
                SampleRate = (int)ReadUInt32LE(data, offset + 8),
                Channels = data[offset + 12] | (data[offset + 13] << 8),
                PayloadSize = data[offset + 14] | (data[offset + 15] << 8),
                IsVoiceDetected = data[offset + 16] == 1
            };
        }

        private static void WriteUInt32LE(byte[] buf, int offset, uint value)
        {
            buf[offset] = (byte)(value & 0xFF);
            buf[offset + 1] = (byte)((value >> 8) & 0xFF);
            buf[offset + 2] = (byte)((value >> 16) & 0xFF);
            buf[offset + 3] = (byte)((value >> 24) & 0xFF);
        }

        private static uint ReadUInt32LE(byte[] buf, int offset)
        {
            return (uint)(buf[offset]
                | (buf[offset + 1] << 8)
                | (buf[offset + 2] << 16)
                | (buf[offset + 3] << 24));
        }
    }

    public class VoiceCallSessionService
    {
        private uint _nextSeq = 1;
        private uint _expectedIncomingSeq = 1;
        private readonly Stopwatch _clock = Stopwatch.StartNew();

        private long _packetsSent;
        private long _packetsReceived;
        private long _packetsLost;
        private long _silenceFramesSuppressed;

        public bool IsMuted { get; set; }
        public bool IsDeafened { get; set; }
        public float VadThreshold { get; set; } = 0.015f; // RMS amplitude silence suppression

        public long PacketsSent => Interlocked.Read(ref _packetsSent);
        public long PacketsReceived => Interlocked.Read(ref _packetsReceived);
        public long PacketsLost => Interlocked.Read(ref _packetsLost);
        public long SilenceFramesSuppressed => Interlocked.Read(ref _silenceFramesSuppressed);

        public event Action<byte[]> OnOutgoingAudioPacketReady;
        public event Action<byte[], AudioFrameHeader> OnIncomingAudioFrame;

        /// <summary>
        /// Processes raw or encoded audio buffer from microphone.
        /// Applies VAD to suppress silence, applies Mute, builds packet in a single buffer allocation.
        /// </summary>
        public bool ProcessOutgoingAudio(byte[] audioData, int sampleRate = 48000, int channels = 1)
        {
            if (audioData == null || audioData.Length == 0 || audioData.Length > ushort.MaxValue || IsMuted)
            {
                return false;
            }

            // Calculate RMS energy (assuming 16-bit PCM if uncompressed)
            float rms = CalculateRms(audioData);
            if (rms < VadThreshold)
            {
                Interlocked.Increment(ref _silenceFramesSuppressed);
                return false; // Silence suppressed to preserve bandwidth
            }

            var header = new AudioFrameHeader
            {
                SequenceNumber = _nextSeq++,
                TimestampMs = (uint)_clock.ElapsedMilliseconds,
                SampleRate = sampleRate,
                Channels = channels,
                PayloadSize = audioData.Length,
                IsVoiceDetected = true
            };

            // Single packet allocation: write header directly into packet[0..17] + copy audio payload
            var packet = new byte[AudioFrameHeader.HeaderSize + audioData.Length];
            header.WriteTo(packet, 0);
            Buffer.BlockCopy(audioData, 0, packet, AudioFrameHeader.HeaderSize, audioData.Length);

            Interlocked.Increment(ref _packetsSent);
            OnOutgoingAudioPacketReady?.Invoke(packet);
            return true;
        }

        /// <summary>
        /// Processes received network packet and dispatches to audio output.
        /// </summary>
        public bool ProcessIncomingAudioPacket(byte[] packetBytes)
        {
            if (packetBytes == null || packetBytes.Length < AudioFrameHeader.HeaderSize || IsDeafened)
            {
                return false;
            }

            var header = AudioFrameHeader.Deserialize(packetBytes, 0);

            // Track packet loss without rewinding sequence watermark on late/out-of-order packets
            if (header.SequenceNumber > _expectedIncomingSeq)
            {
                Interlocked.Add(ref _packetsLost, header.SequenceNumber - _expectedIncomingSeq);
            }
            if (header.SequenceNumber >= _expectedIncomingSeq)
            {
                _expectedIncomingSeq = header.SequenceNumber + 1;
            }

            Interlocked.Increment(ref _packetsReceived);

            int availablePayload = packetBytes.Length - AudioFrameHeader.HeaderSize;
            int payloadLen = header.PayloadSize > 0
                ? Math.Min(header.PayloadSize, availablePayload)
                : availablePayload;

            if (payloadLen > 0)
            {
                var payload = new byte[payloadLen];
                Buffer.BlockCopy(packetBytes, AudioFrameHeader.HeaderSize, payload, 0, payloadLen);
                OnIncomingAudioFrame?.Invoke(payload, header);
                return true;
            }

            return false;
        }

        private static float CalculateRms(byte[] buffer)
        {
            if (buffer.Length < 2) return 0f;

            const double invScale = 1.0 / 32768.0;
            double sumSquares = 0;
            int samples = buffer.Length >> 1;
            int limit = samples << 1;

            for (int i = 0; i < limit; i += 2)
            {
                short sample = (short)(buffer[i] | (buffer[i + 1] << 8));
                double normalized = sample * invScale;
                sumSquares += normalized * normalized;
            }

            return (float)Math.Sqrt(sumSquares / samples);
        }
    }
}
