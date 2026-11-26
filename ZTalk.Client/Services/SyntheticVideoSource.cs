using System;
using System.Diagnostics;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Drawing.Imaging;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace ZTalk.Client.Services
{
    /// <summary>
    /// Nguồn phát video giả lập động cho môi trường thử nghiệm và demo.
    /// Pre-render nền tĩnh và tái sử dụng toàn bộ GDI+ resource + MemoryStream để tránh GC/handle churn.
    /// </summary>
    public class SyntheticVideoSource : IVideoSource
    {
        private CancellationTokenSource _cts;
        private Task _workerTask;
        private readonly string _displayName;
        private int _frameIndex;
        private volatile bool _isRunning;
        private readonly ImageCodecInfo _jpegEncoder;
        private readonly EncoderParameters _encoderParams;

        public event Action<byte[]> OnFrameCaptured;
        public bool IsRunning => _isRunning;
        public string SourceName => "Synthetic Demo Camera";

        public SyntheticVideoSource(string displayName = "Demo User")
        {
            _displayName = displayName ?? "Demo User";

            // Thiết lập JPEG encoder chất lượng 65% để tối ưu kích thước gói tin qua UDP (5-10 KB/frame)
            _jpegEncoder = GetEncoder(ImageFormat.Jpeg);
            _encoderParams = new EncoderParameters(1);
            _encoderParams.Param[0] = new EncoderParameter(Encoder.Quality, 65L);
        }

        public void Start(int width = 320, int height = 240, int targetFps = 15)
        {
            if (_isRunning) return;

            _isRunning = true;
            _cts = new CancellationTokenSource();
            int delayMs = Math.Max(10, 1000 / Math.Max(1, targetFps));
            var ct = _cts.Token;

            _workerTask = Task.Run(() => CaptureLoop(width, height, delayMs, ct));
        }

        public void Stop()
        {
            if (!_isRunning) return;

            _isRunning = false;
            var cts = Interlocked.Exchange(ref _cts, null);
            try
            {
                cts?.Cancel();
                _workerTask?.Wait(1000);
            }
            catch { }
            finally
            {
                if (_workerTask == null || _workerTask.IsCompleted)
                {
                    cts?.Dispose();
                }
            }
        }

        private void CaptureLoop(int width, int height, int delayMs, CancellationToken ct)
        {
            int centerX = width / 2;
            int centerY = height / 2 - 15;
            int avatarRadius = 26;
            int barCount = 14;
            int barWidth = 4;
            int barGap = 3;
            int totalBarWidth = barCount * (barWidth + barGap);
            int startBarX = centerX - totalBarWidth / 2;
            int barBaseY = height - 38;
            string initial = !string.IsNullOrEmpty(_displayName) ? _displayName.Substring(0, 1).ToUpper() : "U";
            string liveTag = $"LIVE • {1000 / delayMs} FPS";

            // Pre-render static background (gradient + radar grid + avatar + name + red badge + LIVE label) once
            using (var staticBg = new Bitmap(width, height, PixelFormat.Format24bppRgb))
            using (var bgG = Graphics.FromImage(staticBg))
            using (var bmp = new Bitmap(width, height, PixelFormat.Format24bppRgb))
            using (var g = Graphics.FromImage(bmp))
            using (var pulsePen = new Pen(Color.FromArgb(120, 0, 180, 255), 2f))
            using (var barBrush = new SolidBrush(Color.FromArgb(70, 200, 120)))
            using (var hudFont = new Font("Consolas", 8.5F))
            using (var hudBrush = new SolidBrush(Color.FromArgb(220, 220, 230)))
            using (var ms = new MemoryStream(16384))
            {
                bgG.SmoothingMode = SmoothingMode.AntiAlias;
                RenderStaticBackdrop(bgG, width, height, centerX, centerY, avatarRadius, initial, liveTag, hudFont, hudBrush);

                g.SmoothingMode = SmoothingMode.AntiAlias;
                var sw = new Stopwatch();

                while (!ct.IsCancellationRequested && _isRunning)
                {
                    sw.Restart();
                    _frameIndex++;

                    // 1. Blit cached static background
                    g.DrawImageUnscaled(staticBg, 0, 0);

                    // 2. Dynamic pulsing radar ring
                    float pulseRadius = 35 + (float)(Math.Sin(_frameIndex * 0.15) * 8);
                    g.DrawEllipse(pulsePen, centerX - pulseRadius, centerY - pulseRadius, pulseRadius * 2, pulseRadius * 2);

                    // 3. Dynamic voice equalizer bars
                    for (int i = 0; i < barCount; i++)
                    {
                        float h = (float)(Math.Sin(_frameIndex * 0.25 + i * 0.5) * 10 + 12);
                        g.FillRectangle(barBrush, startBarX + i * (barWidth + barGap), barBaseY - h, barWidth, h);
                    }

                    // 4. Live clock
                    string clockText = DateTime.Now.ToString("HH:mm:ss.fff");
                    var clockSize = g.MeasureString(clockText, hudFont);
                    g.DrawString(clockText, hudFont, hudBrush, width - clockSize.Width - 10, 9);

                    // 5. Encode JPEG reusing MemoryStream
                    ms.SetLength(0);
                    ms.Position = 0;
                    if (_jpegEncoder != null)
                        bmp.Save(ms, _jpegEncoder, _encoderParams);
                    else
                        bmp.Save(ms, ImageFormat.Jpeg);

                    OnFrameCaptured?.Invoke(ms.ToArray());

                    // Frame pacing
                    int elapsed = (int)sw.ElapsedMilliseconds;
                    int sleepTime = Math.Max(1, delayMs - elapsed);
                    if (ct.WaitHandle.WaitOne(sleepTime))
                        break;
                }
            }
        }

        private void RenderStaticBackdrop(
            Graphics g, int width, int height,
            int centerX, int centerY, int avatarRadius,
            string initial, string liveTag, Font hudFont, Brush hudBrush)
        {
            using (var bgBrush = new LinearGradientBrush(
                new Rectangle(0, 0, width, height),
                Color.FromArgb(20, 24, 38),
                Color.FromArgb(12, 14, 20),
                45f))
            {
                g.FillRectangle(bgBrush, 0, 0, width, height);
            }

            using (var gridPen = new Pen(Color.FromArgb(30, 80, 140, 220), 1f))
            {
                for (int x = 20; x < width; x += 30)
                    g.DrawLine(gridPen, x, 0, x, height);
                for (int y = 20; y < height; y += 30)
                    g.DrawLine(gridPen, 0, y, width, y);
            }

            using (var avatarBrush = new LinearGradientBrush(
                new Rectangle(centerX - avatarRadius, centerY - avatarRadius, avatarRadius * 2, avatarRadius * 2),
                Color.FromArgb(0, 140, 255),
                Color.FromArgb(120, 40, 200),
                -45f))
            {
                g.FillEllipse(avatarBrush, centerX - avatarRadius, centerY - avatarRadius, avatarRadius * 2, avatarRadius * 2);
            }

            using (var fontInitial = new Font("Segoe UI", 18F, FontStyle.Bold))
            using (var fontName = new Font("Segoe UI Semibold", 10.5F, FontStyle.Bold))
            using (var textBrush = new SolidBrush(Color.White))
            using (var badgeBrush = new SolidBrush(Color.FromArgb(220, 40, 40)))
            {
                var initSize = g.MeasureString(initial, fontInitial);
                g.DrawString(initial, fontInitial, textBrush, centerX - initSize.Width / 2, centerY - initSize.Height / 2);

                var nameSize = g.MeasureString(_displayName, fontName);
                g.DrawString(_displayName, fontName, textBrush, centerX - nameSize.Width / 2, centerY + avatarRadius + 8);

                g.FillEllipse(badgeBrush, 12, 12, 8, 8);
                g.DrawString(liveTag, hudFont, hudBrush, 24, 9);
            }
        }

        private static ImageCodecInfo GetEncoder(ImageFormat format)
        {
            var codecs = ImageCodecInfo.GetImageEncoders();
            foreach (var codec in codecs)
            {
                if (codec.FormatID == format.Guid)
                    return codec;
            }
            return null;
        }

        public void Dispose()
        {
            Stop();
            _encoderParams?.Dispose();
        }
    }
}
