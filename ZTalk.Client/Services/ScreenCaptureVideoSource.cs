using System;
using System.Diagnostics;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Drawing.Imaging;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace ZTalk.Client.Services
{
    /// <summary>
    /// Nguồn phát video chia sẻ màn hình máy tính thời gian thực.
    /// Sử dụng GDI+ CopyFromScreen, thu nhỏ và nén JPEG stream qua P2P/Relay.
    /// </summary>
    public class ScreenCaptureVideoSource : IVideoSource
    {
        private CancellationTokenSource _cts;
        private Task _workerTask;
        private volatile bool _isRunning;
        private readonly ImageCodecInfo _jpegEncoder;
        private readonly EncoderParameters _encoderParams;

        public event Action<byte[]> OnFrameCaptured;
        public bool IsRunning => _isRunning;
        public string SourceName => "Screen Share";

        public ScreenCaptureVideoSource()
        {
            _jpegEncoder = GetEncoder(ImageFormat.Jpeg);
            _encoderParams = new EncoderParameters(1);
            _encoderParams.Param[0] = new EncoderParameter(Encoder.Quality, 60L);
        }

        public void Start(int width = 480, int height = 270, int targetFps = 12)
        {
            if (_isRunning) return;

            _isRunning = true;
            _cts = new CancellationTokenSource();
            int delayMs = Math.Max(20, 1000 / Math.Max(1, targetFps));
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

        private void CaptureLoop(int targetWidth, int targetHeight, int delayMs, CancellationToken ct)
        {
            var bounds = Screen.PrimaryScreen.Bounds;

            using (var screenBmp = new Bitmap(bounds.Width, bounds.Height, PixelFormat.Format24bppRgb))
            using (var screenG = Graphics.FromImage(screenBmp))
            using (var scaledBmp = new Bitmap(targetWidth, targetHeight, PixelFormat.Format24bppRgb))
            using (var scaledG = Graphics.FromImage(scaledBmp))
            using (var ms = new MemoryStream(32768))
            {
                scaledG.InterpolationMode = InterpolationMode.Bilinear;
                var sw = new Stopwatch();

                while (!ct.IsCancellationRequested && _isRunning)
                {
                    sw.Restart();

                    try
                    {
                        // 1. Chụp toàn màn hình
                        screenG.CopyFromScreen(bounds.X, bounds.Y, 0, 0, bounds.Size, CopyPixelOperation.SourceCopy);

                        // 2. Scale về kích thước truyền stream
                        scaledG.DrawImage(screenBmp, 0, 0, targetWidth, targetHeight);

                        // 3. Nén JPEG tái sử dụng MemoryStream
                        ms.SetLength(0);
                        ms.Position = 0;
                        if (_jpegEncoder != null)
                            scaledBmp.Save(ms, _jpegEncoder, _encoderParams);
                        else
                            scaledBmp.Save(ms, ImageFormat.Jpeg);

                        OnFrameCaptured?.Invoke(ms.ToArray());
                    }
                    catch { }

                    int elapsed = (int)sw.ElapsedMilliseconds;
                    int sleepTime = Math.Max(1, delayMs - elapsed);
                    if (ct.WaitHandle.WaitOne(sleepTime))
                        break;
                }
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
