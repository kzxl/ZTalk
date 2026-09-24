using ZTalk.Shared.DTOs;
using ZTalk.Server.Models;

namespace ZTalk.Server.Services
{
    /// <summary>
    /// Interface xác thực user
    /// </summary>
    public interface IAuthService
    {
        /// <summary>Xác thực đăng nhập</summary>
        LoginResponseDTO Authenticate(LoginRequestDTO request);

        /// <summary>Đăng ký tài khoản mới</summary>
        LoginResponseDTO Register(LoginRequestDTO request);
    }
}
