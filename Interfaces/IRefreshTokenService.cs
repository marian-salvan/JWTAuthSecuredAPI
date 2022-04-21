using JWTAuthSecuredAPI.Entities;
using Microsoft.AspNetCore.Identity;

namespace JWTAuthSecuredAPI.Interfaces
{
    public interface IRefreshTokenService
    {
        Task<IdentityUserToken<string>?> GetUserRefreshTokenAsync(string refreshToken);
        Task<int> UpsertUserRefreshTokenAsync(string userId, string refreshToken);
        Task<int> RemoveUserRefreshTokenAsync(string userId);
    }
}
