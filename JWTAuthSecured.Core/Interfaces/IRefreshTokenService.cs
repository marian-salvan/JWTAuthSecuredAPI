using Microsoft.AspNetCore.Identity;

namespace JWTAuthSecured.Core.Interfaces
{
    public interface IRefreshTokenService
    {
        Task<IdentityUserToken<string>?> GetUserRefreshTokenAsync(string refreshToken);
        Task<int> UpsertUserRefreshTokenAsync(string userId, string refreshToken);
        Task<int> RemoveUserRefreshTokenAsync(string userId);
    }
}
