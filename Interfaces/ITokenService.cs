using JWTAuthSecuredAPI.Entities;
using JWTAuthSecuredAPI.Models;

namespace JWTAuthSecuredAPI.Interfaces
{
    public interface ITokenUtilsService
    {
        AccessTokenModel GenerateAccessToken(UserEntity userEntity, List<string> userRoles);
        string GenerateRefreshToken();
        bool ValidateRefreshToken(string refreshToken);
    }
}
