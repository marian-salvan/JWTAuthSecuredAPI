using JWTAuthSecured.Core.Models;
using JWTAuthSecured.Data.Entities;

namespace JWTAuthSecuredAPI.Interfaces
{
    public interface ITokenUtilsService
    {
        AccessTokenModel GenerateAccessToken(UserEntity userEntity, List<string> userRoles);
        string GenerateRefreshToken();
        bool ValidateRefreshToken(string refreshToken);
    }
}
