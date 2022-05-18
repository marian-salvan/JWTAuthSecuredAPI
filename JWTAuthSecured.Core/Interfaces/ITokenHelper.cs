using JWTAuthSecured.Core.Entities;
using JWTAuthSecured.Core.Models;

namespace JWTAuthSecured.Core.Interfaces
{
    public interface ITokenHelper
    {
        AccessTokenModel GenerateAccessToken(UserEntity userEntity, List<string> userRoles);
        string GenerateRefreshToken();
        bool ValidateRefreshToken(string refreshToken);
    }
}
