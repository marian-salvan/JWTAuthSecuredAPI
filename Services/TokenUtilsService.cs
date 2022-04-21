using JWTAuthSecuredAPI.Entities;
using JWTAuthSecuredAPI.Interfaces;
using JWTAuthSecuredAPI.Models;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace JWTAuthSecuredAPI.Services
{
    public class TokenUtilsService : ITokenUtilsService
    {
        private readonly IConfiguration _configuration;

        public TokenUtilsService(IConfiguration configuration)
        {
            _configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
        }

        public AccessTokenModel GenerateAccessToken(UserEntity user, List<string> userRoles)
        {
            var securityKey = new SymmetricSecurityKey(
                               Encoding.ASCII.GetBytes(_configuration["Authentication:TokenSecret"]));
            var signingCredentials = new SigningCredentials(
                securityKey, SecurityAlgorithms.HmacSha256);

            var claimsForToken = new List<Claim>
            {
                new Claim("id", user.Id),
                new Claim(ClaimTypes.Name, user.UserName),
                new Claim(ClaimTypes.Email, user.Email),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            };

            foreach (var userRole in userRoles)
            {
                claimsForToken.Add(new Claim(ClaimTypes.Role, userRole));
            }

            var expirationDate = DateTime.UtcNow.AddSeconds(30);

            var jwtSecurityToken = new JwtSecurityToken(
                          _configuration["Authentication:Issuer"],
                          _configuration["Authentication:Audience"],
                          claimsForToken,
                          DateTime.UtcNow,
                          expirationDate,
                          signingCredentials);

            var tokenToReturn = new JwtSecurityTokenHandler()
               .WriteToken(jwtSecurityToken);

            return new AccessTokenModel
            {
                Token = tokenToReturn,
                ExpirationDate = expirationDate
            };
        }

        public string GenerateRefreshToken()
        {
            var securityKey = new SymmetricSecurityKey(
                               Encoding.ASCII.GetBytes(_configuration["Authentication:RefreshTokenSecret"]));
            var signingCredentials = new SigningCredentials(
                securityKey, SecurityAlgorithms.HmacSha256);

            var jwtSecurityToken = new JwtSecurityToken(
                          _configuration["Authentication:Issuer"],
                          _configuration["Authentication:Audience"],
                          null,
                          DateTime.UtcNow,
                          DateTime.UtcNow.AddDays(30),
                          signingCredentials);

            var tokenToReturn = new JwtSecurityTokenHandler()
               .WriteToken(jwtSecurityToken);

            return tokenToReturn;
        }

        public bool ValidateRefreshToken(string refreshToken)
        {
            TokenValidationParameters validationParameters = new TokenValidationParameters()
            {
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Authentication:RefreshTokenSecret"])),
                ValidIssuer = _configuration["Authentication:Issuer"],
                ValidAudience = _configuration["Authentication:Audience"],
                ValidateIssuerSigningKey = true,
                ValidateIssuer = true,
                ValidateAudience = true,
                ClockSkew = TimeSpan.Zero
            };

            JwtSecurityTokenHandler tokenHandler = new JwtSecurityTokenHandler();

            try
            {
                tokenHandler.ValidateToken(refreshToken, validationParameters, out SecurityToken validatedToken);
                return true;
            }
            catch (Exception)
            {
                return false;
            }
        }
    }
}
