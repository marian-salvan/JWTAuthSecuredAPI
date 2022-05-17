using JWTAuthSecured.Core.Constants;
using JWTAuthSecured.Core.Interfaces;
using JWTAuthSecured.Data;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace JWTAuthSecuredAPI.Services
{
    public class RefreshTokenService : IRefreshTokenService
    {
        private readonly ApplicationDbContext _applicationDbContext;

        public RefreshTokenService(ApplicationDbContext applicationDbContext)
        {
            _applicationDbContext = applicationDbContext ?? throw new ArgumentNullException(nameof(applicationDbContext));
        }

        public async Task<IdentityUserToken<string>?> GetUserRefreshTokenAsync(string refreshToken)
        {
            return await _applicationDbContext.UserTokens.SingleOrDefaultAsync(x => x.Value == refreshToken);
        }

        public async Task<int> UpsertUserRefreshTokenAsync(string userId, string refreshToken)
        {
            var existingUserToken = await _applicationDbContext.UserTokens.FindAsync(userId, UserTokenConstants.LocalProvider, UserTokenConstants.Refresh);

            if (existingUserToken == null)
            {
                _applicationDbContext.UserTokens.Add(new IdentityUserToken<string>
                {
                    UserId = userId,
                    LoginProvider = UserTokenConstants.LocalProvider,
                    Name = UserTokenConstants.Refresh,
                    Value = refreshToken
                });
            } 
            else
            {
                existingUserToken.Value = refreshToken;
                _applicationDbContext.UserTokens.Update(existingUserToken);
            }

            return await _applicationDbContext.SaveChangesAsync();
        }


        public async Task<int> RemoveUserRefreshTokenAsync(string userId)
        {
            var userToken = await _applicationDbContext.UserTokens.FindAsync(userId, UserTokenConstants.LocalProvider,  UserTokenConstants.Refresh);

            if (userToken == null)
            {
                throw new ArgumentNullException(nameof(userId));
            }

            _applicationDbContext.UserTokens.Remove(userToken);

            return await _applicationDbContext.SaveChangesAsync();
        }
    }
}
