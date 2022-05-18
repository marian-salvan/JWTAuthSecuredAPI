using System.ComponentModel.DataAnnotations;

namespace JWTAuthSecured.Core.ApiRequests
{
    public class RefreshTokenRequestModel
    {
        public string RefreshToken { get; set; }
    }
}
