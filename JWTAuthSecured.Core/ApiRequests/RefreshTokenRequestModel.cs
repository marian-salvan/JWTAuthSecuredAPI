using System.ComponentModel.DataAnnotations;

namespace JWTAuthSecured.Core.ApiRequests
{
    public class RefreshTokenRequestModel
    {
        [Required]
        public string RefreshToken { get; set; }
    }
}
