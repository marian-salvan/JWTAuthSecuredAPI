using System.ComponentModel.DataAnnotations;

namespace JWTAuthSecuredAPI.Models
{
    public class RefreshTokenRequestModel
    {
        [Required]
        public string RefreshToken { get; set; }
    }
}
