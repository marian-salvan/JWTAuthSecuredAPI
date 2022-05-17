using System.Security.Claims;

namespace JWTAuthSecured.Core.Models
{
    public class TokenGenerationModel
    {
        public string Secret { get; set; }
        public string Issuer { get; set; }
        public string Audience { get; set; }
        public List<Claim> Claims { get; set; } 
    }
}
