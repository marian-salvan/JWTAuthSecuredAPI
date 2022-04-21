namespace JWTAuthSecuredAPI.Models
{
    public class AuthenticatedResponseModel : AccessTokenResposnse
    {
        public string RefreshToken { get; set; }
    }
}
