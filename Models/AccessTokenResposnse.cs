namespace JWTAuthSecuredAPI.Models
{
    public class AccessTokenResposnse
    {
        public string AccessToken { get; set; }
        public DateTime AccessTokenExpirationTime { get; set; }
    }
}
