namespace JWTAuthSecured.Core.ApiResponses
{
    public class AccessTokenResposnse
    {
        public string AccessToken { get; set; }
        public DateTime AccessTokenExpirationTime { get; set; }
    }
}
