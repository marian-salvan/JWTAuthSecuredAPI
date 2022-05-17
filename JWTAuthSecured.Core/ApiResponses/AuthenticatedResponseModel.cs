namespace JWTAuthSecured.Core.ApiResponses
{
    public class AuthenticatedResponseModel : AccessTokenResposnse
    {
        public string RefreshToken { get; set; }
    }
}
