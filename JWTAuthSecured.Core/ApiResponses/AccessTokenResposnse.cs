namespace JWTAuthSecured.Core.ApiResponses
{
    public class AccessTokenResposnse : BaseReponseModel
    {
        public string AccessToken { get; set; }
        public DateTime AccessTokenExpirationTime { get; set; }
    }
}
