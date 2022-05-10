namespace JWTAuthSecuredAPI.Models
{
    public class AccessTokenModel
    {
        public string Token { get; set; }
        public DateTime ExpirationDate { get; set; }
    }
}
