using System.ComponentModel.DataAnnotations;

namespace JWTAuthSecured.Core.ApiRequests
{
    public class RegisterRequestModel
    {
        public string Username { get; set; }

        public string Email { get; set; }

        public string Password { get; set; }
        public string Role { get; set; }
    }
}
