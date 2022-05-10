using System.ComponentModel.DataAnnotations;

namespace JWTAuthSecuredAPI.Models
{
    public class LoginRequestModel
    {
        [EmailAddress]
        [Required(ErrorMessage = "Email is required")]
        public string Email { get; set; }

        [Required(ErrorMessage = "Password is required")]
        public string Password { get; set; }
    }
}
