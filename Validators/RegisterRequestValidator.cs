using FluentValidation;
using JWTAuthSecuredAPI.Constants;
using JWTAuthSecuredAPI.Models;

namespace JWTAuthSecuredAPI.Validators
{
    public class RegisterRequestValidator : AbstractValidator<RegisterRequestModel>
    {
        public RegisterRequestValidator()
        {
            RuleFor(x => x.Username).NotEmpty().NotNull().WithMessage("UserNname is required");
            RuleFor(x => x.Email).NotEmpty().NotNull().EmailAddress().WithMessage("Email is required");
            RuleFor(x => x.Password).NotEmpty().NotNull().WithMessage("Password is required");
            RuleFor(x => x.Role).NotEmpty().NotNull().WithMessage("Role is required");
            RuleFor(x => x.Role).Must(x => x == UserRolesConstants.Admin || x == UserRolesConstants.Reader)
                .WithMessage($"Role must be {UserRolesConstants.Admin} or {UserRolesConstants.Reader}");
        }
    }
}
