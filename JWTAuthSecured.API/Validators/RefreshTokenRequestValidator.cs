using FluentValidation;
using JWTAuthSecured.Core.ApiRequests;

namespace JWTAuthSecured.API.Validators
{
    public class RefreshTokenRequestValidator : AbstractValidator<RefreshTokenRequestModel>
    {
        public RefreshTokenRequestValidator()
        {
            RuleFor(x => x.RefreshToken).NotEmpty().NotNull().WithMessage("Refresh token is required");
        }
    }
}
