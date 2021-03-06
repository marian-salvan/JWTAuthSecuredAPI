using FluentValidation;
using JWTAuthSecured.Core.Entities;
using JWTAuthSecured.Core.Interfaces;
using JWTAuthSecured.Data;
using JWTAuthSecuredAPI.Helpers;
using JWTAuthSecuredAPI.Profiles;
using JWTAuthSecuredAPI.Services;
using JWTAuthSecuredAPI.Validators;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.IdentityModel.Tokens;
using System.Text;

namespace JWTAuthSecuredAPI.Extenstions
{
    public static class ServiceCollectionExtension
    {
        public static void AddDbServices(this IServiceCollection services)
        {
           services.TryAddScoped<IRefreshTokenService, RefreshTokenService>();
        }

        public static void AddHelperServices(this IServiceCollection services)
        {
            services.TryAddScoped<ITokenHelper, TokenHelper>();
            services.AddAutoMapper(typeof(AutoMapperProfile));
        }

        public static void AddUserManagementServices(this IServiceCollection services, IConfiguration configuration)
        {
            services.AddIdentityCore<UserEntity>(options =>
            {
                options.Password.RequireNonAlphanumeric = false;
                options.Password.RequireDigit = false;
                options.Password.RequireUppercase = false;
                options.Password.RequiredLength = 4;
            })
            .AddRoles<IdentityRole>()
            .AddEntityFrameworkStores<ApplicationDbContext>();

            services.TryAddScoped<UserManager<UserEntity>>();

            services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
                .AddJwtBearer(options =>
                {
                    options.TokenValidationParameters = new()
                    {
                        ClockSkew = TimeSpan.Zero,
                        ValidateIssuer = true,
                        ValidateAudience = true,
                        ValidateIssuerSigningKey = true,
                        ValidIssuer = configuration["Authentication:Issuer"],
                        ValidAudience = configuration["Authentication:Audience"],
                        IssuerSigningKey = new SymmetricSecurityKey(
                            Encoding.ASCII.GetBytes(configuration["Authentication:TokenSecret"]))
                    };
                }
            );
        }

        public static void AddValidators(this IServiceCollection services)
        {
            services.AddValidatorsFromAssemblyContaining<RegisterRequestValidator>();
        }
    }
}
