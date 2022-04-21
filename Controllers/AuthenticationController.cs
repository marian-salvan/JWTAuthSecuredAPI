using JWTAuthSecuredAPI.Entities;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Identity;
using JWTAuthSecuredAPI.Models;
using JWTAuthSecuredAPI.Constants;
using JWTAuthSecuredAPI.Interfaces;
using Microsoft.AspNetCore.Authorization;
using System.Security.Claims;

namespace JWTAuthSecuredAPI.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AuthenticationController : ControllerBase
    {
        private readonly UserManager<UserEntity> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IConfiguration _configuration;
        private readonly ITokenUtilsService _tokenUtilsService;
        private readonly IRefreshTokenService _refreshTokenService;

        public AuthenticationController(
            UserManager<UserEntity> userManager, 
            RoleManager<IdentityRole> roleManager,
            IConfiguration configuration,
            ITokenUtilsService tokenUtilsService,
            IRefreshTokenService refreshTokenService)
        {
            _userManager = userManager ?? throw new ArgumentNullException(nameof(userManager));
            _roleManager = roleManager ?? throw new ArgumentNullException(nameof(roleManager));
            _configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
            _tokenUtilsService = tokenUtilsService ?? throw new ArgumentNullException(nameof(tokenUtilsService));
            _refreshTokenService = refreshTokenService ?? throw new ArgumentNullException(nameof(refreshTokenService));
        }

        [HttpPost]
        [Route("register")]
        public async Task<IActionResult> RegisterUser([FromBody] RegisterRequestModel registerModel)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest();
            }

            var registrationUser = new UserEntity()
            {
                Email = registerModel.Email,
                UserName = registerModel.Username,
            };

            var user = await _userManager.FindByEmailAsync(registerModel.Email);

            if (user != null)
            {
                return BadRequest();
            }

            var result = await _userManager.CreateAsync(registrationUser, registerModel.Password);

            if (result.Succeeded)
            {
                switch (registerModel.Role)
                {
                    case UserRolesConstants.Admin:
                        await _userManager.AddToRoleAsync(registrationUser, UserRolesConstants.Admin);
                        break;
                    case UserRolesConstants.Reader:
                        await _userManager.AddToRoleAsync(registrationUser, UserRolesConstants.Reader);
                        break;

                    default: return StatusCode(StatusCodes.Status500InternalServerError);
                }

                return Created("/register", registrationUser);
            }

            return StatusCode(StatusCodes.Status500InternalServerError);
       }

        [HttpPost]
        [Route("login")]
        public async Task<IActionResult> LoginUser([FromBody] LoginRequestModel loginModel)
        {
            var user = await _userManager.FindByEmailAsync(loginModel.Email);

            if (user != null && await _userManager.CheckPasswordAsync(user, loginModel.Password))
            {
                var userRoles = await _userManager.GetRolesAsync(user);

                var accessToken = _tokenUtilsService.GenerateAccessToken(user, userRoles.ToList());
                var refreshToken = _tokenUtilsService.GenerateRefreshToken();

                //save refresh token
                await _refreshTokenService.UpsertUserRefreshTokenAsync(user.Id, refreshToken);

                return Ok(new AuthenticatedResponseModel
                {
                    AccessToken = accessToken.Token,
                    AccessTokenExpirationTime = accessToken.ExpirationDate,
                    RefreshToken = refreshToken,
                });
            }

            return Unauthorized();
        }

        [HttpPost("refresh")]
        public async Task<IActionResult> RefreshAccessToken([FromBody] RefreshTokenRequestModel refreshTokenModel)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest();
            }

            var validToken = _tokenUtilsService.ValidateRefreshToken(refreshTokenModel.RefreshToken);

            if (!validToken)
            {
                return Forbid();
            }

            var savedToken = await _refreshTokenService.GetUserRefreshTokenAsync(refreshTokenModel.RefreshToken);

            if (savedToken == null)
            {
                return Forbid();
            }

            var user = await _userManager.FindByIdAsync(savedToken.UserId);
            if (user == null)
            {
                return Forbid();
            }

            var userRoles = await _userManager.GetRolesAsync(user);
            var newAccessToken = _tokenUtilsService.GenerateAccessToken(user, userRoles.ToList());
;

            return Ok(new AccessTokenResposnse
            {
                AccessToken = newAccessToken.Token,
                AccessTokenExpirationTime = newAccessToken.ExpirationDate
            });        
        }

        [Authorize]
        [HttpDelete]
        [Route("revoke")]
        public async Task<IActionResult> Revoke()
        {
            var email = HttpContext.User.FindFirstValue(ClaimTypes.Email);
            var user = await _userManager.FindByEmailAsync(email);

            if (user == null) return BadRequest("Invalid user email");

            await _refreshTokenService.RemoveUserRefreshTokenAsync(user.Id);

            return NoContent();
        }
    }
}
