using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Authorization;
using System.Security.Claims;
using FluentValidation;
using AutoMapper;
using JWTAuthSecured.Core.ApiResponses;
using JWTAuthSecured.Core.ApiRequests;
using JWTAuthSecured.Core.Constants;
using JWTAuthSecured.Core.Entities;
using JWTAuthSecured.Core.Interfaces;

namespace JWTAuthSecuredAPI.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AuthenticationController : ControllerBase
    {
        private readonly UserManager<UserEntity> _userManager;
        private readonly ITokenHelper _tokenHelper;
        private readonly IRefreshTokenService _refreshTokenService;
        private readonly IMapper _mapper;
        private readonly IValidator<RegisterRequestModel> _registerRequestValidator;
        private readonly IValidator<LoginRequestModel> _loginRequestValidator;
        private readonly IValidator<RefreshTokenRequestModel> _refreshTokenRequestValidator;

        public AuthenticationController(UserManager<UserEntity> userManager, ITokenHelper tokenHelper,
            IRefreshTokenService refreshTokenService, IMapper mapper,
            IValidator<RegisterRequestModel> registerRequestValidator,
            IValidator<LoginRequestModel> loginRequestValidator,
            IValidator<RefreshTokenRequestModel> refreshTokenRequestValidator)
        {
            _userManager = userManager ?? throw new ArgumentNullException(nameof(userManager));
            _tokenHelper = tokenHelper ?? throw new ArgumentNullException(nameof(tokenHelper));
            _refreshTokenService = refreshTokenService ?? throw new ArgumentNullException(nameof(refreshTokenService));
            _mapper = mapper ?? throw new ArgumentNullException(nameof(mapper));
            _registerRequestValidator = registerRequestValidator ?? throw new ArgumentNullException(nameof(registerRequestValidator));
            _loginRequestValidator = loginRequestValidator ?? throw new ArgumentNullException(nameof(loginRequestValidator));
            _refreshTokenRequestValidator = refreshTokenRequestValidator ?? throw new ArgumentNullException(nameof(refreshTokenRequestValidator));
        }

        [HttpPost]
        [Route("register")]
        public async Task<IActionResult> RegisterUser([FromBody] RegisterRequestModel registerModel)
        {
     
            var validationResult = await _registerRequestValidator.ValidateAsync(registerModel);

            if (!validationResult.IsValid)
            {
                return BadRequest(new BaseReponseModel(ErrorCodes.InvalidRequest, 
                    string.Join(";", validationResult.Errors.Select(x => x.ErrorMessage).ToList())));
            }

            var userEnity = _mapper.Map<UserEntity>(registerModel);

            var user = await _userManager.FindByEmailAsync(registerModel.Email);

            if (user != null)
            {
                return BadRequest(new BaseReponseModel(ErrorCodes.ExistingUserEmail));
            }

            var creationResult = await _userManager.CreateAsync(userEnity, registerModel.Password);

            if (creationResult.Succeeded)
            {
                var addToRoleResult = await _userManager.AddToRoleAsync(userEnity, registerModel.Role);

                return addToRoleResult.Succeeded ? 
                    StatusCode(StatusCodes.Status201Created, new RegisterResponseModel { CreateAccountEmail = registerModel.Email }) :
                    StatusCode(StatusCodes.Status500InternalServerError, new RegisterResponseModel(string.Empty,
                        string.Join(";", addToRoleResult.Errors.Select(x => x.Description).ToList())));
            }

            return StatusCode(StatusCodes.Status500InternalServerError, new BaseReponseModel(string.Empty, 
                string.Join(";", creationResult.Errors.Select(x => x.Description).ToList())));
        }

        [HttpPost]
        [Route("login")]
        public async Task<IActionResult> LoginUser([FromBody] LoginRequestModel loginModel)
        {
            var validationResult = await _loginRequestValidator.ValidateAsync(loginModel);

            if (!validationResult.IsValid)
            {
                return BadRequest(new BaseReponseModel(ErrorCodes.InvalidRequest,
                    string.Join(";", validationResult.Errors.Select(x => x.ErrorMessage).ToList())));
            }

            var user = await _userManager.FindByEmailAsync(loginModel.Email);

            if (user != null && await _userManager.CheckPasswordAsync(user, loginModel.Password))
            {
                var userRoles = await _userManager.GetRolesAsync(user);

                var accessToken = _tokenHelper.GenerateAccessToken(user, userRoles.ToList());
                var refreshToken = _tokenHelper.GenerateRefreshToken();

                //save refresh token
                var saveResult = await _refreshTokenService.UpsertUserRefreshTokenAsync(user.Id, refreshToken);

                if (saveResult < 1)
                {
                    return StatusCode(StatusCodes.Status500InternalServerError, new BaseReponseModel(ErrorCodes.CouldNotLogIn));
                }

                return Ok(new AuthenticatedResponseModel
                {
                    AccessToken = accessToken.Token,
                    AccessTokenExpirationTime = accessToken.ExpirationDate,
                    RefreshToken = refreshToken,
                });
            }

            return Unauthorized(new BaseReponseModel(ErrorCodes.NotAllowed));
        }

        [HttpPost("refresh")]
        public async Task<IActionResult> RefreshAccessToken([FromBody] RefreshTokenRequestModel refreshTokenModel)
        {
            var validationResult = await _refreshTokenRequestValidator.ValidateAsync(refreshTokenModel);

            if (!validationResult.IsValid)
            {
                return BadRequest(new BaseReponseModel(ErrorCodes.InvalidRequest,
                    string.Join(";", validationResult.Errors.Select(x => x.ErrorMessage).ToList())));
            }

            var validToken = _tokenHelper.ValidateRefreshToken(refreshTokenModel.RefreshToken);

            if (!validToken)
            {
                return StatusCode(StatusCodes.Status403Forbidden, 
                    new BaseReponseModel(ErrorCodes.CouldNotValidateRefreshToken));
            }

            var savedToken = await _refreshTokenService.GetUserRefreshTokenAsync(refreshTokenModel.RefreshToken);

            if (savedToken == null)
            {
                return StatusCode(StatusCodes.Status403Forbidden,
                                  new BaseReponseModel(ErrorCodes.CouldNotFindRefreshToken));
            }

            var user = await _userManager.FindByIdAsync(savedToken.UserId);

            if (user == null)
            {
                return StatusCode(StatusCodes.Status403Forbidden,
                                  new BaseReponseModel(ErrorCodes.CouldNotFindUser));
            }

            var userRoles = await _userManager.GetRolesAsync(user);
            var newAccessToken = _tokenHelper.GenerateAccessToken(user, userRoles.ToList());

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

            if (email == null) return StatusCode(StatusCodes.Status403Forbidden, 
                new BaseReponseModel(ErrorCodes.MustBeLoggedIn));

            var user = await _userManager.FindByEmailAsync(email);

            if (user == null) return BadRequest(new BaseReponseModel(ErrorCodes.InvalidEmailAddress));

            var removeResult = await _refreshTokenService.RemoveUserRefreshTokenAsync(user.Id);

            return removeResult > 0 ? StatusCode(StatusCodes.Status204NoContent, new BaseReponseModel()) :
                                      StatusCode(StatusCodes.Status500InternalServerError,
                                        new BaseReponseModel(ErrorCodes.CouldNotRevokeToken));
        }
    }
}
