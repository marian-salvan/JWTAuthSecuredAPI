using JWTAuthSecured.Core.ApiResponses;
using JWTAuthSecured.Core.Constants;
using Microsoft.AspNetCore.Diagnostics;
using Microsoft.AspNetCore.Mvc;

namespace JWTAuthSecured.API.Controllers
{
    [ApiController]
    [ApiExplorerSettings(IgnoreApi = true)]
    public class ErrorController : ControllerBase 
    {
        [Route("error")]
        public IActionResult Error()
        {
            var context = HttpContext.Features.Get<IExceptionHandlerFeature>();
            var exception = context?.Error;

            return StatusCode(StatusCodes.Status500InternalServerError, new BaseReponseModel(ErrorCodes.GenericError, exception.Message));
        }
    }
}
