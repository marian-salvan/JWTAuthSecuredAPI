using JWTAuthSecured.Core.Constants;
using JWTAuthSecured.Core.Models;

namespace JWTAuthSecured.Core.ApiResponses
{
    public class BaseReponseModel
    {
        public bool Success { get; set; }
        public ApiError? ApiError { get; set; }

        public BaseReponseModel()
        {
            Success = true;
            ApiError = null;
        }

        public BaseReponseModel(string errorCode)
        {
            ApiError = new ApiError { Code = errorCode, Message = ErrorMessages.GetErrorMessage(errorCode) };
            Success = false;
        }

        public BaseReponseModel(string errorCode, string customErrorMessage)
        {
            ApiError = new ApiError { Code = errorCode, Message = customErrorMessage };
            Success = false;
        }
    }
}
