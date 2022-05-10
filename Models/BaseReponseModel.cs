namespace JWTAuthSecuredAPI.Models
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

        public BaseReponseModel(string errorCode, string errorMessage)
        {
            ApiError = new ApiError { Code = errorCode, Message = errorMessage };
            Success = false;
        }
    }
}
