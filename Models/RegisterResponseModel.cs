﻿namespace JWTAuthSecuredAPI.Models
{
    public class RegisterResponseModel : BaseReponseModel
    {
        public string CreateAccountEmail { get; set; }

        public RegisterResponseModel()
        {

        }
        public RegisterResponseModel(string errorCode, string errorMessage) : base(errorCode, errorMessage)
        {
        }
    }
}
