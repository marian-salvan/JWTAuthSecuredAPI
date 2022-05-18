namespace JWTAuthSecured.Core.Constants
{
    public static class ErrorCodes
    {
        public const string GenericError = "genericError";
        public const string InvalidRequest = "invalidRequest";
        public const string ExistingUserEmail = "existingUserEmail";
        public const string CouldNotLogIn = "couldNotLogIn";
        public const string NotAllowed = "notAllowed";
        public const string CouldNotValidateRefreshToken = "couldNotValidateRefreshToken";
        public const string CouldNotFindRefreshToken = "couldNotFindRefreshToken";
        public const string CouldNotFindUser = "couldNotFindUser";
        public const string MustBeLoggedIn = "mustBeLoggedIn";
        public const string InvalidEmailAddress = "invalidEmailAddress";
        public const string CouldNotRevokeToken = "couldNotRevokeToken";

    }
}
