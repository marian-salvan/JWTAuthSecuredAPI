namespace JWTAuthSecured.Core.Constants
{
    public static class ErrorMessages
    {
        public static string GetErrorMessage(string errorCode)
        {
            return errorCode switch
            {
                ErrorCodes.GenericError => "An unexpected error has occured. Please try again.",
                ErrorCodes.ExistingUserEmail => "This user email exists in db.",
                ErrorCodes.CouldNotLogIn => "Could not log in.",
                ErrorCodes.NotAllowed => "Not allowed.",
                ErrorCodes.CouldNotValidateRefreshToken => "Could not validate refresh token.",
                ErrorCodes.CouldNotFindRefreshToken => "Could not find the refresh token",
                ErrorCodes.CouldNotFindUser => "Could not find user for the provided token",
                ErrorCodes.MustBeLoggedIn => "Your must be logged in to revoke the tokens",
                ErrorCodes.InvalidEmailAddress => "Invalid user email",
                ErrorCodes.CouldNotRevokeToken => "Could not revoke the token",
                _ => "An unexpected error has occured. Please try again.",
            };
        }
    }
}
