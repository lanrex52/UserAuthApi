using UserAuthApi.Models.Accounts;

namespace UserAuthApi.Services.IServices
{
    public interface IAccountService
    {
        LoginResponse UserLogin(LoginRequest request, string ipAddress);
        void UserRegistration(RegistrationRequest request, string origin);
        void VerifyEmail(string token);
        void ForgotPassWord(ForgotPasswordRequest request, string origin);
        void ResetPassword(ResetPasswordRequest request);
        IEnumerable<AccountResponse> GetAllUsers();
        AccountResponse GetuserById (int id);
        AccountResponse CreateUser(CreateRequest request);
        AccountResponse UpdateUser(UpdateRequest request);
        void DeleteUser(int id);
        LoginResponse RefreshToken(string token, string ipAddress);
        void RevokeToken(string token, string ipAddress);

    }
}
