using AutoMapper;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using UserAuthApi.Data;
using UserAuthApi.Entities;
using UserAuthApi.Exceptions;
using UserAuthApi.Helpers;
using UserAuthApi.Models.Accounts;
using UserAuthApi.Services.IServices;
using BC = BCrypt.Net.BCrypt;

namespace UserAuthApi.Services
{
    public class AccountService:IAccountService
    {
        private readonly UserAuthContext _context;
        private IMapper _mapper;
        private readonly AppSettings _appSettings;
        private IEmail _email;

        public AccountService(UserAuthContext context, IMapper mapper,IOptions <AppSettings> appSettings, IEmail email)
        {
            _context = context ?? throw new ArgumentNullException(nameof(context));
            _mapper = mapper ?? throw new ArgumentNullException(nameof(mapper));
            _appSettings = appSettings.Value ?? throw new ArgumentNullException(nameof(appSettings));
            _email = email ?? throw new ArgumentNullException(nameof(email));
        }

        public LoginResponse UserLogin(LoginRequest request, string ipAddress)
        {
            //get account with username or email
            var account = _context.Accounts.SingleOrDefault(x => x.Email == request.UserName
            || x.UserName == request.UserName);
            //Check if account exists or if account is veried or if password matches 
            if (account == null || !account.IsVerified || account.IsActive == false || !BC.Verify(request.Password, account.PasswordHash))
                throw new AppException("Email or Passowrd is incorrect");
            var jwtToken = generateJwtToken(account);
            var refreshToken = generateRefreshToken(ipAddress);
            account.RefreshTokens.Add(refreshToken);

            //remove old refreshToken
            removeOldrefreshToken(account);
            //save changes to db

            _context.Update(account);
            _context.SaveChanges();

            var response = _mapper.Map<LoginResponse>(account);
            response.JwtToken = jwtToken;
            response.RefreshToken = refreshToken.Token;

            return response;


           
        }

        public void UserRegistration(RegistrationRequest request, string origin)
        {
            throw new NotImplementedException();
        }

        public void VerifyEmail(string token)
        {
            throw new NotImplementedException();
        }

        public void ForgotPassWord(ForgotPasswordRequest request, string origin)
        {
            throw new NotImplementedException();
        }

        public void ResetPassword(ResetPasswordRequest request)
        {
            throw new NotImplementedException();
        }

        public IEnumerable<AccountResponse> GetAllUsers()
        {
            throw new NotImplementedException();
        }

        public AccountResponse GetuserById(int id)
        {
            throw new NotImplementedException();
        }

        public AccountResponse CreateUser(CreateRequest request)
        {
            throw new NotImplementedException();
        }

        public AccountResponse UpdateUser(UpdateRequest request)
        {
            throw new NotImplementedException();
        }

        public void DeleteUser(int id)
        {
            throw new NotImplementedException();
        }

        public LoginResponse RefreshToken(string token, string ipAddress)
        {
            throw new NotImplementedException();
        }

        public void RevokeToken(string token, string ipAddress)
        {
            throw new NotImplementedException();
        }

        private string generateJwtToken(Account account)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes(_appSettings.JwtSecret);
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new[] { new Claim("Id", account.Id.ToString()) }),
                Expires = DateTime.UtcNow.AddMinutes(15),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key),
                SecurityAlgorithms.HmacSha256Signature)
            };
            var token = tokenHandler.CreateToken(tokenDescriptor);

            return tokenHandler.WriteToken(token);

        }
        private RefreshToken generateRefreshToken(string ipAddress)
        {
            return new RefreshToken
            {
                Token = randomTokenString(),
                Expires = DateTime.UtcNow.AddDays(2),
                Created = DateTime.UtcNow,
                CreatedByIp = ipAddress
            };
        }

        private void removeOldrefreshToken(Account account)
        {
            account.RefreshTokens.RemoveAll(x =>
            !x.IsActive || x.Created.AddDays(_appSettings.RefreshTokenTTL) <= DateTime.UtcNow);
        }

        private string randomTokenString()
        {
           
            var randomBytes = new byte[40];
            RandomNumberGenerator.Create().GetBytes(randomBytes);

            return BitConverter.ToString(randomBytes).Replace("-", "");
        }
    }
}
