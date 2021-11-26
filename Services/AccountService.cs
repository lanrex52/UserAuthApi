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
            //validate if the user exists
            if (_context.Accounts.Any(x=> x.Email == request.Email))
            {
                throw new AppException("This Email Address Exists");
            }

            //check if userName Exists
            if (_context.Accounts.Any(x => x.UserName == request.UserName))
            {
                throw new AppException("This username has been choosen");
            }
            // request into account object

            var account = _mapper.Map<Account>(request);

            //ensure first user is an Admin

            var isFirstUser = _context.Accounts.Count() == 0;

            account.Role = isFirstUser ? Role.Admin : Role.User;

            //if (isFirstUser == true)
            //{
            //    account.Role = Role.Admin;

            //}
            //else
            //{
            //    account.Role = Role.User;
            //}
            account.Created = DateTime.UtcNow;
            account.VerificationToken = randomTokenString();
            account.IsActive = false;
            account.PasswordHash = BC.HashPassword(request.Password);

            //save user details
            _context.Accounts.Add(account);
            _context.SaveChanges();

            //send Verification Email

            sendVerification(account, origin);
        }

        
        public void VerifyEmail(string token)
        {
            var account = _context.Accounts.SingleOrDefault(x => x.VerificationToken == token);
            if (account == null) throw new AppException("Invalid Token");

            account.Verified = DateTime.UtcNow;
            account.VerificationToken = null;
            account.IsActive = true;
            _context.Accounts.Update(account);

            _context.SaveChanges();
        }

        public void ForgotPassWord(ForgotPasswordRequest request, string origin)
        {
            var account = _context.Accounts.SingleOrDefault(x => x.Email == request.Email);

            if (account == null ) return;
           
            //create the password reset token

            account.ResetToken = randomTokenString();
            //reset token should expire after one day
            account.ResetTokenExpires = DateTime.UtcNow.AddDays(1);

            _context.Accounts.Update(account);

            _context.SaveChanges();

            sendResetEmail(account,origin);


        }

        public void ResetPassword(ResetPasswordRequest request)
        {
            var account = _context.Accounts.SingleOrDefault(x => x.ResetToken == request.Token &&
            x.ResetTokenExpires > DateTime.UtcNow
            );

            if (account == null) throw new AppException("Invalid Token");

            //update user passworf
            account.PasswordHash = BC.HashPassword(request.Password);
            account.PasswordReset = DateTime.Now;
            account.ResetToken = null;
            account.ResetTokenExpires = null;

            _context.Accounts.Update(account);

            _context.SaveChanges();

        }

        public IEnumerable<AccountResponse> GetAllUsers()
        {
            var accounts = _context.Accounts;
            return _mapper.Map<IList<AccountResponse>>(accounts);
        }

        public AccountResponse GetuserById(int id)
        {
            //get user with id
            var account = _context.Accounts.Find(id);
            if (account == null) throw new KeyNotFoundException("Account not found");
            return _mapper.Map<AccountResponse>(account);
        }

        public AccountResponse CreateUser(CreateRequest request)
        {
            //check the user does not exist
            if (_context.Accounts.Any(x => x.Email == request.Email))
                throw new AppException ($"Email: '{request.Email}' already exists" );
            if (_context.Accounts.Any(x => x.UserName == request.UserName))
                throw new AppException($"Username: '{request.UserName}' already exists");

            //map our requests into a new account object

            var account = _mapper.Map<Account>(request);
            account.Created = DateTime.UtcNow;
            account.Verified = DateTime.Now;
            account.IsActive = true;

            account.PasswordHash = BC.HashPassword(request.Password);

            _context.Accounts.Add(account);

            _context.SaveChanges();
            return _mapper.Map<AccountResponse>(account);


        }

        public AccountResponse UpdateUser(int id,UpdateRequest request)
        {
            var account = _context.Accounts.Find(id);
            if (account == null) throw new KeyNotFoundException("Account not found");

            //check if account is active
            if (account.IsActive == false) throw new AppException("Cannot update account");
            //Check for email
            if (account.Email != request.Email && _context.Accounts.Any(x=>x.Email ==request.Email))
                throw new AppException("email already exist");

            if (!string.IsNullOrEmpty(request.Password))
                account.PasswordHash = BC.HashPassword(request.Password);
            _mapper.Map(request,account);
            account.Updated = DateTime.UtcNow;
            _context.Accounts.Update(account);

            _context.SaveChanges();

            return _mapper.Map<AccountResponse>(account);


        }

        public void DeleteUser(int id)
        {
            var account = _context.Accounts.Find(id);
            if (account == null) throw new KeyNotFoundException("Account not found");
            _context.Accounts.Remove(account);
            _context.SaveChanges();

        }

        public LoginResponse RefreshToken(string token, string ipAddress)
        {
            var (refreshToken, account) = getRefreshToken(token);

            var newrefreshToken = generateRefreshToken(ipAddress);
            refreshToken.Revoked = DateTime.UtcNow;
            refreshToken.RevokedByIp = ipAddress;
            refreshToken.ReplaceByToken = newrefreshToken.Token;
            account.RefreshTokens.Add(newrefreshToken);

            removeOldrefreshToken(account);

            _context.Accounts.Update(account);

            _context.SaveChanges();

            //generate jwt token
            var jwtToken = generateJwtToken(account);

            var response = _mapper.Map<LoginResponse>(account);

            response.JwtToken = jwtToken;
            response.RefreshToken = newrefreshToken.Token;

            return response;



        }

        public void RevokeToken(string token, string ipAddress)
        {
            var (refreshToken, account) = getRefreshToken(token);

            refreshToken.Revoked = DateTime.UtcNow;
            refreshToken.RevokedByIp = ipAddress;

            _context.Update(account);
            _context.SaveChanges();
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
        private (RefreshToken,Account) getRefreshToken(string token)
        {
            var account = _context.Accounts.SingleOrDefault(x => x.RefreshTokens.Any(y => y.Token == token));
            if (account == null) throw new AppException("Invalid Token");

            var refreshToken = account.RefreshTokens.Single(x => x.Token == token);
            if(!refreshToken.IsActive) throw new AppException("Invalid Token");

            return (refreshToken, account);

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

        private void sendVerification(Account account, string origin)
        {
            string? message = null;
            if (!string.IsNullOrEmpty(origin))
            {
                var verifyUrl = $"{origin}/api/accounts/verify-url?token={account.VerificationToken}";
                message = $"<p> Please click on the link below to verify your email address:</p> <br>" +
                    $@"<p><a href = ""{verifyUrl}"" >Click Here</p> ";


            }
            else
            {
                message = $"<p> Please use the token below to verify your email in <code> api/account/verify-email</code> api route:</p> <br>" +
                   $@"<p><code>{account.VerificationToken}</code> /p> ";
            }
        }
        private void sendResetEmail(Account account, string origin)
        {
            string message = null;
            if (!string.IsNullOrEmpty(origin))
            {
                var resetUrl = $"{origin}/accounts/reset-password?token={account.ResetToken}";
                message = $"<p> Please click on the link below to rest your passworf. This link is only valid for 1 day:</p> <br>" +
                    $@"<p><a href = ""{resetUrl}"" >Click Here</p> ";


            }
            else
            {
                message = $"<p> Please use the token below to reset your password in <code> api/account/reset-password</code> api route:</p> <br>" +
                   $@"<p><code>{account.ResetToken}</code> /p> ";
            }
        }

    }
}
