using AutoMapper;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using UserAuthApi.Entities;
using UserAuthApi.Helpers;
using UserAuthApi.Models.Accounts;
using UserAuthApi.Services.IServices;

namespace UserAuthApi.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AccountsController : BaseController
    {
        private readonly IAccountService _accountService;
        private readonly IMapper _mapper;

        public AccountsController(IAccountService accountService, IMapper mapper)
        {
            _accountService = accountService ?? throw new ArgumentNullException(nameof(accountService));
            _mapper = mapper ?? throw new ArgumentNullException(nameof(mapper));
        }

        [HttpPost("login")]
        public ActionResult<LoginResponse> Login(LoginRequest request)
        {
            var response =_accountService.UserLogin(request, ipAddress());
            setTokenCookies(response.RefreshToken);
            return Ok(response);

        }
        [HttpGet("refresh-token")]
        public ActionResult<LoginResponse> RefreshToken()
        {
            var token = Request.Cookies["refreshToken"];

            var response = _accountService.RefreshToken(token, ipAddress());
            setTokenCookies(response.RefreshToken);
            return Ok(response);

        }
        [Authorize]

        [HttpPost("revoke-token")]
        public ActionResult<LoginResponse> RevokeToken(RevokeTokenRequest request)
        {
            var token = request.Token ?? Request.Cookies["refreshToken"];
            if (string.IsNullOrEmpty(token))
                return BadRequest(new { message = "Token is Required" });

            // allows user to revoke their token and admins revoke any token

            if (!Account.OwnToken(token) && Account.Role != Role.Admin)
                return Unauthorized(new { message = "Unauthorized" });


             _accountService.RevokeToken(token, ipAddress());
            
            return Ok(new { message = "Token Revoked" });

        }

        [HttpPost("userregistration")]
        public ActionResult UserRegistration(RegistrationRequest request)
        {
             _accountService.UserRegistration(request,Request.Headers["origin"]);
           
            return Ok(new {message=" Thank your for signing up, please check your mail for instruction to verify your account."});

        }

        [HttpPost("verify-email")]
        public IActionResult VerifyEmail(VerifyEmailRequest request)
        {
            _accountService.VerifyEmail(request.Token);
           
            return Ok(new { message = " Verification Successfull" });

        }
        [HttpPost("reset-password")]
        public IActionResult ResetPassword(ResetPasswordRequest request)
        {
            _accountService.ResetPassword(request);

            return Ok(new { message = " Success" });

        }
        [HttpPost("forgot-password")]
        public IActionResult Forgotpassword(ForgotPasswordRequest request)
        {
            _accountService.ForgotPassWord(request, Request.Headers["origin"]);
            

            return Ok(new { message = " Please checkyour email for reset instructions" });

        }

        [Authorize(Role.Admin)]
        [HttpGet]
        public ActionResult<IEnumerable<AccountResponse>> GetAll()
        {
            var users = _accountService.GetAllUsers();

            return Ok(users);

        }
        [Authorize]
        [HttpGet]
        public ActionResult<AccountResponse> GetUserById(int id)
        {
           
            if (id!= Account.Id && Account.Role != Role.Admin)
            {
                return Unauthorized(new { message = "Unauthorized" });
            }
            var users = _accountService.GetuserById(id);
            return Ok(users);

        }
        [Authorize(Role.Admin)]
        [HttpPost]
        public ActionResult<AccountResponse> CreateUser(CreateRequest request)
        {
            var response = _accountService.CreateUser(request);
            
            return Ok(response);

        }
        [Authorize]
        [HttpPut("{id:int}")]
        public ActionResult<AccountResponse> UpdateUser(int id,UpdateRequest request)
        {
            // ensre that user can only update their details and admin can update any uder details
            if (id != Account.Id && Account.Role != Role.Admin)
            {
                return Unauthorized(new { message = "Unauthorized" });
            }
            //ensure only admin can update user role
            if ( Account.Role != Role.Admin)
            {
                request.Role = null;
            }
            var response = _accountService.UpdateUser(id,request);

            return Ok(response);

        }

        [Authorize]
        [HttpDelete("{id:int}")]
        public IActionResult Delete(int id)
        {
            // ensre that user can only delete their details and admin can delete any Oder details
            if (id != Account.Id && Account.Role != Role.Admin)
            {
                return Unauthorized(new { message = "Unauthorized" });
            }
            
            _accountService.DeleteUser(id);

            return Ok(new { message = "User Deleted" });

        }


        private string ipAddress()
        {
            if (Request.Headers.ContainsKey("X-Forwaded-For"))
                return Request.Headers["X-Forwaded-For"];
            else
                return HttpContext.Connection.RemoteIpAddress.MapToIPv4().ToString();
        }
        public void setTokenCookies (string token)
        {
            var cookie = new CookieOptions
            {
                HttpOnly = true,
                Expires = DateTime.UtcNow.AddDays(7)
            };
            Response.Cookies.Append("refreshToken", token, cookie);
        }
    }
}
