using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Text;
using UserAuthApi.Data;
using UserAuthApi.Helpers;

namespace UserAuthApi.Middleware
{
    public class JwtMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly AppSettings _appSettings;

        public JwtMiddleware(RequestDelegate next, IOptions<AppSettings> appSettings)
        {
            _next = next;
            _appSettings = appSettings.Value;
        }

        public async Task Invoke(HttpContext context,UserAuthContext dataContext)
        {
            var token = context.Request.Headers["Authorization"].FirstOrDefault()?.Split(" ").Last();

            if (token != null)
                await attachAccountToContext(context,dataContext,token);

            await _next(context);
        }

        private async Task attachAccountToContext(HttpContext context, UserAuthContext dataContext, string token)
        {
            try
            {
                var tokenHandler = new JwtSecurityTokenHandler();
                var key = Encoding.ASCII.GetBytes(_appSettings.JwtSecret);
                tokenHandler.ValidateToken(token, new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = new SymmetricSecurityKey(key),
                    ValidateIssuer = false,

                    ClockSkew = TimeSpan.Zero

                }, out SecurityToken validateToken);

                var jwtToken = (JwtSecurityToken)validateToken;
                var accountid = int.Parse(jwtToken.Claims.First(x => x.Type == "id").Value);

                //attach account to the context after successful  jwt validation

                context.Items["Account"] = await dataContext.Accounts.FindAsync(accountid);
            


            }
            catch
            {

               //do nothing
            }
        }
    }
}
