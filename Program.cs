using UserAuthApi.Data;
using Microsoft.EntityFrameworkCore;
using UserAuthApi.Helpers;
using UserAuthApi.Services.IServices;
using UserAuthApi.Services;
using Microsoft.OpenApi.Models;
using UserAuthApi.Middleware;

var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();
//add Services
builder.Services.AddControllers();
builder.Services.AddDbContext<UserAuthContext>(o =>
        o.UseSqlServer(builder.Configuration["DefaultConnection"]));

builder.Services.AddCors();
builder.Services.AddAutoMapper(AppDomain.CurrentDomain.GetAssemblies());
builder.Services.AddSwaggerGen(o=>
    o.SwaggerDoc(
    "v1", new OpenApiInfo { Title="UserAuthApi", Version= "v1"}));

builder.Services.AddRouting();
builder.Services.Configure<AppSettings>(builder.Configuration.GetSection("AppSettings"));

//Configure out dependency injection services
builder.Services.AddScoped<IAccountService, AccountService>();
builder.Services.AddScoped<IEmail, Email>();

//App Builder settings
app.UseSwagger();
app.UseSwaggerUI(o => o.SwaggerEndpoint("/swagger/v1/swagger.json", "User Auth Api"));

app.UseHttpsRedirection();

//error handler
app.UseMiddleware<ErrorHandlerMiddleware>();
//custome authentication middleware
app.UseMiddleware<JwtMiddleware>();
app.UseAuthentication();

//cors Policy

app.UseCors(x => x.
SetIsOriginAllowed(origin => true)
.AllowAnyMethod()
.AllowAnyHeader()
.AllowCredentials());


app.UseRouting();



app.UseEndpoints(endpoints =>
{
    endpoints.MapControllers();
});

app.Run();
