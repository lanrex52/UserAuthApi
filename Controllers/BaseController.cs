using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using UserAuthApi.Entities;

namespace UserAuthApi.Controllers
{
    
    [Controller]
    public abstract class BaseController : ControllerBase
    {
        //get current user account if authenticated
        public Account Account => (Account)HttpContext.Items["Account"];
    }
}
