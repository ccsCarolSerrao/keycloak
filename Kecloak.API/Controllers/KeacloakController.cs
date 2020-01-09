using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Kecloak.API.Controllers
{
    [Authorize]
    public class KeacloakController : ControllerBase
    {
        [HttpGet("api/keycloak")]
        //[Authorize]
        [Authorize(Roles = "uma_protection")]
        public IActionResult GetMessage()
        {
            return new JsonResult(new { message = "Oi!" });
        }
    }
}