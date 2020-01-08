using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Kecloak.API.Controllers
{
    [Authorize]
    public class KeacloakController : ControllerBase
    {
        [HttpGet("api/keycloak")]
        [Authorize("ADM")]
        [Authorize(Roles = "Administrators")]
        public IActionResult GetMessage()
        {
            return new JsonResult(new { message = "Oi!" });
        }
    }
}