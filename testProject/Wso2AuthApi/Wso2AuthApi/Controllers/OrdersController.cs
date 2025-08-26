using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Linq;
using System.IdentityModel.Tokens.Jwt;

[ApiController]
[Route("api/[controller]")]
public class OrdersController : ControllerBase
{
    [HttpGet]
    [Authorize]
    public IActionResult GetOrders()
    {
        // show claims for debugging
        var claims = User.Claims.ToDictionary(c => c.Type, c => c.Value);

        // read roles/scopes if present
        var roles = User.Claims.Where(c => c.Type == "roles" || c.Type == "groups").Select(c => c.Value).ToArray();
        var scope = User.Claims.FirstOrDefault(c => c.Type == "scope")?.Value;

        // for now: allow if token is valid (signature + expiry)
        var orders = new[]
        {
            new { id = 1, item = "Laptop", price = 1200 },
            new { id = 2, item = "Phone", price = 800 }
        };

        return Ok(new { orders, roles, scope, claimsPreview = claims });
    }
}
