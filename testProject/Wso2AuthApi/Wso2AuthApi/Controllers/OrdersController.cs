using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Linq;

[ApiController]
[Route("api/[controller]")]
public class OrdersController : ControllerBase
{
    [HttpGet]
    [Authorize]
    public IActionResult GetOrders()
    {
        var orders = new[]
        {
            new { id = 1, item = "Laptop", price = 1200 },
            new { id = 2, item = "Phone", price = 800 }
        };
        return Ok(orders);
    }
}
