using Microsoft.AspNetCore.Mvc;
using System.Security.Cryptography;
using System.Text;

[ApiController]
[Route("api/[controller]")]
public class AuthController : ControllerBase
{
    private readonly IHttpClientFactory _httpClientFactory;
    private const string TokenEndpoint = "https://localhost:9443/oauth2/token";
    private const string LogoutEndpoint = "https://localhost:9443/oidc/logout";
    private const string ClientId = "OkQXerPG4ASHB4RAKQBSGaqFG4wa";

    public AuthController(IHttpClientFactory httpClientFactory)
    {
        _httpClientFactory = httpClientFactory;
    }

    [HttpGet("pkce")]
    public IActionResult GetPkce()
    {
        var codeVerifier = Base64Url(RandomNumberGenerator.GetBytes(32));
        using var sha = SHA256.Create();
        var challengeBytes = sha.ComputeHash(Encoding.UTF8.GetBytes(codeVerifier));
        var codeChallenge = Base64Url(challengeBytes);
        return Ok(new { code_verifier = codeVerifier, code_challenge = codeChallenge });
    }

    [HttpPost("token")]
    public async Task<IActionResult> ExchangeCode([FromBody] TokenRequest req)
    {
        if (req == null || string.IsNullOrEmpty(req.Code) || string.IsNullOrEmpty(req.CodeVerifier))
            return BadRequest(new { error = "code and codeVerifier required" });

        var client = _httpClientFactory.CreateClient("Wso2");
        var form = new Dictionary<string, string?>
        {
            ["grant_type"] = "authorization_code",
            ["code"] = req.Code,
            ["redirect_uri"] = req.RedirectUri,
            ["client_id"] = ClientId,
            ["code_verifier"] = req.CodeVerifier
        };

        var response = await client.PostAsync(TokenEndpoint, new FormUrlEncodedContent(form!));
        var body = await response.Content.ReadAsStringAsync();

        if (!response.IsSuccessStatusCode) return BadRequest(new { error = body });
        return Content(body, "application/json");
    }

    [HttpPost("refresh")]
    public async Task<IActionResult> Refresh([FromBody] RefreshRequest req)
    {
        if (req == null || string.IsNullOrEmpty(req.RefreshToken))
            return BadRequest(new { error = "refreshToken required" });

        var client = _httpClientFactory.CreateClient("Wso2");
        var form = new Dictionary<string, string?>
        {
            ["grant_type"] = "refresh_token",
            ["refresh_token"] = req.RefreshToken,
            ["client_id"] = ClientId
        };

        var response = await client.PostAsync(TokenEndpoint, new FormUrlEncodedContent(form!));
        var body = await response.Content.ReadAsStringAsync();

        if (!response.IsSuccessStatusCode) return BadRequest(new { error = body });
        return Content(body, "application/json");
    }

    [HttpGet("logout-url")]
    public IActionResult LogoutUrl([FromQuery] string idToken)
    {
        var postLogout = "http://localhost:5173";
        var url = $"{LogoutEndpoint}?id_token_hint={Uri.EscapeDataString(idToken)}&post_logout_redirect_uri={Uri.EscapeDataString(postLogout)}";
        return Ok(new { logoutUrl = url });
    }

    private static string Base64Url(ReadOnlySpan<byte> bytes) =>
        Convert.ToBase64String(bytes).Replace("+", "-").Replace("/", "_").Replace("=", "");
}

public class TokenRequest
{
    public string Code { get; set; } = default!;
    public string CodeVerifier { get; set; } = default!;
    public string RedirectUri { get; set; } = default!;
}

public class RefreshRequest
{
    public string RefreshToken { get; set; } = default!;
}
