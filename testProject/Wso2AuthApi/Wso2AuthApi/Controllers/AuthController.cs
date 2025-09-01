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

    // -------------------- PKCE Generation --------------------
    [HttpGet("pkce")]
    public IActionResult GetPkce()
    {
        var codeVerifier = Base64Url(RandomNumberGenerator.GetBytes(32));
        using var sha = SHA256.Create();
        var challengeBytes = sha.ComputeHash(Encoding.UTF8.GetBytes(codeVerifier));
        var codeChallenge = Base64Url(challengeBytes);

        return Ok(new { code_verifier = codeVerifier, code_challenge = codeChallenge });
    }

    // -------------------- Exchange Auth Code --------------------
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

        if (!response.IsSuccessStatusCode)
        {
            Console.WriteLine($"[TOKEN ERROR] {body}");
            return BadRequest(new { error = body });
        }

        var json = System.Text.Json.JsonDocument.Parse(body).RootElement;

        // Set tokens in HttpOnly cookies
        if (json.TryGetProperty("access_token", out var accessToken))
        {
            Response.Cookies.Append("access_token", accessToken.GetString()!,
                new CookieOptions { HttpOnly = true, Secure = true, SameSite = SameSiteMode.Strict });
        }

        if (json.TryGetProperty("refresh_token", out var refreshToken))
        {
            Response.Cookies.Append("refresh_token", refreshToken.GetString()!,
                new CookieOptions { HttpOnly = true, Secure = true, SameSite = SameSiteMode.Strict });
        }

        if (json.TryGetProperty("id_token", out var idToken))
        {
            Response.Cookies.Append("id_token", idToken.GetString()!,
                new CookieOptions { HttpOnly = true, Secure = true, SameSite = SameSiteMode.Strict });
        }

        return Content(body, "application/json");
    }

    // -------------------- Refresh Token --------------------
    [HttpPost("refresh")]
    public async Task<IActionResult> Refresh()
    {
        var refreshToken = Request.Cookies["refresh_token"];
        if (string.IsNullOrEmpty(refreshToken))
            return BadRequest(new { error = "refresh token missing" });

        var client = _httpClientFactory.CreateClient("Wso2");
        var form = new Dictionary<string, string?>
        {
            ["grant_type"] = "refresh_token",
            ["refresh_token"] = refreshToken,
            ["client_id"] = ClientId
        };

        var response = await client.PostAsync(TokenEndpoint, new FormUrlEncodedContent(form!));
        var body = await response.Content.ReadAsStringAsync();

        if (!response.IsSuccessStatusCode)
        {
            Console.WriteLine($"[REFRESH ERROR] {body}");
            return BadRequest(new { error = body });
        }

        var json = System.Text.Json.JsonDocument.Parse(body).RootElement;

        // Update cookies
        if (json.TryGetProperty("access_token", out var accessToken))
        {
            Response.Cookies.Append("access_token", accessToken.GetString()!,
                new CookieOptions { HttpOnly = true, Secure = true, SameSite = SameSiteMode.Strict });
        }

        if (json.TryGetProperty("refresh_token", out var newRefreshToken))
        {
            Response.Cookies.Append("refresh_token", newRefreshToken.GetString()!,
                new CookieOptions { HttpOnly = true, Secure = true, SameSite = SameSiteMode.Strict });
        }

        if (json.TryGetProperty("id_token", out var idToken))
        {
            Response.Cookies.Append("id_token", idToken.GetString()!,
                new CookieOptions { HttpOnly = true, Secure = true, SameSite = SameSiteMode.Strict });
        }

        return Content(body, "application/json");
    }

    // -------------------- Logout URL --------------------
    [HttpGet("logout-url")]
    public IActionResult LogoutUrl([FromQuery] string idToken = "")
    {
        var postLogout = "http://localhost:5173";
        var url = $"{LogoutEndpoint}?id_token_hint={Uri.EscapeDataString(idToken)}&post_logout_redirect_uri={Uri.EscapeDataString(postLogout)}";
        return Ok(new { logoutUrl = url });
    }

    // -------------------- Helpers --------------------
    private static string Base64Url(ReadOnlySpan<byte> bytes) =>
        Convert.ToBase64String(bytes).Replace("+", "-").Replace("/", "_").Replace("=", "");
}

// -------------------- Request Models --------------------
public class TokenRequest
{
    public string Code { get; set; } = default!;
    public string CodeVerifier { get; set; } = default!;
    public string RedirectUri { get; set; } = default!;
}