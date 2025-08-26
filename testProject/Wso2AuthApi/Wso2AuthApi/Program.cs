using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.Net;
using System.Text.Json;

// Minimal, explicit Program.cs for .NET 9 style
var builder = WebApplication.CreateBuilder(args);

// Controllers & CORS
builder.Services.AddControllers();
builder.Services.AddCors(options =>
{
    options.AddDefaultPolicy(policy =>
        policy.WithOrigins("http://localhost:5173")
              .AllowAnyHeader()
              .AllowAnyMethod()
              .AllowCredentials());
});

// HttpClient for WSO2 (dev: accept mkcert/self-signed)
builder.Services.AddHttpClient("Wso2", c =>
{
    c.BaseAddress = new Uri("https://localhost:9443");
}).ConfigurePrimaryHttpMessageHandler(() =>
{
    return new HttpClientHandler
    {
        // DEV: allow self-signed cert (remove in prod)
        ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator
    };
});

// JWT Bearer - validate signature using JWKS from WSO2
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        // issuer exactly as in your tokens (you showed "https://localhost:9443/oauth2/token")
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = "https://localhost:9443/oauth2/token",
            ValidateAudience = false,
            ValidateLifetime = true,
            ClockSkew = TimeSpan.FromSeconds(30),
            // We'll validate signing keys via IssuerSigningKeyResolver below
            ValidateIssuerSigningKey = true
        };

        // Use local JWKS resolver
        options.Events = new JwtBearerEvents
        {
            OnMessageReceived = ctx =>
            {
                // no-op, default Bearer header works
                return Task.CompletedTask;
            },
            OnAuthenticationFailed = ctx =>
            {
                Console.WriteLine($"[JWT] Authentication failed: {ctx.Exception?.Message}");
                return Task.CompletedTask;
            },
            OnTokenValidated = ctx =>
            {
                Console.WriteLine("[JWT] Token validated for: " + ctx.Principal?.Identity?.Name);
                return Task.CompletedTask;
            }
        };

        // DEV: allow fetching metadata over self-signed
        options.RequireHttpsMetadata = false;
        options.BackchannelHttpHandler = new HttpClientHandler
        {
            ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator
        };

        // Provide IssuerSigningKeyResolver that fetches JWKS from WSO2
        options.TokenValidationParameters.IssuerSigningKeyResolver = (token, securityToken, kid, validationParameters) =>
        {
            // simple cache for jwks (10 minutes)
            var keys = JwksCache.GetKeysAsync().GetAwaiter().GetResult();
            return keys;
        };
    });

builder.Services.AddAuthorization();

var app = builder.Build();

// Middleware ordering
app.UseDeveloperExceptionPage();
app.UseCors();
app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();


// ----------------- small JWKS cache utility -----------------
static class JwksCache
{
    private static readonly TimeSpan CacheDuration = TimeSpan.FromMinutes(10);
    private static DateTime _lastFetch = DateTime.MinValue;
    private static SecurityKey[]? _cachedKeys = null;
    private static readonly object _lock = new();

    public static async Task<IEnumerable<SecurityKey>> GetKeysAsync()
    {
        lock (_lock)
        {
            if (_cachedKeys != null && DateTime.UtcNow - _lastFetch < CacheDuration)
                return _cachedKeys;
        }

        try
        {
            // Fetch JWKS from WSO2 (dev: self-signed allowed)
            using var handler = new HttpClientHandler
            {
                ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator
            };
            using var client = new HttpClient(handler) { BaseAddress = new Uri("https://localhost:9443") };

            // WSO2 JWKS endpoint (common): /oauth2/jwks
            var resp = await client.GetAsync("/oauth2/jwks");
            resp.EnsureSuccessStatusCode();
            var json = await resp.Content.ReadAsStringAsync();

            var jwks = new JsonWebKeySet(json);
            var keys = jwks.Keys.Select(k => (SecurityKey)k).ToArray();

            lock (_lock)
            {
                _cachedKeys = keys;
                _lastFetch = DateTime.UtcNow;
            }

            return keys;
        }
        catch (Exception ex)
        {
            Console.WriteLine("[JWKS] Failed to fetch/parse JWKS: " + ex.Message);
            // fallback: empty list -> signature validation will fail
            return Array.Empty<SecurityKey>();
        }
    }
}
