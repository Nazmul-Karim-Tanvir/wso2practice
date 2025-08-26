using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.Text.Json;

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

// HttpClient for WSO2 (allow self-signed cert in dev)
builder.Services.AddHttpClient("Wso2", c =>
{
    c.BaseAddress = new Uri("https://localhost:9443");
}).ConfigurePrimaryHttpMessageHandler(() =>
{
    return new HttpClientHandler
    {
        ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator
    };
});

// JWT Bearer Authentication
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = "https://localhost:9443/oauth2/token",
            ValidateAudience = false,
            ValidateLifetime = true,
            ClockSkew = TimeSpan.FromSeconds(30),
            ValidateIssuerSigningKey = true
        };

        options.Events = new JwtBearerEvents
        {
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

        options.RequireHttpsMetadata = false;
        options.BackchannelHttpHandler = new HttpClientHandler
        {
            ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator
        };

        options.TokenValidationParameters.IssuerSigningKeyResolver = (token, securityToken, kid, validationParameters) =>
        {
            return JwksCache.GetKeysAsync().GetAwaiter().GetResult();
        };
    });

builder.Services.AddAuthorization();
builder.Services.AddControllers();

var app = builder.Build();
app.UseDeveloperExceptionPage();
app.UseCors();
app.UseAuthentication();
app.UseAuthorization();
app.MapControllers();
app.Run();

// ------------------- JWKS Cache -------------------
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
            using var handler = new HttpClientHandler
            {
                ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator
            };
            using var client = new HttpClient(handler) { BaseAddress = new Uri("https://localhost:9443") };

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
        catch
        {
            return Array.Empty<SecurityKey>();
        }
    }
}
