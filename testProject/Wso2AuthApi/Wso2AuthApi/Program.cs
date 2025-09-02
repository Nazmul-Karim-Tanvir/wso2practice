using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.Text.Json;
using System.Security.Claims;

var builder = WebApplication.CreateBuilder(args);

// ------------------ Controllers & CORS ------------------
builder.Services.AddControllers();
builder.Services.AddCors(options =>
{
    options.AddDefaultPolicy(policy =>
        policy.WithOrigins("http://localhost:5173")
              .AllowAnyHeader()
              .AllowAnyMethod()
              .AllowCredentials());
});

// ------------------ HttpClient for WSO2 ------------------
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

// ------------------ JWT Bearer Authentication ------------------
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = "https://localhost:9443/oauth2/token",
            ValidateAudience = true,
            ValidAudience = "OkQXerPG4ASHB4RAKQBSGaqFG4wa",
            ValidateLifetime = true,
            ClockSkew = TimeSpan.FromSeconds(30),
            ValidateIssuerSigningKey = true,

            // Name claim for identifying user
            NameClaimType = "sub"
        };

        // Token validated event to map roles
        options.Events = new JwtBearerEvents
        {
            OnTokenValidated = ctx =>
            {
                var identity = ctx.Principal?.Identity as ClaimsIdentity;
                if (identity != null && ctx.SecurityToken is System.IdentityModel.Tokens.Jwt.JwtSecurityToken jwt)
                {
                    // Remove any existing role claims
                    var existingRoles = identity.FindAll(ClaimTypes.Role).ToList();
                    foreach (var rc in existingRoles)
                        identity.RemoveClaim(rc);

                    // Extract roles from JWT payload
                    if (jwt.Payload.TryGetValue("roles", out var rolesObj) &&
                        rolesObj is JsonElement jsonElement &&
                        jsonElement.ValueKind == JsonValueKind.Array)
                    {
                        foreach (var roleElement in jsonElement.EnumerateArray())
                        {
                            var role = roleElement.GetString();
                            if (!string.IsNullOrEmpty(role))
                                identity.AddClaim(new Claim(ClaimTypes.Role, role));
                        }
                    }
                }

                Console.WriteLine("[JWT] Token validated for: " + ctx.Principal?.Identity?.Name);
                return Task.CompletedTask;
            },

            OnAuthenticationFailed = ctx =>
            {
                Console.WriteLine($"[JWT] Authentication failed: {ctx.Exception?.Message}");
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

// ------------------ Authorization ------------------
builder.Services.AddAuthorization();

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
        catch (Exception ex)
        {
            Console.WriteLine($"[JWKS ERROR] Failed to fetch keys: {ex.Message}");
            Console.WriteLine(ex.StackTrace);
            return Array.Empty<SecurityKey>();
        }
    }
}



/* 

using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.Text.Json;
using System.Security.Claims;
using System.Security.Cryptography;

namespace MyApi
{
    class Program
    {
        public static void Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);

            // ------------------ Logging ------------------
            builder.Logging.ClearProviders();
            builder.Logging.AddConsole();

            // ------------------ Controllers & CORS ------------------
            builder.Services.AddControllers();
            builder.Services.AddCors(options =>
            {
                options.AddDefaultPolicy(policy =>
                    policy.WithOrigins("http://localhost:5173")
                          .AllowAnyHeader()
                          .AllowAnyMethod()
                          .AllowCredentials());
            });

            // ------------------ HttpClient for WSO2 ------------------
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

            // ------------------ JWT Bearer Authentication ------------------
            bool useFakeKeys = true; // toggle for testing

            builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
                .AddJwtBearer(options =>
                {
                    options.TokenValidationParameters = new TokenValidationParameters
                    {
                        ValidateIssuer = true,
                        ValidIssuer = "https://localhost:9443/oauth2/token",
                        ValidateAudience = true,
                        ValidAudience = "OkQXerPG4ASHB4RAKQBSGaqFG4wa",
                        ValidateLifetime = true,
                        ClockSkew = TimeSpan.FromSeconds(30),
                        ValidateIssuerSigningKey = true,
                        NameClaimType = "sub"
                    };

                    options.Events = new JwtBearerEvents
                    {
                        OnTokenValidated = ctx =>
                        {
                            var logger = ctx.HttpContext.RequestServices.GetRequiredService<ILogger<Program>>();
                            var identity = ctx.Principal?.Identity as ClaimsIdentity;

                            if (identity != null && ctx.SecurityToken is System.IdentityModel.Tokens.Jwt.JwtSecurityToken jwt)
                            {
                                // Remove existing roles
                                var existingRoles = identity.FindAll(ClaimTypes.Role).ToList();
                                foreach (var rc in existingRoles)
                                    identity.RemoveClaim(rc);

                                // Add roles from JWT payload
                                if (jwt.Payload.TryGetValue("roles", out var rolesObj) &&
                                    rolesObj is JsonElement jsonElement &&
                                    jsonElement.ValueKind == JsonValueKind.Array)
                                {
                                    foreach (var roleElement in jsonElement.EnumerateArray())
                                    {
                                        var role = roleElement.GetString();
                                        if (!string.IsNullOrEmpty(role))
                                            identity.AddClaim(new Claim(ClaimTypes.Role, role));
                                    }
                                }
                            }

                            logger.LogInformation("[JWT] Token validated for: {User}", ctx.Principal?.Identity?.Name);
                            return Task.CompletedTask;
                        },

                        OnAuthenticationFailed = ctx =>
                        {
                            var logger = ctx.HttpContext.RequestServices.GetRequiredService<ILogger<Program>>();
                            logger.LogWarning(ctx.Exception, "[JWT] Authentication failed");
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
                        if (useFakeKeys)
                        {
                            return Program.GetFakeKeys();
                        }

                        return Program.JwksCache.GetKeysAsync().GetAwaiter().GetResult();
                    };
                });

            builder.Services.AddAuthorization();

            var app = builder.Build();
            app.UseDeveloperExceptionPage();
            app.UseCors();
            app.UseAuthentication();
            app.UseAuthorization();
            app.MapControllers();
            app.Run();
        }

        // ------------------- JWKS Cache -------------------
        public static class JwksCache
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
                    // fallback if fetching JWKS fails
                    return Array.Empty<SecurityKey>();
                }
            }
        }

        // ------------------- Fake Keys -------------------
        public static SecurityKey[] GetFakeKeys()
        {
            using var rsa = RSA.Create(2048);
            var key = new RsaSecurityKey(rsa) { KeyId = "fake-key" };
            Console.WriteLine("[TEST] Using fake key for JWT verification");
            Console.Out.Flush();
            return new SecurityKey[] { key };
        }
    }
}
*/