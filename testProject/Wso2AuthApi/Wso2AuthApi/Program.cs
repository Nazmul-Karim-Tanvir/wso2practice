using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.Text.Json;
using System.Security.Claims;
using Microsoft.IdentityModel.JsonWebTokens;

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
            NameClaimType = ClaimTypes.Name
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

        // 👇 Events for logging & error handling
        options.Events = new JwtBearerEvents
        {
            OnTokenValidated = ctx =>
            {
                var identity = ctx.Principal?.Identity as ClaimsIdentity;
                var jwt = ctx.SecurityToken as JsonWebToken;

                if (identity != null && jwt != null)
                {
                    // Remove existing role claims
                    foreach (var rc in identity.FindAll(ClaimTypes.Role).ToList())
                        identity.RemoveClaim(rc);

                    // Add roles from JWT payload
                    if (jwt.TryGetPayloadValue("roles", out JsonElement jsonElement) &&
                        jsonElement.ValueKind == JsonValueKind.Array)
                    {
                        foreach (var roleElement in jsonElement.EnumerateArray())
                        {
                            var role = roleElement.GetString();
                            if (!string.IsNullOrEmpty(role))
                                identity.AddClaim(new Claim(ClaimTypes.Role, role));
                        }
                    }

                    // Set Name claim from "sub" or fallback to "email"
                    var name = jwt.Claims.FirstOrDefault(c => c.Type == "sub")?.Value
                               ?? jwt.Claims.FirstOrDefault(c => c.Type == "email")?.Value;
                    if (!string.IsNullOrEmpty(name) && !identity.HasClaim(c => c.Type == ClaimTypes.Name))
                        identity.AddClaim(new Claim(ClaimTypes.Name, name));
                }

                // Logging
                var logger = ctx.HttpContext.RequestServices.GetRequiredService<ILogger<Program>>();
                var userName = ctx.Principal?.Identity?.Name ?? "(no name)";
                var roles = identity?.Claims
                                    .Where(c => c.Type == ClaimTypes.Role)
                                    .Select(c => c.Value)
                                    .ToList() ?? new List<string>();
                logger.LogInformation("[JWT] Token validated for: {User}", userName);
                logger.LogInformation("[JWT] Roles after mapping: {Roles}", string.Join(", ", roles));

                return Task.CompletedTask;
            },

            OnAuthenticationFailed = ctx =>
            {
                var logger = ctx.HttpContext.RequestServices.GetRequiredService<ILogger<Program>>();
                logger.LogWarning(ctx.Exception, "[JWT] Authentication failed");

                // // ctx.Response.StatusCode = 401;
                // // ctx.Response.ContentType = "application/json";

                // string message = ctx.Exception switch
                // {
                //     SecurityTokenExpiredException => "{\"error\": \"Token has expired\"}",
                //     SecurityTokenInvalidIssuerException => "{\"error\": \"Invalid token issuer\"}",
                //     _ => "{\"error\": \"Authentication failed\"}"
                // };

                return Task.CompletedTask;
            }
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