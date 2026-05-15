using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;

namespace IdentityServer.Services;

public interface ITokenValidationService
{
    Task<TokenValidationResult> ValidateTokenAsync(string token, string clientId);
}

public class TokenValidationService : ITokenValidationService
{
    private readonly IConfiguration _configuration;
    private readonly IConfigurationManager<OpenIdConnectConfiguration> _configurationManager;

    public TokenValidationService(IConfiguration configuration)
    {
        _configuration = configuration;
        _configurationManager = new ConfigurationManager<OpenIdConnectConfiguration>(
            "https://localhost.balazskrizsan.com:4040/.well-known/openid-configuration",
            new OpenIdConnectConfigurationRetriever());
    }

    public async Task<TokenValidationResult> ValidateTokenAsync(string token, string clientId)
    {
        try
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var openIdConfig = await _configurationManager.GetConfigurationAsync(CancellationToken.None);

            var validationParameters = new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKeys = openIdConfig.SigningKeys,
                ValidateIssuer = true,
                ValidIssuer = "https://localhost.balazskrizsan.com:4040",
                ValidateAudience = true,
                ValidAudience = "https://localhost.balazskrizsan.com:4040",
                ValidateLifetime = true,
                ClockSkew = TimeSpan.Zero
            };

            var principal = tokenHandler.ValidateToken(token, validationParameters, out _);

            var userIdClaim = principal.FindFirst("user_id")?.Value;
            var userEmailClaim = principal.FindFirst("user_email")?.Value;
            var scopeClaim = principal.FindFirst("scope")?.Value;
            var clientClaim = principal.FindFirst("client_id")?.Value;

            if (string.IsNullOrWhiteSpace(userIdClaim) || string.IsNullOrWhiteSpace(userEmailClaim))
            {
                return new TokenValidationResult { IsValid = false, ErrorMessage = "Invalid token claims" };
            }

            if (clientClaim != clientId)
            {
                return new TokenValidationResult { IsValid = false, ErrorMessage = "Client mismatch" };
            }

            return new TokenValidationResult
            {
                IsValid = true,
                UserId = userIdClaim,
                Email = userEmailClaim,
                ClientId = clientClaim,
                Scope = scopeClaim
            };
        }
        catch (Exception ex)
        {
            return new TokenValidationResult
                { IsValid = false, ErrorMessage = $"Token validation failed: {ex.Message}" };
        }
    }
}

public class TokenValidationResult
{
    public bool IsValid { get; set; }
    public string? ErrorMessage { get; set; }
    public string? UserId { get; set; }
    public string? Email { get; set; }
    public string? ClientId { get; set; }
    public string? Scope { get; set; }
}
