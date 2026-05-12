using System.Security.Claims;
using Duende.IdentityServer.Models;
using Duende.IdentityServer.Services;
using Duende.IdentityServer.Stores;
using Duende.IdentityServer.Validation;

namespace IdentityService.Services;

public class TokenGeneratorService(
    ITokenService tokenService,
    IClientStore clientStore
)
{
    public async Task<string> GenerateClientCredentialsTokenAsync(string clientId, string scope, Dictionary<string, string> additionalClaims = null)
    {
        var client = await clientStore.FindEnabledClientByIdAsync(clientId);
        if (client == null)
            throw new InvalidOperationException("Client not found");

        var now = DateTime.UtcNow;
        var issuer = "https://localhost.balazskrizsan.com:4040";

        var claims = new List<Claim>
        {
            new("sub", clientId),
            new("client_id", clientId),
            new("iss", issuer),
            new("aud", issuer),
            new("scope", scope)
        };

        if (additionalClaims != null)
        {
            foreach (var claim in additionalClaims)
            {
                claims.Add(new Claim(claim.Key, claim.Value));
            }
        }

        var tokenRequest = new TokenCreationRequest
        {
            ValidatedResources = new ResourceValidationResult
            {
                Resources = new Resources
                {
                    ApiResources = new List<ApiResource>(),
                    ApiScopes = new List<ApiScope> { new ApiScope(scope) }
                }
            },
            ValidatedRequest = new ValidatedRequest
            {
                ClientId = clientId,
                Client = client,
                Subject = new ClaimsPrincipal(new ClaimsIdentity(claims))
            }
        };

        var token = await tokenService.CreateAccessTokenAsync(tokenRequest);

        token.CreationTime = now;
        token.Issuer = issuer;
        token.Audiences = new[] { issuer };
        token.Lifetime = client.AccessTokenLifetime;
        token.Claims.Add(new Claim("scope", scope));

        if (additionalClaims != null)
        {
            foreach (var claim in additionalClaims)
            {
                token.Claims.Add(new Claim(claim.Key, claim.Value));
            }
        }

        return await tokenService.CreateSecurityTokenAsync(token);
    }
}
