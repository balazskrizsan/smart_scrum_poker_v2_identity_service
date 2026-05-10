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
    public async Task<string> GenerateClientCredentialsTokenAsync(string clientId, string scope)
    {
        var client = await clientStore.FindEnabledClientByIdAsync(clientId);
        if (client == null)
            throw new InvalidOperationException("Client not found");

        var now = DateTime.UtcNow;
        var issuer = "https://localhost.balazskrizsan.com:4040";

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
                Subject = new ClaimsPrincipal(new ClaimsIdentity(new[]
                {
                    new Claim("sub", clientId),
                    new Claim("client_id", clientId),
                    new Claim("iss", issuer),
                    new Claim("aud", issuer),
                    new Claim("scope", scope)
                }))
            }
        };

        var token = await tokenService.CreateAccessTokenAsync(tokenRequest);

        // Ensure proper timestamps
        token.CreationTime = now;
        token.Issuer = issuer;
        token.Audiences = new[] { issuer };
        token.Lifetime = client.AccessTokenLifetime;
        token.Claims.Add(new Claim("scope", scope));

        return await tokenService.CreateSecurityTokenAsync(token);
    }
}
