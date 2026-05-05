using Duende.IdentityServer.Models;

namespace IdentityService;

public static class Config
{
    public static IEnumerable<IdentityResource> IdentityResources =>
    [
        new IdentityResources.OpenId(),
        new IdentityResources.Profile(),
        new IdentityResource("nickname", "User Nickname", ["nickname"])
    ];

    public static IEnumerable<ApiScope> ApiScopes =>
    [
        new("poker.start"),
        new("user.info.read"),
        new("aws.ses"),
    ];

    public static IEnumerable<ApiResource> ApiResources =>
    [
        new("userinfo.api", "User Info API")
        {
            Scopes = { "user.info.read" }
        },
        new("ssp_aws_services", "SSP AWS Services")
        {
            Scopes = { "aws.ses" }
        }
    ];

    public static IEnumerable<Client> Clients =>
    [
        new()
        {
            ClientId = "smart_scrum_poker_frontend",
            RequireClientSecret = false,

            AllowedGrantTypes = GrantTypes.Code,
            AccessTokenLifetime = 3600, // 1 hour
            AbsoluteRefreshTokenLifetime = 2592000, // 30 days
            SlidingRefreshTokenLifetime = 1296000, // 15 days

            RedirectUris = { "https://localhost.balazskrizsan.com:3010/auth-callback" },
            AllowedCorsOrigins = { "https://localhost.balazskrizsan.com:3010" },
            // FrontChannelLogoutUri = "https://localhost:44300/signout-oidc",
            // PostLogoutRedirectUris = { "https://localhost:44300/signout-callback-oidc" },

            AllowOfflineAccess = true,
            AllowedScopes = { "openid", "profile", "nickname", "poker.start" }
        },
        new()
        {
            ClientId = "smart_scrum_poker_ids",
            ClientSecrets = { new Secret("smart_scrum_poker_ids".Sha256()) },
            AllowedGrantTypes = GrantTypes.ClientCredentials,
            AccessTokenLifetime = 3600,
            AllowedScopes = { "user.info.read" }
        },
        new()
        {
            ClientId = "smart_scrum_poker_aws",
            ClientSecrets = { new Secret("smart_scrum_poker_aws".Sha256()) },
            AllowedGrantTypes = GrantTypes.ClientCredentials,
            AccessTokenLifetime = 3600,
            AllowedScopes = { "aws.ses" }
        }
    ];
}
