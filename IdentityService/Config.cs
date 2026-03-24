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
        new("scope1"),
        new("scope2")
    ];

    public static IEnumerable<Client> Clients =>
    [
        new()
        {
            ClientId = "smart_scrum_poker_frontend",
            RequireClientSecret = false,
            // ClientSecrets = { new Secret("49C1A7E1-0C79-4A89-A3D6-A37998FB86B0".Sha256()) },

            AllowedGrantTypes = GrantTypes.Code,

            RedirectUris = { "https://localhost.balazskrizsan.com:3010/auth-callback" },
            AllowedCorsOrigins = { "https://localhost.balazskrizsan.com:3010" },
            // FrontChannelLogoutUri = "https://localhost:44300/signout-oidc",
            // PostLogoutRedirectUris = { "https://localhost:44300/signout-callback-oidc" },

            AllowOfflineAccess = true,
            AllowedScopes = { "openid", "profile", "nickname" }
        }
    ];
}