using Duende.IdentityServer.Models;
using Duende.IdentityServer.Stores;
using Microsoft.AspNetCore.Authentication;
using IdentityService.Pages.Login;

namespace IdentityService.Repositories;

public class ExternalProviderRepository(
    IAuthenticationSchemeProvider schemeProvider,
    IIdentityProviderStore identityProviderStore
) : IExternalProviderRepository
{
    public async Task<List<ViewModel.ExternalProvider>> GetAllProvidersAsync()
    {
        var schemes = await schemeProvider.GetAllSchemesAsync();

        var providers = schemes
            .Where(x => x.DisplayName != null)
            .Select(x => new ViewModel.ExternalProvider
            (
                authenticationScheme: x.Name,
                displayName: x.DisplayName ?? x.Name
            )).ToList();

        var dynamicSchemes = (await identityProviderStore.GetAllSchemeNamesAsync())
            .Where(x => x.Enabled)
            .Select(x => new ViewModel.ExternalProvider
            (
                authenticationScheme: x.Scheme,
                displayName: x.DisplayName ?? x.Scheme
            ));
        
        providers.AddRange(dynamicSchemes);

        return providers;
    }

    public async Task<(List<ViewModel.ExternalProvider> providers, bool allowLocal)> GetFilteredProvidersAsync(AuthorizationRequest? context)
    {
        var providers = await GetAllProvidersAsync();
        var allowLocal = true;
        var client = context?.Client;

        if (client != null)
        {
            allowLocal = client.EnableLocalLogin;
            if (client.IdentityProviderRestrictions.Count != 0)
            {
                providers = providers.Where(provider =>
                    client.IdentityProviderRestrictions.Contains(provider.AuthenticationScheme)).ToList();
            }
        }

        return (providers, allowLocal);
    }
}
