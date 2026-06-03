using Duende.IdentityServer.Models;
using IdentityService.Pages.Login;
using IdentityService.Repositories;

namespace IdentityService.Services;

public class ExternalProviderService(IExternalProviderRepository repository) : IExternalProviderService
{
    public async Task<List<ViewModel.ExternalProvider>> GetAllProvidersAsync()
    {
        return await repository.GetAllProvidersAsync();
    }

    public async Task<(List<ViewModel.ExternalProvider> providers, bool allowLocal)> GetFilteredProvidersAsync(AuthorizationRequest? context)
    {
        return await repository.GetFilteredProvidersAsync(context);
    }
}
