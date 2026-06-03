using Duende.IdentityServer.Models;
using IdentityService.Pages.Login;

namespace IdentityService.Repositories;

public interface IExternalProviderRepository
{
    Task<List<ViewModel.ExternalProvider>> GetAllProvidersAsync();
    Task<(List<ViewModel.ExternalProvider> providers, bool allowLocal)> GetFilteredProvidersAsync(AuthorizationRequest? context);
}
