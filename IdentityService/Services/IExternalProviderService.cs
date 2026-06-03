using Duende.IdentityServer.Models;
using IdentityService.Pages.Login;

namespace IdentityService.Services;

public interface IExternalProviderService
{
    Task<List<ViewModel.ExternalProvider>> GetAllProvidersAsync();
    Task<(List<ViewModel.ExternalProvider> providers, bool allowLocal)> GetFilteredProvidersAsync(AuthorizationRequest? context);
}
