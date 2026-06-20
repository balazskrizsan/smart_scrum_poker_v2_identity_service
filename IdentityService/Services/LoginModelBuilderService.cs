using Duende.IdentityServer;
using Duende.IdentityServer.Services;
using IdentityService.Pages.Login;
using Microsoft.AspNetCore.Authentication;

namespace IdentityService.Services;

public class LoginModelBuilderService(
    IIdentityServerInteractionService interaction,
    IAuthenticationSchemeProvider schemeProvider,
    IExternalProviderService externalProviderService
) : ILoginModelBuilderService
{
    public async Task<LoginModelData> BuildModelAsync(string? returnUrl)
    {
        Console.WriteLine($"[LoginModelBuilder] ReturnUrl: {returnUrl}");
        var input = new InputModel
        {
            ReturnUrl = returnUrl
        };

        var quickRegisterInput = new QuickRegisterInputModel
        {
            ReturnUrl = returnUrl
        };

        var context = await interaction.GetAuthorizationContextAsync(returnUrl);
        Console.WriteLine($"[LoginModelBuilder] Context: {context != null}, ClientId: {context?.Client.ClientId}");
        if (context?.IdP != null)
        {
            var scheme = await schemeProvider.GetSchemeAsync(context.IdP);
            if (scheme != null)
            {
                var local = context.IdP == IdentityServerConstants.LocalIdentityProvider;

                // this is meant to short circuit the UI and only trigger the one external IdP
                var view = new ViewModel
                {
                    EnableLocalLogin = local,
                };

                input.Email = context.LoginHint;

                if (!local)
                {
                    view.ExternalProviders =
                    [
                        new ViewModel.ExternalProvider(authenticationScheme: context.IdP,
                            displayName: scheme.DisplayName)
                    ];
                }

                return new LoginModelData
                {
                    Input = input,
                    QuickRegisterInput = quickRegisterInput,
                    View = view
                };
            }

            // Fall through to default if scheme is null
        }

        var (providers, allowLocal) = await externalProviderService.GetFilteredProvidersAsync(context);

        var viewModel = new ViewModel
        {
            AllowRememberLogin = LoginOptions.AllowRememberLogin,
            EnableLocalLogin = allowLocal && LoginOptions.AllowLocalLogin,
            ExternalProviders = providers.ToArray()
        };

        return new LoginModelData
        {
            Input = input,
            QuickRegisterInput = quickRegisterInput,
            View = viewModel
        };
    }
}
