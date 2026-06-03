using Duende.IdentityServer;
using Duende.IdentityServer.Events;
using Duende.IdentityServer.Models;
using Duende.IdentityServer.Services;
using IdentityService.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using SignInResult = Microsoft.AspNetCore.Identity.SignInResult;

namespace IdentityService.Pages.Login;

[SecurityHeaders]
[AllowAnonymous]
public class Index(
    IIdentityServerInteractionService interaction,
    IEventService events,
    SignInManager<IdentityUser> signInManager,
    UserInputValidationService validationService,
    QuicRegisterService quicRegisterService,
    ILoginModelBuilderService loginModelBuilderService,
    IUserLookupService userLookupService
)
    : PageModel
{
    public ViewModel View { get; set; } = default!;

    [BindProperty] public InputModel Input { get; set; } = default!;

    [BindProperty] public QuickRegisterInputModel QuickRegisterInput { get; set; } = default!;

    public async Task<IActionResult> OnGet(string? returnUrl)
    {
        var modelData = await loginModelBuilderService.BuildModelAsync(returnUrl);
        Input = modelData.Input;
        QuickRegisterInput = modelData.QuickRegisterInput;
        View = modelData.View;

        if (View.IsExternalLoginOnly)
        {
            // we only have one option for logging in and it's an external provider
            return RedirectToPage("/ExternalLogin/Challenge", new { scheme = View.ExternalLoginScheme, returnUrl });
        }

        return Page();
    }

    public async Task<IActionResult> OnPost()
    {
        // check if we are in the context of an authorization request
        var context = await interaction.GetAuthorizationContextAsync(Input.ReturnUrl);

        // Handle QuickRegister button
        if (QuickRegisterInput.Button == "quickregister")
        {
            return await HandleQuickRegisterAsync(context);
        }

        if (Input.Button == "login")
        {
            return await HandleLocalLoginAsync(context);
        }

        // something went wrong, show form with error
        return await BuildAndReturnPageAsync(Input.ReturnUrl);
    }

    private async Task<IActionResult> HandleLocalLoginAsync(AuthorizationRequest? context)
    {
        var validationResult = validationService.ValidateLocalAccountInput(Input, ModelState);

        if (!validationResult.IsValid)
        {
            return await BuildAndReturnPageAsync(Input.ReturnUrl);
        }

        var user = await userLookupService.FindUserByEmailAsync(Input.Email);

        // validate username/password against in-memory store
        if (user != null && (await signInManager.CheckPasswordSignInAsync(user, Input.Password, false)) ==
            SignInResult.Success)
        {
            await events.RaiseAsync(new UserLoginSuccessEvent(user.UserName, user.Id, user.UserName,
                clientId: context?.Client.ClientId));
            Telemetry.Metrics.UserLogin(context?.Client.ClientId, IdentityServerConstants.LocalIdentityProvider);

            // only set explicit expiration here if user chooses "remember me". 
            // otherwise we rely upon expiration configured in cookie middleware.
            var props = new AuthenticationProperties();
            if (LoginOptions.AllowRememberLogin && Input.RememberLogin)
            {
                props.IsPersistent = true;
                props.ExpiresUtc = DateTimeOffset.UtcNow.Add(LoginOptions.RememberMeLoginDuration);
            }

            // issue authentication cookie with subject ID and username
            var isuser = new IdentityServerUser(user.Id)
            {
                DisplayName = user.UserName
            };

            await HttpContext.SignInAsync(isuser, props);

            if (context != null)
            {
                // This "can't happen", because if the ReturnUrl was null, then the context would be null
                ArgumentNullException.ThrowIfNull(Input.ReturnUrl, nameof(Input.ReturnUrl));

                if (context.IsNativeClient())
                {
                    // The client is native, so this change in how to
                    // return the response is for better UX for the end user.
                    return this.LoadingPage(Input.ReturnUrl);
                }

                // we can trust model.ReturnUrl since GetAuthorizationContextAsync returned non-null
                return Redirect(Input.ReturnUrl ?? "~/");
            }

            // request for a local page
            if (Url.IsLocalUrl(Input.ReturnUrl))
            {
                return Redirect(Input.ReturnUrl);
            }

            if (string.IsNullOrEmpty(Input.ReturnUrl))
            {
                return Redirect("~/");
            }

            // user might have clicked on a malicious link - should be logged
            throw new ArgumentException("invalid return URL");
        }

        const string error = "invalid credentials";
        await events.RaiseAsync(new UserLoginFailureEvent(Input.Email, error, clientId: context?.Client.ClientId));
        Telemetry.Metrics.UserLoginFailure(context?.Client.ClientId, IdentityServerConstants.LocalIdentityProvider,
            error);
        ModelState.AddModelError(string.Empty, LoginOptions.InvalidCredentialsErrorMessage);

        // something went wrong, show form with error
        return await BuildAndReturnPageAsync(Input.ReturnUrl);
    }

    private async Task<IActionResult> HandleQuickRegisterAsync(AuthorizationRequest? context)
    {
        // Generate name if not provided
        if (string.IsNullOrWhiteSpace(QuickRegisterInput.Name))
        {
            QuickRegisterInput.Name = quicRegisterService.GenerateNicknameWithTimestamp(QuickRegisterInput.Nickname);
        }

        // Validate input using the validation service
        var validationResult = validationService.ValidateQuickRegisterInput(QuickRegisterInput, ModelState);

        if (!validationResult.IsValid)
        {
            return await BuildAndReturnPageAsync(QuickRegisterInput.ReturnUrl);
        }

        // Create user using the quick register service
        var (user, result) = await quicRegisterService.CreateQuickUserAsync(
            QuickRegisterInput.Name,
            QuickRegisterInput.Email,
            QuickRegisterInput.Nickname);

        if (result.Succeeded)
        {
            await events.RaiseAsync(
                new UserLoginSuccessEvent("N/A", user.Id, "N/A", clientId: context?.Client.ClientId)
            );
            Telemetry.Metrics.UserLogin(context?.Client.ClientId, IdentityServerConstants.LocalIdentityProvider);

            var isuser = new IdentityServerUser(user.Id)
            {
                DisplayName = user.UserName
            };

            await HttpContext.SignInAsync(isuser);
            await quicRegisterService.TrySendCompleteRegistrationToken(user);

            if (context != null)
            {
                ArgumentNullException.ThrowIfNull(QuickRegisterInput.ReturnUrl, nameof(QuickRegisterInput.ReturnUrl));

                if (context.IsNativeClient())
                {
                    return this.LoadingPage(QuickRegisterInput.ReturnUrl);
                }

                return Redirect(QuickRegisterInput.ReturnUrl ?? "~/");
            }

            if (Url.IsLocalUrl(QuickRegisterInput.ReturnUrl))
            {
                return Redirect(QuickRegisterInput.ReturnUrl);
            }

            if (string.IsNullOrEmpty(QuickRegisterInput.ReturnUrl))
            {
                return Redirect("~/");
            }

            throw new ArgumentException("invalid return URL");
        }

        foreach (var error in result.Errors)
        {
            ModelState.AddModelError(string.Empty, error.Description);
        }

        // If we got here, something failed, redisplay form
        return await BuildAndReturnPageAsync(QuickRegisterInput.ReturnUrl);
    }

    private async Task<IActionResult> BuildAndReturnPageAsync(string? returnUrl)
    {
        var modelData = await loginModelBuilderService.BuildModelAsync(returnUrl);
        Input = modelData.Input;
        QuickRegisterInput = modelData.QuickRegisterInput;
        View = modelData.View;

        return Page();
    }
}