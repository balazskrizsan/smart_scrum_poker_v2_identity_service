using Duende.IdentityServer;
using Duende.IdentityServer.Events;
using Duende.IdentityServer.Models;
using Duende.IdentityServer.Services;
using Duende.IdentityServer.Stores;
using Duende.IdentityServer.Test;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using SignInResult = Microsoft.AspNetCore.Identity.SignInResult;
using System.Security.Claims;

namespace IdentityService.Pages.Login;

[SecurityHeaders]
[AllowAnonymous]
public class Index : PageModel
{
    private readonly IIdentityServerInteractionService _interaction;
    private readonly IEventService _events;
    private readonly SignInManager<IdentityUser> _signInManager;
    private readonly IAuthenticationSchemeProvider _schemeProvider;
    private readonly IIdentityProviderStore _identityProviderStore;
    private readonly UserManager<IdentityUser> _userManager;

    public ViewModel View { get; set; } = default!;

    [BindProperty]
    public InputModel Input { get; set; } = default!;

    [BindProperty]
    public QuickRegisterInputModel QuickRegisterInput { get; set; } = default!;

    public Index(
        IIdentityServerInteractionService interaction,
        IAuthenticationSchemeProvider schemeProvider,
        IIdentityProviderStore identityProviderStore,
        IEventService events, 
        SignInManager<IdentityUser> signInManager,
        UserManager<IdentityUser> userManager)
    {

        _interaction = interaction;
        _schemeProvider = schemeProvider;
        _identityProviderStore = identityProviderStore;
        _events = events;
        _signInManager = signInManager;
        _userManager = userManager;
    }

    public async Task<IActionResult> OnGet(string? returnUrl)
    {
        await BuildModelAsync(returnUrl);

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
        var context = await _interaction.GetAuthorizationContextAsync(Input.ReturnUrl);

        // Handle QuickRegister button
        if (QuickRegisterInput.Button == "quickregister")
        {
            return await HandleQuickRegisterAsync(context);
        }

        if (Input.Button == "login")
        {
            return await HandleLocalLoginAsync(context);
        }

        // // the user clicked the "cancel" button
        // if (Input.Button != "login")
        // {
        //     if (context != null)
        //     {
        //         // This "can't happen", because if the ReturnUrl was null, then the context would be null
        //         ArgumentNullException.ThrowIfNull(Input.ReturnUrl, nameof(Input.ReturnUrl));
        //
        //         // if the user cancels, send a result back into IdentityService as if they 
        //         // denied the consent (even if this client does not require consent).
        //         // this will send back an access denied OIDC error response to the client.
        //         await _interaction.DenyAuthorizationAsync(context, AuthorizationError.AccessDenied);
        //
        //         // we can trust model.ReturnUrl since GetAuthorizationContextAsync returned non-null
        //         if (context.IsNativeClient())
        //         {
        //             // The client is native, so this change in how to
        //             // return the response is for better UX for the end user.
        //             return this.LoadingPage(Input.ReturnUrl);
        //         }
        //
        //         return Redirect(Input.ReturnUrl ?? "~/");
        //     }
        //     else
        //     {
        //         // since we don't have a valid context, then we just go back to the home page
        //         return Redirect("~/");
        //     }
        // }

        // something went wrong, show form with error
        await BuildModelAsync(Input.ReturnUrl);
        return Page();
    }

    private async Task<IActionResult> HandleLocalLoginAsync(Duende.IdentityServer.Models.AuthorizationRequest? context)
    {
        // Debug: Log the input email
        var inputEmail = Input.Email?.Trim();
        System.Diagnostics.Debug.WriteLine($"Looking for user with email: '{inputEmail}'");
        
        var user = await _signInManager.UserManager.FindByEmailAsync(inputEmail);
        
        // Debug: Log if user was found
        System.Diagnostics.Debug.WriteLine($"User found: {user != null}");
        
        // If user not found, try alternative lookup methods
        if (user == null)
        {
            // Try case-insensitive search by normalized email
            var normalizedEmail = _userManager.NormalizeEmail(inputEmail);
            user = await _userManager.Users.FirstOrDefaultAsync(u => u.NormalizedEmail == normalizedEmail);
            System.Diagnostics.Debug.WriteLine($"User found by normalized email: {user != null}");
            
            // If still not found, try case-insensitive search by regular email
            if (user == null)
            {
                user = await _userManager.Users.FirstOrDefaultAsync(u => u.Email.ToLower() == inputEmail.ToLower());
                System.Diagnostics.Debug.WriteLine($"User found by case-insensitive email: {user != null}");
            }
            
            // Debug: List all users if still not found
            if (user == null)
            {
                var allUsers = await _userManager.Users.ToListAsync();
                System.Diagnostics.Debug.WriteLine($"Total users in DB: {allUsers.Count}");
                foreach (var u in allUsers)
                {
                    System.Diagnostics.Debug.WriteLine($"User: {u.UserName}, Email: '{u.Email}', NormalizedEmail: '{u.NormalizedEmail}'");
                }
            }
        }
        // validate username/password against in-memory store
        if (user != null && (await _signInManager.CheckPasswordSignInAsync(user, Input.Password, false)) == SignInResult.Success)
        {
            
            await _events.RaiseAsync(new UserLoginSuccessEvent(user.UserName, user.Id, user.UserName, clientId: context?.Client.ClientId));
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
            else if (string.IsNullOrEmpty(Input.ReturnUrl))
            {
                return Redirect("~/");
            }
            else
            {
                // user might have clicked on a malicious link - should be logged
                throw new ArgumentException("invalid return URL");
            }
        }

        const string error = "invalid credentials";
        await _events.RaiseAsync(new UserLoginFailureEvent(Input.Email, error, clientId: context?.Client.ClientId));
        Telemetry.Metrics.UserLoginFailure(context?.Client.ClientId, IdentityServerConstants.LocalIdentityProvider, error);
        ModelState.AddModelError(string.Empty, LoginOptions.InvalidCredentialsErrorMessage);

        // something went wrong, show form with error
        await BuildModelAsync(Input.ReturnUrl);
        return Page();
    }

    private async Task<IActionResult> HandleQuickRegisterAsync(Duende.IdentityServer.Models.AuthorizationRequest? context)
    {
        // Clear ModelState and only validate QuickRegisterInput
        ModelState.Clear();
        
        // Generate name if not provided
        if (string.IsNullOrWhiteSpace(QuickRegisterInput.Name))
        {
            QuickRegisterInput.Name = GenerateNicknameWithTimestamp(QuickRegisterInput.Nickname);
        }
        
        if (TryValidateModel(QuickRegisterInput))
        {
            // Generate random password
            var randomPassword = GenerateRandomPassword();
            
            // Create new user with random password
            var user = new IdentityUser
            {
                UserName = QuickRegisterInput.Name,
                Email = QuickRegisterInput.Email,
                EmailConfirmed = false
            };

            var result = await _userManager.CreateAsync(user, randomPassword);
            
            if (result.Succeeded)
            {
                // Add nickname claim if provided
                if (!string.IsNullOrWhiteSpace(QuickRegisterInput.Nickname))
                {
                    await _userManager.AddClaimAsync(user, new Claim("nickname", QuickRegisterInput.Nickname));
                }

                // Auto-login the new user
                await _signInManager.SignInAsync(user, isPersistent: false);
                
                await _events.RaiseAsync(new UserLoginSuccessEvent(user.UserName, user.Id, user.UserName, clientId: context?.Client.ClientId));
                Telemetry.Metrics.UserLogin(context?.Client.ClientId, IdentityServerConstants.LocalIdentityProvider);

                // Create authentication cookie
                var isuser = new IdentityServerUser(user.Id)
                {
                    DisplayName = user.UserName
                };

                await HttpContext.SignInAsync(isuser);

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
                else if (string.IsNullOrEmpty(QuickRegisterInput.ReturnUrl))
                {
                    return Redirect("~/");
                }
                else
                {
                    throw new ArgumentException("invalid return URL");
                }
            }

            foreach (var error in result.Errors)
            {
                ModelState.AddModelError(string.Empty, error.Description);
            }
        }

        // If we got here, something failed, redisplay form
        await BuildModelAsync(QuickRegisterInput.ReturnUrl);
        return Page();
    }

    private async Task BuildModelAsync(string? returnUrl)
    {
        Input = new InputModel
        {
            ReturnUrl = returnUrl
        };

        QuickRegisterInput = new QuickRegisterInputModel
        {
            ReturnUrl = returnUrl
        };

        var context = await _interaction.GetAuthorizationContextAsync(returnUrl);
        if (context?.IdP != null)
        {
            var scheme = await _schemeProvider.GetSchemeAsync(context.IdP);
            if (scheme != null)
            {
                var local = context.IdP == Duende.IdentityServer.IdentityServerConstants.LocalIdentityProvider;

                // this is meant to short circuit the UI and only trigger the one external IdP
                View = new ViewModel
                {
                    EnableLocalLogin = local,
                };

                Input.Email = context.LoginHint;

                if (!local)
                {
                    View.ExternalProviders = [new ViewModel.ExternalProvider(authenticationScheme: context.IdP, displayName: scheme.DisplayName)];
                }
            }

            return;
        }

        var schemes = await _schemeProvider.GetAllSchemesAsync();

        var providers = schemes
            .Where(x => x.DisplayName != null)
            .Select(x => new ViewModel.ExternalProvider
            (
                authenticationScheme: x.Name,
                displayName: x.DisplayName ?? x.Name
            )).ToList();

        var dynamicSchemes = (await _identityProviderStore.GetAllSchemeNamesAsync())
            .Where(x => x.Enabled)
            .Select(x => new ViewModel.ExternalProvider
            (
                authenticationScheme: x.Scheme,
                displayName: x.DisplayName ?? x.Scheme
            ));
        providers.AddRange(dynamicSchemes);


        var allowLocal = true;
        var client = context?.Client;
        if (client != null)
        {
            allowLocal = client.EnableLocalLogin;
            if (client.IdentityProviderRestrictions != null && client.IdentityProviderRestrictions.Count != 0)
            {
                providers = providers.Where(provider => client.IdentityProviderRestrictions.Contains(provider.AuthenticationScheme)).ToList();
            }
        }

        View = new ViewModel
        {
            AllowRememberLogin = LoginOptions.AllowRememberLogin,
            EnableLocalLogin = allowLocal && LoginOptions.AllowLocalLogin,
            ExternalProviders = providers.ToArray()
        };
    }

    private static string GenerateRandomPassword()
    {
        const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*";
        var random = new Random();
        var password = new char[16];
        
        for (int i = 0; i < password.Length; i++)
        {
            password[i] = chars[random.Next(chars.Length)];
        }
        
        return new string(password);
    }

    private static string GenerateNicknameWithTimestamp(string? nickname)
    {
        // If no nickname provided, generate a random one
        if (string.IsNullOrWhiteSpace(nickname))
        {
            var nicknames = new[] { "Vendeg", "User", "Jatekos", "Tag", "Felhasznalo", "Latogato" };
            var random = new Random();
            nickname = nicknames[random.Next(nicknames.Length)];
        }
        
        var now = DateTime.Now;
        var timestamp = now.ToString("yyyyMMdd_HHmmss");
        
        return $"{nickname}_{timestamp}";
    }
}
