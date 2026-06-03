using Duende.IdentityServer;
using Duende.IdentityServer.Events;
using Duende.IdentityServer.Services;
using IdentityServer.Services;
using IdentityService.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace IdentityService.Pages.Account.QuickRegisterFinish;

[SecurityHeaders]
[AllowAnonymous]
public class Index(
    IEventService events,
    UserManager<IdentityUser> userManager,
    SignInManager<IdentityUser> signInManager,
    ITokenValidationService tokenValidationService,
    RegisterService registerService)
    : PageModel
{
    public ViewModel View { get; set; } = default!;

    [BindProperty] public InputModel Input { get; set; } = default!;

    public async Task<IActionResult> OnGet(string? token)
    {
        if (string.IsNullOrWhiteSpace(token))
        {
            ModelState.AddModelError(string.Empty, "Token is required");
            return Page();
        }

        var validationResult = await ValidateTokenAsync(token, "smart_scrum_poker_ids_quick_register_finish");
        if (!validationResult.IsValid)
        {
            ModelState.AddModelError(string.Empty, validationResult.ErrorMessage);
            return Page();
        }

        Input = new InputModel
        {
            Token = token,
            Email = validationResult.Email,
            UserId = validationResult.UserId
        };

        return Page();
    }

    public async Task<IActionResult> OnPost()
    {
        if (ModelState.IsValid)
        {
            if (Input.Password != Input.ConfirmPassword)
            {
                ModelState.AddModelError(string.Empty, "Passwords do not match");
                return Page();
            }

            var validationResult = await ValidateTokenAsync(Input.Token, "smart_scrum_poker_ids_quick_register_finish");
            if (!validationResult.IsValid)
            {
                ModelState.AddModelError(string.Empty, validationResult.ErrorMessage);
                return Page();
            }

            var user = await userManager.FindByIdAsync(validationResult.UserId);
            if (user == null)
            {
                ModelState.AddModelError(string.Empty, "User not found");
                return Page();
            }

            if (user.Email != validationResult.Email)
            {
                ModelState.AddModelError(string.Empty, "Email mismatch");
                return Page();
            }

            await userManager.RemovePasswordAsync(user);
            var result = await userManager.AddPasswordAsync(user, Input.Password!);
            if (result.Succeeded)
            {
                await registerService.ConfirmEmailAsync(user);
                await registerService.CleanupDuplicateUsersAsync(user);
                await signInManager.SignInAsync(user, isPersistent: false);
                await events.RaiseAsync(new UserLoginSuccessEvent("N/A", user.Id, "N/A", clientId: null));
                Telemetry.Metrics.UserLogin(null, IdentityServerConstants.LocalIdentityProvider);

                return Redirect("~/");
            }

            foreach (var error in result.Errors)
            {
                ModelState.AddModelError(string.Empty, error.Description);
            }
        }

        return Page();
    }

    private async Task<TokenValidationResult> ValidateTokenAsync(string token, string clientId)
    {
        var validationResult = await tokenValidationService.ValidateTokenAsync(token, clientId);

        if (!validationResult.IsValid)
        {
            return validationResult;
        }

        if (validationResult.Scope != "user.quick_register.finish")
        {
            return new TokenValidationResult { IsValid = false, ErrorMessage = "Invalid token scope" };
        }

        return validationResult;
    }

    public class ViewModel
    {
    }

    public class InputModel
    {
        public string Token { get; set; } = string.Empty;
        public string Email { get; set; } = string.Empty;
        public string UserId { get; set; } = string.Empty;
        public string? Password { get; set; }
        public string? ConfirmPassword { get; set; }
    }
}
