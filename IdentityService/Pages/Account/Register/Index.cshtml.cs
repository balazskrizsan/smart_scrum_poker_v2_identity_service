using Duende.IdentityServer;
using Duende.IdentityServer.Events;
using Duende.IdentityServer.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.Security.Claims;

namespace IdentityService.Pages.Register;

[SecurityHeaders]
[AllowAnonymous]
public class Index : PageModel
{
    private readonly UserManager<IdentityUser> _userManager;
    private readonly SignInManager<IdentityUser> _signInManager;
    private readonly IIdentityServerInteractionService _interaction;
    private readonly IEventService _events;

    public ViewModel View { get; set; } = default!;
        
    [BindProperty]
    public InputModel Input { get; set; } = default!;
        
    public Index(
        IIdentityServerInteractionService interaction,
        IEventService events,
        UserManager<IdentityUser> userManager,
        SignInManager<IdentityUser> signInManager)
    {
        _userManager = userManager;
        _signInManager = signInManager;
        _interaction = interaction;
        _events = events;
    }

    public async Task<IActionResult> OnGet(string? returnUrl)
    {
        Input = new InputModel
        {
            ReturnUrl = returnUrl
        };

        return Page();
    }
        
    public async Task<IActionResult> OnPost()
    {
        // the user clicked the "cancel" button
        if (Input.Button != "register")
        {
            return Redirect(Input.ReturnUrl ?? "~/");
        }

        if (ModelState.IsValid)
        {
            // Generate username from nickname
            var generatedUsername = GenerateNicknameWithTimestamp(Input.Nickname);
            
            var user = new IdentityUser
            {
                UserName = generatedUsername,
                Email = Input.Email
            };

            var result = await _userManager.CreateAsync(user, Input.Password!);

            if (result.Succeeded)
            {
                // Add nickname claim
                if (!string.IsNullOrWhiteSpace(Input.Nickname))
                {
                    await _userManager.AddClaimAsync(user, new Claim("nickname", Input.Nickname));
                }
                
                await _signInManager.SignInAsync(user, isPersistent: false);
                await _events.RaiseAsync(new UserLoginSuccessEvent(user.UserName, user.Id, user.UserName, clientId: null));
                Telemetry.Metrics.UserLogin(null, IdentityServerConstants.LocalIdentityProvider);

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

            foreach (var error in result.Errors)
            {
                ModelState.AddModelError(string.Empty, error.Description);
            }
        }

        // If we got this far, something failed, redisplay form
        return Page();
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
