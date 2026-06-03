using System.Security.Claims;
using Duende.IdentityServer.Extensions;
using Microsoft.AspNetCore.Identity;

namespace IdentityService.Services;

public class QuicRegisterService(
    UserManager<IdentityUser> userManager,
    SignInManager<IdentityUser> signInManager,
    AwsSesService awsSesService,
    TokenGeneratorService tokenGeneratorService
)
{
    public async Task<(IdentityUser? user, IdentityResult result)> CreateQuickUserAsync(string name, string email,
        string? nickname)
    {
        var randomPassword = GenerateRandomPassword();

        var user = new IdentityUser
        {
            UserName = name,
            Email = email,
            EmailConfirmed = false
        };

        var result = await userManager.CreateAsync(user, randomPassword);

        if (result.Succeeded)
        {
            if (!string.IsNullOrWhiteSpace(nickname))
            {
                await userManager.AddClaimAsync(user, new Claim("nickname", nickname));
            }

            await signInManager.SignInAsync(user, isPersistent: false);
        }

        return (user, result);
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

        return new string(password) + "aA_-%!123";
    }

    public async Task TrySendCompleteRegistrationToken(IdentityUser user)
    {
        if (user.Email.IsNullOrEmpty())
        {
            return;
        }

        var quickRegFinish = await tokenGeneratorService.GenerateClientCredentialsTokenAsync(
            "smart_scrum_poker_ids_quick_register_finish",
            "user.quick_register.finish",
            new Dictionary<string, string>()
            {
                { "user_id", user.Id },
                { "user_email", user.Email },
            }
        );
        var completeRegistrationUrl =
            $"https://localhost.balazskrizsan.com:4040/Account/QuickRegisterFinish?token={Uri.EscapeDataString(quickRegFinish)}";

        await awsSesService.SendTemplatedEmailByIdAsync(new AwsSesService.TemplatedEmailByIdRequest
        {
            To = "krizsan.balazs@gmail.com",
            Subject = "New user created - complete your registration",
            TemplateId = "complete-quick-registration",
            TemplateVariables = new Dictionary<string, string>()
            {
                { "email", user.Email },
                { "completionUrl", completeRegistrationUrl },
            }
        });
    }

    public string GenerateNicknameWithTimestamp(string nickname)
    {
        var now = DateTime.Now;
        var timestamp = now.ToString("yyyyMMdd_HHmmss");

        return $"{nickname}_{timestamp}";
    }
}
