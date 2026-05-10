using System.Security.Claims;
using Microsoft.AspNetCore.Identity;

namespace IdentityService.Services
{
    public class QuicRegisterService(UserManager<IdentityUser> userManager, SignInManager<IdentityUser> signInManager)
    {
        public async Task<(IdentityUser? user, IdentityResult result)> CreateQuickUserAsync(string name, string email, string? nickname)
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

            return new string(password);
        }
    }
}