using System.Security.Claims;
using Microsoft.AspNetCore.Identity;

namespace IdentityService.Services
{
    public class QuicRegisterService
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly SignInManager<IdentityUser> _signInManager;

        public QuicRegisterService(UserManager<IdentityUser> userManager, SignInManager<IdentityUser> signInManager)
        {
            _userManager = userManager;
            _signInManager = signInManager;
        }

        public async Task<(IdentityUser? user, IdentityResult result)> CreateQuickUserAsync(string name, string email, string? nickname)
        {
            var randomPassword = GenerateRandomPassword();

            var user = new IdentityUser
            {
                UserName = name,
                Email = email,
                EmailConfirmed = false
            };

            var result = await _userManager.CreateAsync(user, randomPassword);

            if (result.Succeeded)
            {
                // Add nickname claim if provided
                if (!string.IsNullOrWhiteSpace(nickname))
                {
                    await _userManager.AddClaimAsync(user, new Claim("nickname", nickname));
                }

                // Auto-login the new user
                await _signInManager.SignInAsync(user, isPersistent: false);
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