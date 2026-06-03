using System.Diagnostics;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace IdentityService.Services;

public class UserLookupService(UserManager<IdentityUser> userManager) : IUserLookupService
{
    public async Task<IdentityUser?> FindUserByEmailAsync(string email)
    {
        var inputEmail = email?.Trim();
        Debug.WriteLine($"Looking for user with email: '{inputEmail}'");

        var user = await userManager.Users.FirstOrDefaultAsync(u => u.Email == inputEmail && u.EmailConfirmed);
        Debug.WriteLine($"User found: {user != null}");

        if (user == null)
        {
            var normalizedEmail = userManager.NormalizeEmail(inputEmail);
            user = await userManager.Users.FirstOrDefaultAsync(u =>
                u.NormalizedEmail == normalizedEmail && u.EmailConfirmed
            );
            Debug.WriteLine($"User found by normalized email: {user != null}");

            if (user == null)
            {
                user = await userManager.Users.FirstOrDefaultAsync(u =>
                    u.Email.ToLower() == inputEmail.ToLower() && u.EmailConfirmed
                );
                Debug.WriteLine($"User found by case-insensitive email: {user != null}");
            }
        }

        return user;
    }
}
