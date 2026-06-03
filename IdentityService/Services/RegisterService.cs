using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace IdentityService.Services;

public class RegisterService(UserManager<IdentityUser> userManager)
{
    public async Task ConfirmEmailAsync(IdentityUser user)
    {
        user.EmailConfirmed = true;
        await userManager.UpdateAsync(user);
    }

    public async Task CleanupDuplicateUsersAsync(IdentityUser user)
    {
        var duplicateUsers = await userManager.Users
            .Where(u => u.Email == user.Email && u.Id != user.Id && !u.EmailConfirmed)
            .ToListAsync();

        foreach (var duplicateUser in duplicateUsers)
        {
            await userManager.DeleteAsync(duplicateUser);
        }
    }
}
