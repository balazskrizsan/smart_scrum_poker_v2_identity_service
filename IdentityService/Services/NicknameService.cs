using IdentityService.Database;
using Microsoft.AspNetCore.Identity;

namespace IdentityService.Services;

public class NicknameService(ApplicationDbContext dbContext, UserManager<IdentityUser> userManager) : INicknameService
{
    public string? GetNickname(string username)
    {
        var user = userManager.FindByNameAsync(username).Result;
        if (user == null)
        {
            return null;
        }

        var claim = dbContext.UserClaims
            .FirstOrDefault(c => c.UserId == user.Id && c.ClaimType == "nickname");
        return claim?.ClaimValue;
    }
}
