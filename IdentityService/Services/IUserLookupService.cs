using Microsoft.AspNetCore.Identity;

namespace IdentityService.Services;

public interface IUserLookupService
{
    Task<IdentityUser?> FindUserByEmailAsync(string email);
}
