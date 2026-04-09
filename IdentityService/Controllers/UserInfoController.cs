using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace IdentityService.Controllers;

[ApiController]
[Route("/api/userinfo")]
// [Authorize(Policy = "user.info.read")]
public class UserInfoController : ControllerBase
{
    private readonly UserManager<IdentityUser> _userManager;

    public UserInfoController(UserManager<IdentityUser> userManager)
    {
        _userManager = userManager;
    }

    [HttpPost("batch")]
    public async Task<ActionResult<IEnumerable<UserInfoResponse>>> GetUserNicknames([FromBody] UserIdsRequest request)
    {
        if (!request.UserIds.Any())
        {
            return BadRequest("User IDs list is required");
        }

        var users = await _userManager.Users
            .Where(u => request.UserIds.Contains(u.Id))
            .ToListAsync();

        var result = new List<UserInfoResponse>();
        
        foreach (var user in users)
        {
            // @todo: remove multicall
            var claims = await _userManager.GetClaimsAsync(user);
            var nicknameClaim = claims.FirstOrDefault(c => c.Type == "nickname");
            
            result.Add(new UserInfoResponse
            {
                UserId = user.Id,
                UserName = user.UserName,
                UserNick = nicknameClaim?.Value ?? user.UserName
            });
        }

        return Ok(result);
    }
}

public class UserIdsRequest
{
    public List<string> UserIds { get; set; } = new();
}

public class UserInfoResponse
{
    public string UserId { get; set; } = string.Empty;
    public string UserName { get; set; } = string.Empty;
    public string UserNick { get; set; } = string.Empty;
}
