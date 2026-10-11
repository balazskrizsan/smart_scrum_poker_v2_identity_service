namespace IdentityService.Services;

public interface INicknameService
{
    string? GetNickname(string userId);
}
