using IdentityService.Pages.Login;

namespace IdentityService.Services;

public interface ILoginModelBuilderService
{
    Task<LoginModelData> BuildModelAsync(string? returnUrl);
}

public class LoginModelData
{
    public InputModel Input { get; set; } = default!;
    public QuickRegisterInputModel QuickRegisterInput { get; set; } = default!;
    public ViewModel View { get; set; } = default!;
}
