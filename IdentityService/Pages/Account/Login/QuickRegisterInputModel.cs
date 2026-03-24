using System.ComponentModel.DataAnnotations;

namespace IdentityService.Pages.Login;

public class QuickRegisterInputModel
{
    [Required(ErrorMessage = "A név megadása kötelező")]
    [Display(Name = "Név")]
    public string? Name { get; set; }

    [EmailAddress(ErrorMessage = "Invalid e-mail address")]
    [Display(Name = "E-mail (optional)")]
    public string? Email { get; set; }

    [Display(Name = "Nick")]
    public string? Nickname { get; set; }

    public string? ReturnUrl { get; set; }
    public string? Button { get; set; }
}
