using System.ComponentModel.DataAnnotations;

namespace IdentityService.Pages.Login;

public class QuickRegisterInputModel
{
    [Required(ErrorMessage = "A név megadása kötelező")]
    [Display(Name = "Név")]
    public string? Name { get; set; }

    [EmailAddress(ErrorMessage = "Érvénytelen e-mail cím")]
    [Display(Name = "E-mail (opcionális)")]
    public string? Email { get; set; }

    [Display(Name = "Becenév")]
    public string? Nickname { get; set; }

    public string? ReturnUrl { get; set; }
    public string? Button { get; set; }
}
