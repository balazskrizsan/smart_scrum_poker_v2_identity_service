using System.ComponentModel.DataAnnotations;
using System.Net.Mail;
using IdentityService.Pages.Login;
using Microsoft.AspNetCore.Mvc.ModelBinding;

namespace IdentityService.Services;

public class UserInputValidationService
{
    public ValidationResult ValidateLocalAccountInput(InputModel input, ModelStateDictionary modelState)
    {
        var result = new ValidationResult();

        // Clear only local account related validation errors
        modelState.Remove(nameof(InputModel.Email));
        modelState.Remove(nameof(InputModel.Password));

        // Validate required fields
        if (string.IsNullOrWhiteSpace(input.Email))
        {
            modelState.AddModelError(nameof(InputModel.Email), "Email is required");
            result.IsValid = false;
        }

        if (string.IsNullOrWhiteSpace(input.Password))
        {
            modelState.AddModelError(nameof(InputModel.Password), "Password is required");
            result.IsValid = false;
        }

        // Validate email format
        if (!string.IsNullOrWhiteSpace(input.Email))
        {
            var emailAttribute = new EmailAddressAttribute();
            if (!emailAttribute.IsValid(input.Email))
            {
                modelState.AddModelError(nameof(InputModel.Email), "Invalid email format");
                result.IsValid = false;
            }
        }

        // Validate password length (minimum 6 characters)
        if (!string.IsNullOrWhiteSpace(input.Password) && input.Password.Length < 6)
        {
            modelState.AddModelError(nameof(InputModel.Password), "Password must be at least 6 characters long");
            result.IsValid = false;
        }

        return result;
    }

    public ValidationResult ValidateQuickRegisterInput(QuickRegisterInputModel input, ModelStateDictionary modelState)
    {
        var result = new ValidationResult();

        // Clear only quick register related validation errors
        modelState.Remove(nameof(QuickRegisterInputModel.Name));
        modelState.Remove(nameof(QuickRegisterInputModel.Email));
        modelState.Remove(nameof(QuickRegisterInputModel.Nickname));

        // Validate required name field
        if (string.IsNullOrWhiteSpace(input.Name))
        {
            modelState.AddModelError(nameof(QuickRegisterInputModel.Name), "A név megadása kötelező");
            result.IsValid = false;
        }

        // Validate email format if provided
        if (!string.IsNullOrWhiteSpace(input.Email))
        {
            var emailAttribute = new EmailAddressAttribute();
            if (!emailAttribute.IsValid(input.Email))
            {
                modelState.AddModelError(nameof(QuickRegisterInputModel.Email), "Invalid e-mail address");
                result.IsValid = false;
            }
        }

        // Validate nickname length if provided (max 50 characters)
        if (!string.IsNullOrWhiteSpace(input.Nickname) && input.Nickname.Length > 50)
        {
            modelState.AddModelError(nameof(QuickRegisterInputModel.Nickname), "Nickname cannot be longer than 50 characters");
            result.IsValid = false;
        }

        // Validate name length (max 100 characters)
        if (!string.IsNullOrWhiteSpace(input.Name) && input.Name.Length > 100)
        {
            modelState.AddModelError(nameof(QuickRegisterInputModel.Name), "Name cannot be longer than 100 characters");
            result.IsValid = false;
        }

        return result;
    }

    public static bool IsValidEmail(string email)
    {
        if (string.IsNullOrWhiteSpace(email))
        {
            return false;
        }

        try
        {
            var addr = new MailAddress(email);

            return addr.Address == email;
        }
        catch
        {
            return false;
        }
    }
}

public class ValidationResult
{
    public bool IsValid { get; set; } = true;
    public List<string> Errors { get; set; } = new List<string>();
}
