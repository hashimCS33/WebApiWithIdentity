using System;
using System.ComponentModel.DataAnnotations;

namespace WebApiWithIdentity.DTOs;

public class UserRegisterDto 
{

    [Required(ErrorMessage = "Username is required.")]
    [MaxLength(50, ErrorMessage = "Username cannot exceed 50 characters.")]
    public string UserName { get; set; } = string.Empty;
    [Required(ErrorMessage = "Email is required.")]
    [EmailAddress(ErrorMessage = "Invalid email address.")]
    public string Email { get; set; } = string.Empty;
    [Required(ErrorMessage = "Full name is required.")]
    public string FullName { get; set; } = string.Empty;
    public string Address { get; set; } = string.Empty;
    [Phone(ErrorMessage = "Invalid phone number.")]
    public string PhoneNumber { get; set; } = string.Empty;
    [Required(ErrorMessage = "Password is required.")]
    [MinLength(6, ErrorMessage = "Password must be at least 6 characters long.")]
    public string Password { get; set; } = string.Empty;
}
