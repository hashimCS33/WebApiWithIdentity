using System;

namespace WebApiWithIdentity.DTOs.ExternalLoginDtos;

public class ExternalLoginResponse
{

    public bool Success {get ; set;} = false;

    public string Message {get; set;} = string.Empty;

    public string UserEmail {get; set; }= string.Empty;

    public string UserId {get ; set; } = string.Empty;

    public bool IsNewUser {get; set;} = false;

    public string UserRole { get ; set;} = string.Empty;




}
