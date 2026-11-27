using System;

namespace WebApiWithIdentity.DTOs.ExternalLoginDtos;

public class LinkExternalLoginResponse
{
    public bool Success {get; set;} = false;

    public string Message {get; set;} = string.Empty;

    
}
