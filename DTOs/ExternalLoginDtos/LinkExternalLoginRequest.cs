using System;

namespace WebApiWithIdentity.DTOs.ExternalLoginDtos;

public class LinkExternalLoginRequest
{

    public string Provider {get; set;} = string.Empty;

    public string ExternalToken {get; set;} = string.Empty;

}
