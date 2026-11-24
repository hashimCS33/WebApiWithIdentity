using System;

namespace WebApiWithIdentity.DTOs.TwoFactorAuthDtos;

public class Verify2FARequest
{
    public string UserId {get;set;} =string.Empty;
    public string Code {get; set;} = string.Empty;

    public string TempToken {get; set;} = string.Empty;

}
