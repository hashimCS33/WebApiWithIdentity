using System;

namespace WebApiWithIdentity.DTOs.TwoFactorAuthDtos;

public class ConsumeRecoveryCodesRequest
{
    public string Code {get;set;}= string.Empty;
    public string TempToken { get; set; } = string.Empty;
    

}
