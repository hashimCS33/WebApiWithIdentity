using System;

namespace WebApiWithIdentity.DTOs.TwoFactorAuthDtos;

public class ConsumeRecoveryCodesResponse
{
    public bool Success {get ; set;} = false;

    public string Message {get;set;} = string.Empty;

    public string Token {get; set;} =string.Empty;
}
