using System;

namespace WebApiWithIdentity.DTOs.TwoFactorAuthDtos;

public class ConsumeRecoveryCodesRequest
{
    public string Code {get;set;}= string.Empty;
    

}
