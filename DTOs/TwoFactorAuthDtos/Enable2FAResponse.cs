using System;

namespace WebApiWithIdentity.DTOs.TwoFactorAuthDtos;

public class Enable2FAResponse
{
    public bool Success {get ; set;} = false;

    public string Message  {get ; set; } = String.Empty;

    public string SecretKey {get; set;} =String.Empty;

    public string QrCodeUri {get; set;} = string.Empty;


    
   
}
