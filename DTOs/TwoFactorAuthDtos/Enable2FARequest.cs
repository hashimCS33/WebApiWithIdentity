using System;
using Microsoft.Extensions.Configuration.UserSecrets;

namespace WebApiWithIdentity.DTOs.TwoFactorAuthDtos;

public class Enable2FARequest
{
  public String UserId {get; set;} = String.Empty;

  
}
