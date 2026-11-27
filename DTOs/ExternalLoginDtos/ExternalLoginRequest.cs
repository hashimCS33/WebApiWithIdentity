using System;

namespace WebApiWithIdentity.DTOs.ExternalLoginDtos;

public class ExternalLoginRequest
{
  
  public string Provider {get; set;} = string.Empty;

  public string ExternalToken {get; set;} = string.Empty;

  public string UserEmail {get; set;} = string.Empty;

}
