using System;

namespace WebApiWithIdentity.DTOs.TwoFactorAuthDtos;

public class RecoveryCodesResponse
{
  public List<string> codes {get;set;}= [];

  public string Message {get;set;} = "Save These Codes in save place,for you recovery";

  
}
