using System;

namespace WebApiWithIdentity.DTOs.ClaimsDTOs;

public class ClaimDto
{
    public string ClaimType {get;set;} = string.Empty;
   public string ClaimValue{get;set;} = string.Empty;
}
