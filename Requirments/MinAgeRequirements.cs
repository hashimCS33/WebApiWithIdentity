using System;
using Microsoft.AspNetCore.Authorization;

namespace WebApiWithIdentity.Requirments;

public class MinAgeRequirements (int minimumAge) : IAuthorizationRequirement
{
   public int MinimumAge  {get;} = minimumAge;
   
}
