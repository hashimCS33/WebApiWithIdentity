using System;
using Microsoft.AspNetCore.Identity;

namespace WebApiWithIdentity.Models;

public class ApplicationRole : IdentityRole
 
{
    public String Description { get; set; } = string.Empty;

    public DateTime CreatedAt { get; set; } = DateTime.Now;

    public bool IsSystemRole { get; set; } = false;
   
    
}
