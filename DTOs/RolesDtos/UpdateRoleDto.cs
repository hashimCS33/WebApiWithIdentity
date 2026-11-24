using System;

namespace WebApiWithIdentity.DTOs.RolesDtos;

public class UpdateRoleDto
{
   public string RoleName { get; set; } = string.Empty;
   public string Description { get; set; } = string.Empty;
   
}
