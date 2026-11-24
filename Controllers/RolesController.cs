using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using WebApiWithIdentity.DTOs.RolesDtos;
using WebApiWithIdentity.Models;

namespace WebApiWithIdentity.Controllers
{
    [Route("api/[controller]/[action]")]
    [ApiController]
    [Authorize(Roles = "Admin")] // Only allow Admin role to access this controller
    public class RolesController : ControllerBase
    {
        private readonly RoleManager<ApplicationRole> _roleManager;
        private readonly UserManager<ApplicationUser> _userManager;

        public RolesController(RoleManager<ApplicationRole> roleManager, UserManager<ApplicationUser> userManager)
        {
            _roleManager = roleManager;
            _userManager = userManager;
        }

        [HttpGet]
        public async Task<IActionResult> GetAllRoles()
        {
            var roles = _roleManager.Roles.ToList();
            if (roles == null || !roles.Any())
            {
                return NotFound("No roles found.");
            }
            return Ok(roles);
        }
        [HttpGet("{id}")]
        public async Task<IActionResult> GetRoleById(string id)
        {
            var role = await _roleManager.FindByIdAsync(id);
            if (role == null)
            {
                return NotFound("Role not found.");
            }
            return Ok(role);
        }

        [HttpPost]
        [Authorize(Roles = "Admin")] // Only allow Admin role to create roles
       public async Task<IActionResult> CreateRole([FromBody] CreateRoleDto createRoleDto)
        {
            if (createRoleDto == null || string.IsNullOrWhiteSpace(createRoleDto.RoleName))
            {
                return BadRequest("Role name is required.");
            }

            var existingRole = await _roleManager.FindByNameAsync(createRoleDto.RoleName);
            if (existingRole != null)
            {
                return BadRequest("Role already exists.");
            }

            var newRole = new ApplicationRole {
                 Name = createRoleDto.RoleName ,
                 Description = $"Role for {createRoleDto.RoleName}",
                 CreatedAt = DateTime.UtcNow,
                 IsSystemRole = createRoleDto.RoleName.ToLower() == "admin" ? true : false // Example: Mark "admin" role as a system role
                 };
            var result = await _roleManager.CreateAsync(newRole);
            if (!result.Succeeded)
            {
                return BadRequest("Failed to create role.");
            }

            return Ok("Role created successfully.");
        }
       
     [HttpDelete("{id}")]
     [Authorize(Roles = "Admin")] // Only allow Admin role to delete roles
        public async Task<IActionResult> DeleteRole(string id)
        {
            var role = await _roleManager.FindByIdAsync(id);
            if (role == null)
            {
                return NotFound("Role not found.");
            }

            var result = await _roleManager.DeleteAsync(role);
            if (!result.Succeeded)
            {
                return BadRequest("Failed to delete role.");
            }

            return Ok("Role deleted successfully.");
        }

        [HttpPut("{id}")]
        [Authorize(Roles = "Admin")] // Only allow Admin role to update roles
        public async Task<IActionResult> UpdateRole(string id, [FromBody] UpdateRoleDto updateRoleDto)
        {
            var role = await _roleManager.FindByIdAsync(id);
            if (role == null)
            {
                return NotFound("Role not found.");
            }

            role.Name = updateRoleDto.RoleName;
            role.Description = updateRoleDto.Description;

            var result = await _roleManager.UpdateAsync(role);
            if (!result.Succeeded)
            {
                return BadRequest("Failed to update role.");
            }

            return Ok("Role updated successfully.");
        }
     


    }
}
