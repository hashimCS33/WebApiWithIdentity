using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using WebApiWithIdentity.DTOs;
using WebApiWithIdentity.DTOs.AccounetDtos;
using WebApiWithIdentity.DTOs.AccountDtos;
using WebApiWithIdentity.Models;

namespace WebApiWithIdentity.Controllers
{
    [Route("api/[controller]/[action]")]
    [ApiController]
    public class UsersController : ControllerBase
    {
        private readonly UserManager<ApplicationUser> _userManager;

        private readonly RoleManager<ApplicationRole> _roleManager;
        
        public UsersController(UserManager<ApplicationUser> userManager, RoleManager<ApplicationRole> roleManager)
        {
            _userManager = userManager;
            _roleManager = roleManager;
        }


        [HttpGet]
        public async Task<IActionResult> GetUsers()
        {
            var users = _userManager.Users.ToList();
            if (users == null || !users.Any())
            {
                return NotFound("No users found.");
            }
            return Ok(users);
        }

        [HttpGet("{id}")]
        public async Task<IActionResult> GetUserById(string id)
        {
            var user = await _userManager.FindByIdAsync(id);
            if (user == null)
            {
                return NotFound("User not found.");
            }
            return Ok(user);
        }
      [HttpDelete("{id}")]
        public async Task<IActionResult> DeleteUser(string id)
        {
            var user = await _userManager.FindByIdAsync(id);
            if (user == null)
            {
                return NotFound("User not found.");
            }

            var result = await _userManager.DeleteAsync(user);
            if (!result.Succeeded)
            {
                return BadRequest("Failed to delete user.");
            }

            return Ok("User deleted successfully.");
        }
      [HttpPut("{id}")]
        public async Task<IActionResult> UpdateUser(string id, [FromBody] UpdateUserDto user)
        {
            if (user == null || id != user.Id)
            {
                return BadRequest("Invalid user data.");
            }

            var existingUser = await _userManager.FindByIdAsync(id);
            if (existingUser == null)
            {
                return NotFound("User not found.");
            }
            existingUser.UserName = user.UserName;
            existingUser.Address = user.UserAdress;
            existingUser.PhoneNumber = user.UserPhoneNumber;


            var result = await _userManager.UpdateAsync(existingUser);
            if (!result.Succeeded)
            {
                return BadRequest("Failed to update user.");
            }

            return Ok("User updated successfully.");
        }


       [HttpGet("{userid}/roles")]
        public async Task<IActionResult> GetUserRoles(string userId)
        {
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
            {
                return NotFound("User not found.");
            }

            var roles = await _userManager.GetRolesAsync(user);
            return Ok(roles);
        }

        [HttpPost("{userId}/roles/assign")]
        public async Task<IActionResult> AssignRoleToUser(string userId, [FromBody] AssignRoleDto assignRoleDto)
        {
            if (assignRoleDto == null || string.IsNullOrWhiteSpace(assignRoleDto.RoleName))
            {
                return BadRequest("Role name is required.");
            }

            var roleName = assignRoleDto.RoleName;
        {
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
            {
                return NotFound(new { message = "User not found.", receivedUserId = userId });
            }

            var role = await _roleManager.FindByNameAsync(roleName);
            if (role == null)
            {
                return NotFound("Role not found.");
            }
            if (await _userManager.IsInRoleAsync(user, roleName))
            {
                return BadRequest("User is already assigned to this role.");
            }

            var result = await _userManager.AddToRoleAsync(user, roleName);
            if (!result.Succeeded)
            {
                return BadRequest("Failed to assign role to user.");
            }

            return Ok("Role assigned to user successfully.");
        }

    
    }
    [HttpDelete("{userid}/roles/{roleName}")]
    public async Task<IActionResult> RemoveRoleFromUser(string userId,[FromQuery] string roleName)
    {
        var user = await _userManager.FindByIdAsync(userId);
        if (user == null)
        {
            return NotFound("User not found.");
        }

        var role = await _roleManager.FindByNameAsync(roleName);
        if (role == null)
        {
            return NotFound("Role not found.");
        }

        if (!await _userManager.IsInRoleAsync(user, roleName))
        {
            return BadRequest("User is not assigned to this role.");
        }

        var result = await _userManager.RemoveFromRoleAsync(user, roleName);
        if (!result.Succeeded)
        {
            return BadRequest("Failed to remove role from user.");
        }

        return Ok("Role removed from user successfully.");
    }

    [HttpGet("{userid}/roles/{roleName}")]
    public async Task<IActionResult> GetAllUsersInRole(string roleName)
    {
        var role = await _roleManager.FindByNameAsync(roleName);
        if (role == null)
        {
            return NotFound("Role not found.");
        }

        var usersInRole = await _userManager.GetUsersInRoleAsync(roleName);
        return Ok(usersInRole);
    }


    [HttpGet("{userid}/roles")]
    public async Task<IActionResult> IsUserInRole(string userId,[FromQuery] string roleName)
    {
        var user = await _userManager.FindByIdAsync(userId);
        if (user == null)
        {
            return NotFound("User not found.");
        }

        var role = await _roleManager.FindByNameAsync(roleName);
        if (role == null)
        {
            return NotFound("Role not found.");
        }

        var isInRole = await _userManager.IsInRoleAsync(user, roleName);
        return Ok(isInRole);
    }
}
}
