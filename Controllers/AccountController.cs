using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using WebApiWithIdentity.DTOs;
using WebApiWithIdentity.DTOs.AccounetDtos;
using WebApiWithIdentity.Models;

namespace WebApiWithIdentity.Controllers
{
    [Route("api/[controller]/[action]")]
    [ApiController]
    public class AccountController : ControllerBase
    {
        private readonly UserManager<ApplicationUser> _userManager;

        private readonly SignInManager<ApplicationUser> _signInManager;

        private readonly RoleManager<ApplicationRole> _roleManager;


        public AccountController(UserManager<ApplicationUser> userManager, SignInManager<ApplicationUser> signInManager, RoleManager<ApplicationRole> roleManager)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _roleManager = roleManager;
        }


        [HttpPost]
        [Authorize(Policy = "AdultContent")]
        public async Task<IActionResult> Register([FromBody] UserRegisterDto userRegisterDto)
        {
            try
            {
                if (userRegisterDto == null)
                {
                    return BadRequest("User registration data is required.");
                }
                if (!ModelState.IsValid)
                {
                    return BadRequest(ModelState);
                }

                var existingUser = await _userManager.FindByNameAsync(userRegisterDto.UserName);
                if (existingUser != null)
                {
                    return BadRequest("Username already exists.");
                }

                var existingEmail = await _userManager.FindByEmailAsync(userRegisterDto.Email);
                if (existingEmail != null)
                {
                    return BadRequest("Email already exists.");
                }

                var newUser = new ApplicationUser
                {
                    UserName = userRegisterDto.UserName,
                    Email = userRegisterDto.Email,
                    FullName = userRegisterDto.FullName,
                    Address = userRegisterDto.Address,
                    PhoneNumber = userRegisterDto.PhoneNumber,
                    PasswordHash = _userManager.PasswordHasher.HashPassword(null, userRegisterDto.Password),
                    EmailConfirmed = false, // Set to true if you want to skip email confirmation
                    PhoneNumberConfirmed = false, // Set to true if you want to skip phone number confirmation
                    TwoFactorEnabled = false, // Set to true if you want to enable two-factor authentication
                    LockoutEnabled = false, // Set to true if you want to enable account lockout
                };

                var result = await _userManager.CreateAsync(newUser);
                if (!result.Succeeded)
                {
                    return BadRequest(result.Errors);
                }

                var defaultClaims = new List<System.Security.Claims.Claim>
                {
                    new ("Department","General"),
                    new("subscriptionTier","Free"),
                    new("CreatedAt",DateTime.UtcNow.ToString("0")),
                    new("lastLogin",DateTime.UtcNow.ToString("0")),
                    new("IsActive","true"),
                    new("userId",newUser.Id),
                    new("UserName",newUser.UserName),
                    new("UserRole",_userManager.GetRolesAsync(newUser).Result.FirstOrDefault() ?? "None"),
                };
                await _userManager.AddClaimsAsync(newUser,defaultClaims);

                await _userManager.AddToRoleAsync(newUser,"User");

                await _signInManager.SignInAsync(newUser, isPersistent: false);

                var claims = await _userManager.GetClaimsAsync(newUser);
                return Ok(new {Meeaseg = "User registered successfully.",claims =claims});

            }
            catch (Exception ex)
            {
                return StatusCode(StatusCodes.Status500InternalServerError, $"An error occurred while registering the user: {ex.Message}");
            }

        }

        [HttpPost]
        public async Task<IActionResult> Login([FromForm] UserLoginDto userLoginDto)
        {
            if (userLoginDto == null)
                return BadRequest("User login data is required.");
             

            //check if the user exists by email 
            var user = await _userManager.FindByEmailAsync(userLoginDto.UserEmail);
            if (user == null)
                return Unauthorized("User not found with the provided email.");

            //check password 
            var checkPasswordResult = await _userManager.CheckPasswordAsync(user, userLoginDto.Password);
            if (!checkPasswordResult)
                return Unauthorized("Invalid email or password.");

            var result = await _signInManager.CheckPasswordSignInAsync(
                user, userLoginDto.Password, lockoutOnFailure: true);

            if (!result.Succeeded)
                return Unauthorized("Failed to sign in.");

            //4 . create a new instance of ApplicationUser with the same properties as the existing user


            await _signInManager.SignInAsync(new ApplicationUser
            {
                UserName = user.UserName,
                Email = user.Email,
                FullName = user.FullName,
                Address = user.Address,
                PhoneNumber = user.PhoneNumber,
                PasswordHash = user.PasswordHash,
                EmailConfirmed = user.EmailConfirmed,
                PhoneNumberConfirmed = user.PhoneNumberConfirmed,
                TwoFactorEnabled = user.TwoFactorEnabled,
            }
             
            , isPersistent: false);
            return Ok("User logged in successfully.");
        }

        [HttpPost("logout")]

        public async Task<IActionResult> Logout()
        {
            try
            {
                var user = User.Identity?.Name;
                await _signInManager.SignOutAsync();
                return Ok("User logged out successfully.");
            }
            catch (Exception ex)
            {
                return StatusCode(StatusCodes.Status500InternalServerError, $"An error occurred while logging out the user: {ex.Message}");
            }
        }

        [HttpPut ("{id}/change-password")]

        public async Task<IActionResult> changePassword([FromRoute] string id,[FromBody] ChangePasswordDto changePasswordDto)
        {
            var user = await _userManager.FindByIdAsync(id);
            if (user == null)
            {
                return NotFound("User not found.");
            }
     


            //Remove the old password and set the new password

            var removePasswordResult = await _userManager.RemovePasswordAsync(user);
            if (!removePasswordResult.Succeeded)
            {
                return BadRequest("Failed to remove the old password.");
            }

            var addREsult = await _userManager.AddPasswordAsync(user, changePasswordDto.NewPassword);
            if (!addREsult.Succeeded)
            {
                return BadRequest("Failed to set the new password.");
            }

            return Ok("Password changed successfully.");


        }
        [HttpGet("{userId}")]
        [Authorize(Roles = "Admin")]
        public async Task<IActionResult> LockoutStatus(String id)
        {
            if(id == null)
              return BadRequest("id must  has a value");
            
           var user = await _userManager.FindByIdAsync(id);
            if (user == null)
            {
                return NotFound("User not found.");
            }
            var isLockOut = await _userManager.IsLockedOutAsync(user);
            var LockoutEnabled = await _userManager.GetLockoutEnabledAsync(user);
            var accessFaildedCount = await _userManager.GetAccessFailedCountAsync(user);
            var lockoutEnd= user.LockoutEnd;

            TimeSpan? remainingLockout = null;
            if(isLockOut && lockoutEnd.HasValue)
            {
                remainingLockout = lockoutEnd.Value - DateTime.UtcNow;
                if(remainingLockout.Value.TotalSeconds <0)
                remainingLockout = TimeSpan.Zero;
            }

            return Ok(new
            {
               IsLockOut = isLockOut,
               LockOutEnabled = LockoutEnabled,
               AccessFaliedCoutn = accessFaildedCount,
               LockOutEnd = lockoutEnd,
               RemainigLockOut =  remainingLockout
            });


        }
        // lock user account
        [HttpPost ("{id}/lock")]
        [Authorize(Roles = "Admin")]
        public async Task<IActionResult> LockUserAccount([FromRoute] string id)
        {
            if(id == null)
              return BadRequest("id must  has a value");

            var user = await _userManager.FindByIdAsync(id);
            if (user == null)
            {
                return NotFound("User not found.");
            }

           
          
            await _userManager.ResetAccessFailedCountAsync(user);
            var result = await _userManager.SetLockoutEndDateAsync(user, null);

            if (!result.Succeeded)
            {
                return BadRequest("Failed to lock the user account.");
            }

            return Ok("User account locked successfully.");
        }

        [HttpPost("{id}/unlock")]
        [Authorize(Roles = "Admin")]
        public async Task<IActionResult> UnlockUserAccount([FromRoute] string id)
        {
            var user = await _userManager.FindByIdAsync(id);
            if (user == null)
            {
                return NotFound("User not found.");
            }

            var result = await _userManager.SetLockoutEndDateAsync(user, null);

            if (!result.Succeeded)
            {
                return BadRequest("Failed to unlock the user account.");
            }

            return Ok("User account unlocked successfully.");
        }

    }
}
