using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using WebApiWithIdentity.DTOs.ClaimsDTOs;
using WebApiWithIdentity.Models;

namespace WebApiWithIdentity.Controllers
{
    [Route("api/[controller]/[action]")]
    [ApiController]
    public class UsersClaimsController : ControllerBase
    {
        private readonly UserManager<ApplicationUser> _userManager;


        public UsersClaimsController(UserManager<ApplicationUser> userManager)
        {
            _userManager = userManager;   
        }       
         
       [HttpGet ("{userId}")]
       public async Task<IActionResult> GetUserClaims(string userId)
        {
            var user = await _userManager.FindByEmailAsync(userId);
            if (user == null )
            {
                return NotFound(new {Message = "User not found"});
            }
            var clamis = await _userManager.GetClaimsAsync(user);
            if (clamis == null)
            {
                return NotFound(new {Message = "No clamis found the user "});
            }
            return Ok(clamis);
        }

        [HttpPost ("{userId}")]
        public async Task<IActionResult> AddUserClaim(String userId,[FromBody] ClaimDto addClaimDto)
        {
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null )
            {
                return NotFound(new {Message = "User not found"});
            }
            var exisitingsClaims = await _userManager.GetClaimsAsync(user);
            if (!exisitingsClaims.Any(c => c.Type == addClaimDto.ClaimType && c.Value == addClaimDto.ClaimValue))
            {
                return BadRequest(new {message ="Claim already exists for the user "});
            }

            var newClaim = new System.Security.Claims.Claim(addClaimDto.ClaimType,addClaimDto.ClaimValue);
          
            var result = await _userManager.AddClaimAsync(user,newClaim);
            if (!result.Succeeded)
            {
                return BadRequest(new {message = "Error adding claim",Errors = result.Errors});

            }
            return Ok(new {Message = "Claim added Successfully"});
            
        }

       [HttpDelete("{userId}")]
       public async Task<IActionResult> RemoveUserClaim(string userId,[FromBody] ClaimDto RemoveClaimDto)
        {
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null )
            {
                return NotFound(new {Message = "User not found"});
            }
            var existingClaims = await _userManager.GetClaimsAsync(user);
            if(existingClaims == null)
            {
                return NotFound(new {message = "No claims found for the user"});

            }
            
            if (!existingClaims.Any(c => c.Type == RemoveClaimDto.ClaimType && c.Value == RemoveClaimDto.ClaimValue))
            {
                return NotFound(new {message ="Claim not found for the user "});
            }

            var claimToRemove = new System.Security.Claims.Claim(RemoveClaimDto.ClaimType,RemoveClaimDto.ClaimValue);
            var result = await _userManager.RemoveClaimAsync(user,claimToRemove);
            if (!result.Succeeded)
            {
                return BadRequest(new {message = "Error removing claim",Errors = result.Errors});

            }
            return Ok(new {Message = "Claim removed Successfully"});
        }
       [HttpPut ("{userId}")]
       public async Task<IActionResult> UpdateUserClaim(string userId ,[FromBody] ClaimDto updateClaimDto)
        {
            var user = await _userManager.FindByIdAsync(userId);
            if(user == null)
            {
                return NotFound(new {message = "User not found"});
            }

            var existingClaims = await _userManager.GetClaimsAsync(user);
            if(existingClaims == null)
            {
                return NotFound(new { message = "No claims found  for the user "});
            }
            if(!existingClaims.Any(c =>c.Type == updateClaimDto.ClaimType && c.Value == updateClaimDto.ClaimValue))
            {
                return NotFound(new {message = "Claim  not found for the user"});

            }
            var oldClaim = existingClaims.FirstOrDefault(c => c.Type == updateClaimDto.ClaimType );
            var newClaim = new System.Security.Claims.Claim(updateClaimDto.ClaimType,updateClaimDto.ClaimValue);
            var result = await _userManager.ReplaceClaimAsync(user,oldClaim!,newClaim);
            if (!result.Succeeded)
            {
                return BadRequest(new {message = "Error updating claim",Errors = result.Errors});

            }
            return Ok(new {Message ="Claim updated successfully"});
        }

    }
}
