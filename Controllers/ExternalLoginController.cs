using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using WebApiWithIdentity.DTOs.ExternalLoginDtos;
using WebApiWithIdentity.Models;

namespace WebApiWithIdentity.Controllers
{
    [Route("api/[controller]/[action]")]
    [ApiController]
    public class ExternalLoginController : ControllerBase
    {
        private  readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;

        private readonly ILogger<ExternalLoginController> _logger;

        public ExternalLoginController(SignInManager<ApplicationUser> signInManager, UserManager<ApplicationUser> userManager, ILogger<ExternalLoginController> logger)
        {
            _signInManager = signInManager;
            _userManager = userManager;
            _logger = logger;
        }

        [HttpGet]
        public IActionResult GetProviders()
         {
           var providers = new List<object>
           {
           new{ Name = "Google ",DisplayName = "Continue with Google",Icon = "google"},
           new{ Name = "Facebook ",DisplayName = "Continue with Google",Icon = "google" },
           new{ Name = "Microsoft",DisplayName = "Continue with Google",Icon = "google" }
           };
           return Ok(new 
           {
               Success = true,
               Message= " Supported external login providers. ",
               Data= providers
           });         
         }
         

        [HttpPost]
         public async Task<IActionResult> ExternalLogin([FromBody] ExternalLoginRequest externalLoginRequest)
        {
            if (string.IsNullOrEmpty(externalLoginRequest.Provider))
            {
                return BadRequest(new ExternalLoginResponse
                {
                    Success = false,
                    Message = "External Provider is required"
                });
            }

            if(string.IsNullOrEmpty (externalLoginRequest.ExternalToken))
            {
                return BadRequest(new ExternalLoginResponse
                {
                    Success = false,
                    Message = "External  Token  is required"
                });
            }

            var externalUserInfo = await VaildateExternalTokenAsync(externalLoginRequest.Provider , externalLoginRequest.ExternalToken);

            if(externalUserInfo == null)
            {
                return BadRequest(new ExternalLoginResponse
                {
                    Success =false,
                    Message = "Invalid External Token"
                });
            }

            var email = externalUserInfo.Email;
            var user = await FindUaerByExternalProviderAsync(externalLoginRequest.Provider,externalUserInfo.ProviderKey);
            if (user != null)
            {
               
                return Ok(new ExternalLoginResponse
                {
                    Success = true,
                    Message = "Login Successful",
                    IsNewUser = false,
                    UserId = user.Id,
                    UserEmail = user.Email!,
                    UserRole = string.Join(", ", await _userManager.GetRolesAsync(user)),

                });
            }
            
            var existingUserByEmail = await _userManager.FindByEmailAsync(email);
            if(existingUserByEmail != null)
            {
                var linkResult1 = await _userManager.AddLoginAsync(existingUserByEmail,
                new UserLoginInfo(externalLoginRequest.Provider,externalUserInfo.ProviderKey,externalLoginRequest.Provider));
                if (!linkResult1.Succeeded)
                {
                    return BadRequest(new ExternalLoginResponse
                    {
                        Success = false,
                        Message = "Colud not able to link external provider login "
                    });
                }
                return Ok(new ExternalLoginResponse
                {
                    Success = true,
                    Message = "Login Successful with external account linked",
                    IsNewUser = false,
                    UserEmail = existingUserByEmail.Email ?? string.Empty,
                    UserId = existingUserByEmail.Id,
                    UserRole = string.Join(", ", await _userManager.GetRolesAsync(existingUserByEmail)),
                });
            }
        
            var NewUser= new ApplicationUser
            {
                UserName = email,
                Email = email ,
                EmailConfirmed = true,
                FullName = externalUserInfo.FullName,
            };

            var createResult = await _userManager.CreateAsync(NewUser,Guid.NewGuid().ToString());
            if(!createResult.Succeeded)
            {
                return BadRequest(new ExternalLoginResponse
                {
                    Success = false,
                    Message = "Failed to create user"
                });
            }

            var linkResult = await _userManager.AddLoginAsync(NewUser,
            new UserLoginInfo(externalLoginRequest.Provider,externalUserInfo.ProviderKey,externalLoginRequest.Provider));
            if (!linkResult.Succeeded)
            {
                return BadRequest(new ExternalLoginResponse
                {
                    Success = false,
                    Message = "Failed to link with external login"
                });
            }

            await _userManager.AddToRoleAsync(NewUser,"User");
            var role = await _userManager.GetRolesAsync(NewUser);
            return Ok(new ExternalLoginResponse
            {
                Success = true,
                Message = "Account created and Login Successfully",
                IsNewUser = true,
                UserEmail = NewUser.Email ?? string.Empty,
                UserId = NewUser.Id,
                UserRole = string.Join(", ", role)
                
            });

        }

        [HttpPost]
        public async Task<IActionResult> LinkExternalLogin([FromBody] LinkExternalLoginRequest request)
        {
            if (string.IsNullOrEmpty(request.Provider) || string.IsNullOrEmpty(request.ExternalToken))
            {
                return BadRequest(new LinkExternalLoginResponse
                {
                    Success = false,
                    Message = "Provider and external token are required"
                    
                });
            }

            var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            var user = userId == null ? null : await _userManager.FindByIdAsync(userId);

            if (user == null)
            {
                return Unauthorized( new LinkExternalLoginResponse
                {
                    Success = false,
                    Message = "User not authenticted you are  not loging , plaease login in first and try again"
                } );
            }

            /// Cheack if this external login is already  linked to ANOTHER user 
       
            var externalUserInfo = await VaildateExternalTokenAsync(request.Provider, request.ExternalToken);
            if (externalUserInfo == null)
            {
                return BadRequest(new LinkExternalLoginResponse
                {
                    Success = false,
                    Message = "Invalid external token"
                });
            }

            var existingUser = await FindUaerByExternalProviderAsync(request.Provider, externalUserInfo.ProviderKey);
            if (existingUser !=null && existingUser.Id != userId)
            {
                return BadRequest(new LinkExternalLoginResponse
                {
                   Success = false,
                   Message= "This external account is already linked to aother user "
                    
                });
            }
            // check if already linked to this user
            if (existingUser != null)
            {
                return Ok(new ExternalLoginResponse
                {
                    Success = true,
                    Message = "This exteanl account is already linked to account"
                });
            }
            
            //Link the ecternal provider
            var result = await _userManager.AddLoginAsync(user ,
            new UserLoginInfo(request.Provider , externalUserInfo.ProviderKey, request.Provider));
            if(! result.Succeeded)
            {
                return BadRequest(new LinkExternalLoginResponse
                {
                    Success = false,
                    Message= "Failed to link external account"   
                });
            }

            _logger.LogInformation("External account {Provider} linked to user {UserId}",request.Provider,userId);


            return Ok(new ExternalLoginResponse
            {
                Success = true,
                Message = $"Your {request.Provider} account has beem linked"
            });

        }



    public async Task<IActionResult> unLinkExternalLogin([FromQuery] string provider )
        {
            if (string.IsNullOrEmpty(provider))
            {
                return BadRequest(new ExternalLoginResponse
                {
                    Success = false,
                    Message = "Provider"
                });
            }

            var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            var user = userId == null ? null : await _userManager.FindByIdAsync(userId);


            if (user == null)
            {
                return Unauthorized(new ExternalLoginResponse
                {
                    Success = false,
                    Message = "User not authenticated"
                });
            }

            // get the user's external logins
            var logins = await _userManager.GetLoginsAsync(user);
            var externalLogin = logins.FirstOrDefault(l => l.LoginProvider == provider);

            if(externalLogin == null)
            {
                return BadRequest(new ExternalLoginResponse
                {
                    Success = false,
                    Message = $"No {provider} accounet is linked to this user"
                });
            }

            // cannot unlink the last login method (user would  be locked out)

            var hasPassword  = await _userManager.HasPasswordAsync(user);
            if(!hasPassword && logins.Count <=1)
            {
                return BadRequest(new ExternalLoginResponse
                {
                    Success = false,
                    Message = "Cannot unlink the last login method Add a password or another  external accounet "
                    
                });
            }

            //Remove the external login


            var  result = await _userManager.RemoveLoginAsync(user , provider , externalLogin.ProviderKey);
            if(!result.Succeeded)
            {
                var errors = result.Errors.Select(e =>  e.Description).ToList();
                return BadRequest(new ExternalLoginResponse
                {
                    Success = false,
                    Message = " "
                });
            }



           _logger.LogInformation("External accounet {Provider} unlinked from user {UserId}",provider , userId);

           return Ok(new ExternalLoginResponse
           {
               Success = true,
               Message = $"Your {provider} accounet  has been unlinked"
           });


        } 

        private async Task<ExternalUserInfo?> VaildateExternalTokenAsync(string provider,string token)
        {
            await Task.Delay(10);

            if(string.IsNullOrEmpty(token))
            {
                return null;
            }
            var providerKey =$"{provider} _ {Guid.NewGuid().ToString("N")}";
            return new ExternalUserInfo
            {
                 ProviderKey = providerKey,
                 Email = $"user_{provider.ToLower()}@example.com",
                 FullName = $"Mock User from {provider}" 
            };
        }

        private Task<ApplicationUser?> FindUaerByExternalProviderAsync(string provider, string providerKey)
        {
            return _userManager.FindByLoginAsync(provider, providerKey);
        }


          
    }
}
public class ExternalUserInfo
{
    public string ProviderKey { get; set;} = string.Empty;

    public string Email {get ; set; } = string.Empty;

    public string FullName {get; set;}= string.Empty;


}



// Endpoints:

// 1. ExternalLogin [Done]

// 2. LinlExternalLogin [Done]

// 3. UnLinkExternalLogin [Done]

// 4. Providers [Done]


