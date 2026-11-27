using System.Collections.Concurrent;
using System.Data;
using System.Security.Claims;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.Data;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ApiExplorer;
using Microsoft.EntityFrameworkCore.Metadata.Internal;
using Microsoft.EntityFrameworkCore.Query;
using Microsoft.EntityFrameworkCore.Storage.ValueConversion.Internal;
using Microsoft.IdentityModel.Tokens;
using OtpNet;
using WebApiWithIdentity.DTOs.TwoFactorAuthDtos;
using WebApiWithIdentity.Models;

namespace WebApiWithIdentity.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class TwoFactorAuthController : ControllerBase
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;

        private readonly ILogger <TwoFactorAuthController> _logger;

        private static readonly ConcurrentDictionary<string, (string UserId, DateTime ExpiresAt)> _tempTokens = new();

        
      
        public TwoFactorAuthController(UserManager<ApplicationUser> userManger, ILogger<TwoFactorAuthController> logger,
            SignInManager<ApplicationUser> signInManager)
        {
            _userManager = userManger;
            _logger = logger;
            _signInManager = signInManager;
        }
          
        [HttpPost("enable")]  
        public async Task<IActionResult> Enable2FA([FromBody] Enable2FARequest enable2FARequest)
        {
            if (enable2FARequest.UserId == null)
            {
                return BadRequest(new Enable2FAResponse
                {
                    Success = false,
                    Message = "UserID is required",
                });
            }

            var user = await _userManager.FindByIdAsync(enable2FARequest.UserId);
            if (user == null)
            {
                return BadRequest(new Enable2FAResponse
                {
                    Success = false,
                    Message = "there is no users found for this id"
                } );
            }

            if (user.TwoFactorEnabled)
            {
                return BadRequest(new Enable2FAResponse
                {
                    Success=false,
                    Message = "Two Factor Authencation is already Enabled"
                });
            }
          var secret = RandomNumberGenerator.GetBytes(20);
          var base64Secret = Base64UrlEncoder.Encode(secret);
          var base32Secret = Base32Encoding.ToString(secret);


          var qrCodeUri = $"otpauth://totp/WebApiWithIdentity:{user.Email}?secret={base32Secret}&issuer=WebApiWithIdentity";
          user.TwoFactorSecret = base64Secret;


          await _userManager.UpdateAsync(user);
          _logger.LogInformation($"2FA secret genrated for user {user.Id}");

          return Ok(new Enable2FAResponse
          {
              Success =true,
              Message = "Scan this QR  code with any authentictor application , then verify",
              QrCodeUri = qrCodeUri,
              SecretKey =base32Secret

          });

        }


     [HttpPost("verify")]
     public async Task<IActionResult> Verify2FA([FromBody]Verify2FARequest verify2FARequest)
        {
            if (string.IsNullOrEmpty(verify2FARequest.Code) || verify2FARequest.Code.Length != 6)
            {
                return BadRequest(new Verify2FAResponse
                {
                    Success = false,
                    Message = "Invalid Code"
                });
            }

            var user = await _userManager.FindByIdAsync(verify2FARequest.UserId);
            if (user == null)
            {
                return BadRequest(new Verify2FAResponse
                {
                    Success = false,
                    Message = $"there is no users founds for this {verify2FARequest.UserId}"
                });

            }


            if (string.IsNullOrEmpty(user.TwoFactorSecret))
            {
                return BadRequest(new Verify2FAResponse
                {
                    Success = false,
                    Message = "2FA Secret Key not found , please enable 2Fa first"
                });
            }
            var base64Secret = Base64UrlEncoder.DecodeBytes(user.TwoFactorSecret);
            var totp = new Totp(base64Secret);
            var isVaild =totp.VerifyTotp(verify2FARequest.Code , out long timeStepMatched , new VerificationWindow(3,0));
        
            if (!isVaild)
            {
                return BadRequest(new Verify2FAResponse
                {
                    Success= false,
                    Message = "Invalid Code"
                });
            }

            user.TwoFactorEnabled = true;
            var updateResult = await _userManager.UpdateAsync(user);
            if (!updateResult.Succeeded)
            {
                return BadRequest(new Verify2FAResponse
                {
                    Success = false,
                    Message = "Failed to enabled 2FA"
                });
            }

            var recoveryCodes = await _userManager.GenerateNewTwoFactorRecoveryCodesAsync(user , 6);
            _logger.LogInformation($"2FA enabled for user {user.Id}"); 

            return Ok(new Verify2FAResponse
            {
                Success = true,
                Message = "2FA enabaled succussfully",
                RecoveryCodes = recoveryCodes!.ToList()
            });
        }

        [HttpPost("login")]
        public async Task <IActionResult> Login([FromBody] LoginRequest loginRequest)
        {
            if(loginRequest == null)
            {
                return BadRequest(new
                {
                    Succucc = false,
                    Message ="Login data is requrired , validation falied"
                } );
            }
            var user = await _userManager.FindByEmailAsync(loginRequest.Email);
            if(user == null)
            {
                return BadRequest(new
                {
                    Success = false,
                    Message = $"There is no  user founds for this email {loginRequest.Email }"
                });
            }

            var signInResult = await _signInManager.CheckPasswordSignInAsync(user, loginRequest.Password, lockoutOnFailure: true);
            if (!signInResult.Succeeded)
            {
                return BadRequest(new
                {
                    Success = false,
                    Message = " Invalid UserEmail OR Password"
                });
            }

            if(!user.TwoFactorEnabled)
            {
               return Ok(new
               {
                   Success = true,
                   Message = "Login Successfully"
               });
            }

             var tempToken = Guid.NewGuid().ToString("N");
             var now = DateTime.UtcNow;
             foreach (var entry in _tempTokens)
             {
                 if (entry.Value.ExpiresAt <= now)
                     _tempTokens.TryRemove(entry.Key, out _);
             }

             var tempExpiry = now.AddMinutes(5);
             _tempTokens[tempToken] = (user.Id, tempExpiry);

             _logger.LogInformation("2FA login step 1 done seccussfully");

             return Ok(new
             {
                 Succuss = true,
                 Message ="Two Factor Authencation Required",
                 Required2FA = true,
                 tempToken =tempToken,
                 TempTokenExpiry = tempExpiry
             });

            
        }

        [HttpPost("login/verify")]
        public async Task <IActionResult> TwoFactorLoginVerfiy([FromBody] Verify2FARequest verify2FARequest)
        {
           if (string.IsNullOrEmpty(verify2FARequest.TemoToken))
            {
                return BadRequest(new Verify2FAResponse
                {
                    Success = false,
                    Message = "Temp Token is Required"
                });
            } 

            if (string.IsNullOrEmpty(verify2FARequest.Code) || verify2FARequest.Code.Length !=6)
            {
                return BadRequest(new Verify2FAResponse
                {
                    Success = false,
                    Message = "Invalid Code"
                });
            }

            if (!_tempTokens.TryGetValue(verify2FARequest.TemoToken, out var challenge) ||
                challenge.ExpiresAt <= DateTime.UtcNow)
            {
                return BadRequest(new Verify2FAResponse
                {
                    Success = false,
                    Message =" Invalid or Expiry Temp Token "
                });
            }

            var userId = challenge.UserId;
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null || !user.TwoFactorEnabled)
            {
                return BadRequest(new Verify2FAResponse
                {
                    Success = false,
                    Message = $"There is no user founds for this id {userId}"
                });
            }

            if (string.IsNullOrEmpty(user.TwoFactorSecret))
            {
                _tempTokens.TryRemove(verify2FARequest.TemoToken, out _);
                return BadRequest(new Verify2FAResponse
                {
                    Success = false,
                    Message = "2FA scret key not configured"
                });
            }
            var base64Secret = Base64UrlEncoder.DecodeBytes(user.TwoFactorSecret);
            var totp = new Totp(base64Secret);
            var isVaild =totp.VerifyTotp(verify2FARequest.Code , out long timeStepMatched , new VerificationWindow(3,0));
            if(!isVaild)
            {
                return BadRequest(new Verify2FAResponse
                {
                    Success = false,
                    Message= " Invalid Code"
                });
            }

            if (!_tempTokens.TryRemove(verify2FARequest.TemoToken, out var consumedChallenge) ||
                consumedChallenge.ExpiresAt <= DateTime.UtcNow)
            {
                return BadRequest(new Verify2FAResponse
                {
                    Success = false,
                    Message = "Invalid or expired temp token"
                });
            }

            await _signInManager.SignInWithClaimsAsync(user, false, [new Claim("amr", "mfa")]);

            _logger.LogInformation($"Login Successful with 2FA for user {userId}");
            return Ok(new Verify2FAResponse
            {
                Success = true,
                Message = "Login Successful with 2FA", 
            });
        }



        
        [Authorize]
        [HttpGet("recovery-codes")]
        public async Task<IActionResult> GetRecoveryCodes()
        {
            var user = await _userManager.GetUserAsync(User);

            if(user == null)
            {
                return NotFound(new 
                {
                    Success =false,
                    Message ="user not found"
                });
            }

            if(!user.TwoFactorEnabled)
            {
                return BadRequest(new 
                {
                    Success = false,
                    Message ="2Fa is not enabled",
                    Errors = new List<string>{"Recovery codes are only available when 2FA is enabled"}

                });
            }

        //Generate new  coverery codes (in production , you might show existing ones)
        // if they haven't been used . or force regeneration

        var recoveryCodes = await _userManager.GenerateNewTwoFactorRecoveryCodesAsync(user,6);


        _logger.LogInformation("Recovery codes regenerated for user {UserId}", user.Id);
        
        return Ok(new
        {
            Success = true,
            Message = "New recovery codes generated . Save them immediately - they cannot be retreieved",
            RecoverCodes = recoveryCodes
        });

        }

        [HttpPost("login/recovery-code")]
        public async Task<IActionResult> LoginWithRecoveryCode([FromBody] ConsumeRecoveryCodesRequest request)
        {
            if (string.IsNullOrWhiteSpace(request.Code) || string.IsNullOrWhiteSpace(request.TempToken))
            {
                return BadRequest(new ConsumeRecoveryCodesResponse
                {
                    Success = false,
                    Message = "Recovery code and temp token are required"
                });
            }

            if (!_tempTokens.TryRemove(request.TempToken, out var challenge) ||
                challenge.ExpiresAt <= DateTime.UtcNow)
            {
                return BadRequest(new ConsumeRecoveryCodesResponse
                {
                    Success = false,
                    Message = "Invalid or expired temp token"
                });
            }

            var user = await _userManager.FindByIdAsync(challenge.UserId);
            if (user == null || !user.TwoFactorEnabled || await _userManager.IsLockedOutAsync(user))
            {
                return Unauthorized(new ConsumeRecoveryCodesResponse
                {
                    Success = false,
                    Message = "Unable to sign in"
                });
            }

            var result = await _userManager.RedeemTwoFactorRecoveryCodeAsync(user, request.Code.Trim());

            if (!result.Succeeded)
            {
                return BadRequest(new ConsumeRecoveryCodesResponse
                {
                    Success = false,
                    Message = "Invalid or used recovery code"
                });
            }

            await _signInManager.SignInWithClaimsAsync(user, false, [new Claim("amr", "mfa")]);
            _logger.LogInformation("User logged in with recovery code: {UserId}", user.Id);

            return Ok(new ConsumeRecoveryCodesResponse
            {
                Success = true,
                Message = "Login successful with recovery code"
            });
        }

   
    [HttpPost ("{userId}")] 
    public async Task<IActionResult> Disable2FA(string userId)
        {
            if(string.IsNullOrEmpty(userId))
            {
                return BadRequest(new
                {
                    Success =false,
                    Message = "UserId is required"
                });
            }

            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
            {
                return BadRequest(new
                {
                    Success =false,
                    Message = "Invalid User"
                });
            }

            if (!user.TwoFactorEnabled)
            {
                return BadRequest(new
                {
                    Success = false,
                    Message = "2FA is not enabled"
                });
            }
            user.TwoFactorEnabled = false;
            user.TwoFactorSecret = "";

            var result = await _userManager.UpdateAsync(user);
            if(!result.Succeeded)
            {
                return BadRequest(new 
                {
                    Success = false,
                    Message = "Failed to disable 2FA"
                });
            }


            _logger.LogInformation($"2FA disabled for this user {userId}");

            return Ok(new
            {
                Success = true,
                Message = "2FA authrentication has been disabled"
            });

            
        }
    
}

}




//endpoints
// 1 . enable 2fa auth -genearte secret key [post] [Done]
// 2 . verify code that came from authencator app is vaild or not [post] [Done]
// 3 . login - first step (verfiy password and check if 2fa required or not) [post][Done]
// 4 . login & verify -seconed step [post][Done]
// 5 . recovery codes - get recovery codes [the only get endpoint ] [Done]
// 6 . login with recovery code [Done]
// 7 . disable 2fa [Done]
