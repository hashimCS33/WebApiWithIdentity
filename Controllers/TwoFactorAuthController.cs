using System.Security.Claims;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore.Metadata.Internal;
using Microsoft.EntityFrameworkCore.Query;
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
        private readonly UserManager<ApplicationUser> _userManger;

        private readonly ILogger <TwoFactorAuthController> _logger;

        private static readonly Dictionary<string,string> _tempTokens = new Dictionary<string, string>();

        
      
        public TwoFactorAuthController(UserManager<ApplicationUser> userManger, ILogger<TwoFactorAuthController> logger)
        {
            _userManger = userManger;
            _logger = logger;
        }
          
        [HttpPost]
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

            var user = await _userManger.FindByIdAsync(enable2FARequest.UserId);
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


          var qrCodeUri = $"otpauth://totp/WebApiWithIdentity:{user.Email}?secret = {base64Secret} & issuer = WebApiWithIdentity";
          user.TwoFactorSecret = base64Secret;

          await _userManger.UpdateAsync(user);
          _logger.LogInformation($"2FA secret genrated for user {user.Id}");

          return Ok(new Enable2FAResponse
          {
              Success =true,
              Message = "Scan this QR  code with any authentictor application , then verify",
              QrCodeUri = qrCodeUri,
              SecretKey =base64Secret
          });

        }


     [HttpPost]
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

            var user = await _userManger.FindByIdAsync(verify2FARequest.UserId);
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
            var updateResult = await _userManger.UpdateAsync(user);
            if (!updateResult.Succeeded)
            {
                return BadRequest(new Verify2FAResponse
                {
                    Success = false,
                    Message = "Failed to enabled 2FA"
                });
            }

            var recoveryCodes = await _userManger.GenerateNewTwoFactorRecoveryCodesAsync(user , 6);
            _logger.LogInformation($"2FA enabled for user {user.Id}"); 

            return Ok(new Verify2FAResponse
            {
                Success = true,
                Message = "2FA enabaled succussfully",
                RecoveryCodes = recoveryCodes!.ToList()
            });
        }



    }


}


//endpoints
// 1 . enable 2fa auth -genearte secret key [post]
// 2 . verify code that came from authencator app is vaild or not [post]
// 3 . login - first step (verfiy password and check if 2fa required or not) [post]
// 4 . login & verify -seconed step [post]
// 5 . recovery codes - get recovery codes [the only get endpoint ]
// 6 . login with recovery code 
// 7 . disable 2fa 