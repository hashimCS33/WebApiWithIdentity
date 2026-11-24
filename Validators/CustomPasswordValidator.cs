using System;
using Microsoft.AspNetCore.Identity;
using WebApiWithIdentity.Models;

namespace WebApiWithIdentity.Validators;

public class CustomPasswordValidator : IPasswordValidator<ApplicationUser>
{
    public Task<IdentityResult> ValidateAsync(UserManager<ApplicationUser> manager,
     ApplicationUser user, string? password)
    {
        //check if the oasswird contain the user's username
        //ex  usernaem hashim passwrod hashim123 no Erorr would ne inavild
        if (password?.Contains(user.UserName!) == true)
        {
            return Task.FromResult(IdentityResult.Failed(new IdentityError
            {
                Code = "passwordContainsUsername",
                Description = "Password cannot contain the username"
            }));
        }
        //check if the password contain the user's email 
        //ex email "hashim@gmail.com",password "hashhim@gmail.com123! would be inavlid 

        if (password?.Contains(user.Email!) == true)
        {
            return Task.FromResult(IdentityResult.Failed(new IdentityError
            {
                Code = "passwordContainsUserEmail",
                Description = "poaword cannto contain the user email "
            }));
        }
         // check if password contain cmmand patters 
        // ex :123 , abc. qwer

        if (password?.Contains("123") == true || password?.Contains("abc")  == true|| password?.Contains("qwert") == true)
        {
            return Task.FromResult(IdentityResult.Failed(new IdentityError
            {
                Code = "passwordContainsCommandPatterns",
                Description = "poaword cannto contain common patterns "
            }));
        }
        return Task.FromResult(IdentityResult.Success);
    }
}
