using System;

namespace WebApiWithIdentity.DTOs.AccounetDtos;

public class UserLoginDto
{
    public string UserName { get; set; }
    public string UserEmail { get; set; }
    public string Password { get; set; }
}
