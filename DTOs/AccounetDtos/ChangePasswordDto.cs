
using System;

namespace WebApiWithIdentity.DTOs.AccounetDtos;

public class ChangePasswordDto
{
    public string OldPassword { get; set; }
    public string NewPassword { get; set; }
}
