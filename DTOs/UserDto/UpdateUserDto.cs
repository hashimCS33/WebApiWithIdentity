using System;

namespace WebApiWithIdentity.DTOs;

public class UpdateUserDto
{
    public string Id { get; set; }
    public string Email { get; set; }
    public string UserName { get; set; }
    public string UserAdress { get; set; }
   
    public string UserPhoneNumber { get; set; }
    
}
