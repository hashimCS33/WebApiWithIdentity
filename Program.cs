using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using WebApiWithIdentity.data;
using WebApiWithIdentity.Models;
using WebApiWithIdentity.Requirments;
using WebApiWithIdentity.Validators;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
// Learn more about configuring OpenAPI at https://aka.ms/aspnet/openapi
builder.Services.AddOpenApi();
builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection")));


//Configure Identity Services
builder.Services.AddIdentity<ApplicationUser, ApplicationRole>(
 options =>
 {
    //password settings
     options.Password.RequireDigit = true;// Requires at least one digit (0-9) in the password
     options.Password.RequireLowercase = true;// Requires at least one lowercase letter (a-z) in the password
     options.Password.RequireUppercase = true;// Requires at least one uppercase letter (A-Z) in the password
     options.Password.RequireNonAlphanumeric = true;// Requires at least one non-alphanumeric character (e.g., !, @, #, etc.) in the password
     options.Password.RequiredLength = 10;
     options.Password.RequiredUniqueChars =3;
     //lockout settings
      options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(5);
      options.Lockout.MaxFailedAccessAttempts = 5;
      options.Lockout.AllowedForNewUsers = true;

     //user settings
     options.User.AllowedUserNameCharacters =
      "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._@+";
     options.User.RequireUniqueEmail = true;

     //sign in settings
     options.SignIn.RequireConfirmedEmail = false;
     options.SignIn.RequireConfirmedPhoneNumber = false;
     options.SignIn.RequireConfirmedAccount = false;
       
 }
).AddEntityFrameworkStores<ApplicationDbContext>()
.AddDefaultTokenProviders().AddPasswordValidator<CustomPasswordValidator>();
  
  //Cofigure Coolkies
  builder.Services.ConfigureApplicationCookie(options =>
  {
    options.Cookie.HttpOnly = true;
    options.ExpireTimeSpan = TimeSpan.FromMinutes(5);
    options.LoginPath = "/Account/Login";
    options.AccessDeniedPath = "/Account/AccessDenied";
    options.SlidingExpiration = true;
  });  

  builder.Services.AddAuthorization(options =>
{

    options.AddPolicy("AdultContent",
    policy => policy.AddRequirements(new MinAgeRequirements(18)));

    // Require a specific claim with a specific value
    options.AddPolicy("CanEditPosts", policy =>
        policy.RequireClaim("permission", "can_edit_posts"));

    // Require ANY of multiple values
    options.AddPolicy("CanManageContent", policy =>
        policy.RequireClaim("permission", "can_edit_posts", "can_delete_posts", "can_publish_posts"));

    // Require a claim to exist (any value)
    options.AddPolicy("HasTenant", policy =>
        policy.RequireClaim("tenant_id"));

    // Require a claim with a value matching a regex
    options.AddPolicy("ClearanceLevel", policy =>
        policy.RequireClaim("clearance", "high", "critical"));

    // Combine multiple requirements (AND logic)
    options.AddPolicy("AdminInTenant", policy =>
        policy.RequireClaim( "Admin")
              .RequireClaim("tenant_id"));
});
  
  


var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
    
}

app.UseHttpsRedirection();

//Add Authentication and Authorization middleware
app.UseAuthentication();

app.UseAuthorization();

app.MapControllers();


app.Run();

