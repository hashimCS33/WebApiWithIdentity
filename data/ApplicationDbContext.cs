using System;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using WebApiWithIdentity.Models;

namespace WebApiWithIdentity.data;

public class ApplicationDbContext : IdentityDbContext <ApplicationUser, ApplicationRole, string>
{
    public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
        : base(options)
    {

    }


    protected override void OnModelCreating(ModelBuilder builder)
    {
         base.OnModelCreating(builder);

         builder.Entity<ApplicationUser>(entity =>
         {
             entity.ToTable(name: "Users");
             entity.Property(e => e.UserName).HasMaxLength(100).IsRequired();
             entity.Property(e => e.Email).HasMaxLength(200).IsRequired();
             entity.Property(e => e.FullName).IsRequired().HasMaxLength(100);
             entity.Property(e => e.Address).HasMaxLength(200).IsRequired();
             entity.Property(e => e.PhoneNumber).HasMaxLength(15);
             
         });

        builder.Entity<ApplicationRole>(entity =>
        {
                entity.ToTable(name: "Roles");
                entity.Property(e => e.Name).HasMaxLength(100).IsRequired();
                entity.Property(e => e.Description).HasMaxLength(200);
        });

        builder.Entity<IdentityUserRole<string>>(entity =>
        {
            entity.ToTable("UserRoles");
        });

        builder.Entity<IdentityUserClaim<string>>(entity =>
        {
            entity.ToTable("UserClaims");
        });

        builder.Entity<IdentityUserLogin<string>>(entity =>
        {
            entity.ToTable("UserLogins");
        });

        builder.Entity<IdentityRoleClaim<string>>(entity =>
        {
            entity.ToTable("RoleClaims");
        });

        builder.Entity<IdentityUserToken<string>>(entity =>
        {
            entity.ToTable("UserTokens");
        });
       
    }
}
