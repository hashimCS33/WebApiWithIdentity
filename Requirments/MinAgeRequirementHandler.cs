using System;
using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;

namespace WebApiWithIdentity.Requirments;

public class MinAgeRequirementHandler : AuthorizationHandler<MinAgeRequirements>
{
    protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, MinAgeRequirements requirement)
    {
          // Get the user's birthdate from claims
            // Try different claim types for flexibility
            var birthdateClaim = context.User.FindFirst("birthdate")
                ?? context.User.FindFirst("date_of_birth")
                ?? context.User.FindFirst(ClaimTypes.DateOfBirth);

            if (birthdateClaim == null)
            {
                // No birthdate claim — cannot verify age, deny access
                // (alternative: you could allow if no birthdate claim is present,
                // depending on your requirements)
                return Task.CompletedTask;
            }

            // Parse the birthdate
            if (!DateTime.TryParse(birthdateClaim.Value, out var birthdate))
            {
                // Invalid birthdate format — deny access
                return Task.CompletedTask;
            }

            // Calculate age
            var today = DateTime.Today;
            var age = today.Year - birthdate.Year;
            if (birthdate > today.AddYears(-age))
            {
                age--;  // Birthday hasn't occurred yet this year
            }

            // Check if age meets minimum
            if (age >= requirement.MinimumAge)
            {
                context.Succeed(requirement);
            }

            return Task.CompletedTask;

    }
}
