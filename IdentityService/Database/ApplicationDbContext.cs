using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace IdentityService.Database;

public class ApplicationDbContext(DbContextOptions<ApplicationDbContext> options) : IdentityDbContext<IdentityUser>
{
    protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
    {
        if (!optionsBuilder.IsConfigured)
        {
            optionsBuilder.UseNpgsql("Host=localhost;Port=4050;Database=app_db;Username=admin;Password=password");
        }
    }
}
