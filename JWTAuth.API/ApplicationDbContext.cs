using JWTAuthSecuredAPI.Constants;
using JWTAuthSecuredAPI.Entities;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace JWTAuthSecuredAPI
{
    public class ApplicationDbContext : IdentityDbContext<UserEntity>
    {
        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options) : base(options)
        {
        }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            modelBuilder.Entity<IdentityRole>().HasData(
                new IdentityRole
                {
                    Id = Guid.NewGuid().ToString(),
                    Name = UserRolesConstants.Admin,
                    NormalizedName = UserRolesConstants.Admin,
                    ConcurrencyStamp = Guid.NewGuid().ToString()
                },
                new IdentityRole
                {
                    Id = Guid.NewGuid().ToString(),
                    Name = UserRolesConstants.Reader,
                    NormalizedName = UserRolesConstants.Reader,
                    ConcurrencyStamp = Guid.NewGuid().ToString()
                }
             );

            base.OnModelCreating(modelBuilder);
        }

        public DbSet<UserEntity> Users { get; set; }
        public DbSet<IdentityRole> Roles { get; set; }
        public DbSet<IdentityUserToken<string>> UserTokens { get; set; }

    }
}
