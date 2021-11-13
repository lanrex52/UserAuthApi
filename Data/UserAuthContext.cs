using Microsoft.EntityFrameworkCore;
using UserAuthApi.Entities;

namespace UserAuthApi.Data
{
    public class UserAuthContext:DbContext
    {
        public UserAuthContext(DbContextOptions<UserAuthContext> options): base(options)
        {

        }

        public DbSet<Account> Accounts {  get; set; }
    }
}
