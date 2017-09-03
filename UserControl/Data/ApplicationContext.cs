using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using UserControl.Models;

namespace UserControl.Data
{
	public class ApplicationContext : IdentityDbContext<AppUser, IdentityRole, string>
    {
		public ApplicationContext(DbContextOptions options) : base(options)
		{
		}

		public ApplicationContext() :base()
		{
		}

	}
}
