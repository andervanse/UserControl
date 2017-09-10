using Microsoft.AspNetCore.Identity.EntityFrameworkCore;

namespace UserControl.Models
{
	public class AppUser : IdentityUser
    {
		public AppUser():base()
		{
		}

		public AppUser(string userName):base(userName)
		{
		}
    }
}
