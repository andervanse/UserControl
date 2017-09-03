using System;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using UserControl.Models;

namespace UserControl.Data
{
	public class ContextInitializer
    {
		private RoleManager<IdentityRole> _roleMgr;
		private UserManager<AppUser> _userMgr;

		public ContextInitializer(UserManager<AppUser> userMgr, RoleManager<IdentityRole> roleMgr)
		{
			_userMgr = userMgr;
			_roleMgr = roleMgr;
		}

		public async Task Seed()
		{
			var user = await _userMgr.FindByNameAsync("Anderson");

			// Add User
			if (user == null)
			{
				if (!(await _roleMgr.RoleExistsAsync("Admin")))
				{
					var role = new IdentityRole("Admin");
					role.Claims.Add(new IdentityRoleClaim<string>() { ClaimType = "IsAdmin", ClaimValue = "True" });
					await _roleMgr.CreateAsync(role);
				}

				user = new AppUser("Anderson")
				{
					Email = "andervanse@gmail.com"
				};

				var userResult = await _userMgr.CreateAsync(user, "P@ssw0rd!");
				var roleResult = await _userMgr.AddToRoleAsync(user, "Admin");
				var claimResult = await _userMgr.AddClaimAsync(user, new Claim("SuperUser", "True"));

				if (!userResult.Succeeded || !roleResult.Succeeded || !claimResult.Succeeded)
				{
					throw new InvalidOperationException("Failed to build user and roles");
				}

			}
		}
	}
}
