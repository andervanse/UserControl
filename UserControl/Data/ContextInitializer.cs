using System;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using UserControl.Models;

namespace UserControl.Data
{
	public class ContextInitializer
    {
		private RoleManager<IdentityRole> _roleMgr;
		private IConfigurationRoot _config;
		private UserManager<AppUser> _userMgr;

		public ContextInitializer(UserManager<AppUser> userMgr, RoleManager<IdentityRole> roleMgr, IConfigurationRoot config)
		{
			_userMgr = userMgr;
			_roleMgr = roleMgr;
			_config = config;
		}

		public async Task Seed()
		{
			string userName = _config["AdminUser:Name"];
			string email = _config["AdminUser:Email"];
			string password = _config["AdminUser:Password"];

			var user = await _userMgr.FindByNameAsync(userName);

			// Add User
			if (user == null)
			{
				if (!(await _roleMgr.RoleExistsAsync("Admin")))
				{
					var role = new IdentityRole("Admin");
					role.Claims.Add(new IdentityRoleClaim<string>() { ClaimType = "IsAdmin", ClaimValue = "True" });
					await _roleMgr.CreateAsync(role);
				}

				user = new AppUser(userName)
				{
					Email = email
				};

				var userResult = await _userMgr.CreateAsync(user, password);
				var roleResult = await _userMgr.AddToRoleAsync(user, "Admin");
				var claimResult = await _userMgr.AddClaimAsync(user, new Claim("SuperUser", "True"));

				if (!userResult.Succeeded || !roleResult.Succeeded || !claimResult.Succeeded)
				{
					throw new InvalidOperationException("Failed to build user and roles");
				}

				var code = await _userMgr.GenerateEmailConfirmationTokenAsync(user);
				var result = await _userMgr.ConfirmEmailAsync(user, code);

				if (!result.Succeeded)
					throw new InvalidOperationException("Failed to confirm Email");

			}
		}
	}
}
