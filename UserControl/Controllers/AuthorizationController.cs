using System;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using UserControl.Models;
using UserControl.Services;

namespace UserControl.Controllers
{
	[Route("api/auth")]
	public class AuthorizationController: Controller
    {
		private ILogger<AuthorizationController> _logger;
		private SignInManager<AppUser> _signInManager;
		private UserManager<AppUser> _userManager;
		private IPasswordHasher<AppUser> _hasher;
		private IEmailSender _emailSender;
		private IConfigurationRoot _config;

		public AuthorizationController(ILogger<AuthorizationController> logger,
			SignInManager<AppUser> signInManager,
			UserManager<AppUser> userManager,
			IPasswordHasher<AppUser> hasher,
			IEmailSender emailSender,
			IConfigurationRoot config)
		{
			_logger = logger;
			_signInManager = signInManager;
			_userManager = userManager;
			_hasher = hasher;
			_emailSender = emailSender;
			_config = config;
		}

		[Route("token", Name = "token")]
		[HttpPost]
		public async Task<IActionResult> CreateToken([FromBody] UserCredentials credentials)
		{
			if (!ModelState.IsValid) return BadRequest(ModelState);

			try
			{
				var user = await _userManager.FindByEmailAsync(credentials.Email);

				if (user != null)
				{					
					bool isEmailConfirmed = user.EmailConfirmed == true;

					if (isEmailConfirmed && _hasher.VerifyHashedPassword(user, user.PasswordHash, credentials.Password) == PasswordVerificationResult.Success)
					{
						var userClaims = await _userManager.GetClaimsAsync(user);

						var claims = new[]
						{
							new Claim(JwtRegisteredClaimNames.Sub, user.UserName),
						    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
						    new Claim(JwtRegisteredClaimNames.Email, user.Email)
						}.Union(userClaims);				

						var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["Tokens:Key"]));
						var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

						var token = new JwtSecurityToken(
							issuer: _config["Tokens:Issuer"],
							audience: _config["Tokens:Audience"],
							claims: claims,
							expires: DateTime.UtcNow.AddMinutes(15),
							signingCredentials: creds);

						return Ok(new
						{
							token = new JwtSecurityTokenHandler().WriteToken(token),
							expiration = token.ValidTo
						});
					}
				}
			}
			catch (Exception ex)
			{
				_logger.LogError($"Erro ao criar token:{ex}");
			}

			return BadRequest();
		}

		[Route("ForgotPassword")]
		[HttpPost]
		public async Task<IActionResult> ForgotPassword([FromBody] ForgotPasswordViewModel model)
		{
			if (ModelState.IsValid)
			{
				var user = await _userManager.FindByEmailAsync(model.Email);
				if (user == null || !(await _userManager.IsEmailConfirmedAsync(user)))
				{
					// Don't reveal that the user does not exist or is not confirmed.
					return Ok(new { message = "Verifique seu e-mail para resetar sua senha." });
				}

				// Send an email with this link
				var code = await _userManager.GeneratePasswordResetTokenAsync(user);
				var callbackUrl = Url.Action(nameof(ResetPassword), "Account",
					new { userId = user.Id, code = code }, protocol: HttpContext.Request.Scheme);

				await _emailSender.SendEmailAsync(model.Email, "Reset Password",
				     $"Por favor informe sua nova senha clicando <a href='{callbackUrl}'>Aqui</a>");

				return Ok(new { message = "Verifique seu e-mail para resetar sua senha." });
			}

			// If we got this far, something failed, redisplay form
			return BadRequest(model);
		}

		[Authorize(Policy = "SuperUser")]
		[Route("register")]
		[HttpPost]
		public async Task<IActionResult> Register([FromBody] UserModel model)
		{
			if (ModelState.IsValid)
			{
				var user = new AppUser { UserName = model.UserName, Email = model.Email };
				var result = await _userManager.CreateAsync(user, model.Password);				

				if (result.Succeeded)
				{
					_logger.LogInformation("User created a new account with password.");

					// Send an email with this link
					var code = await _userManager.GenerateEmailConfirmationTokenAsync(user);
					var callbackUrl = Url.Link("confirmEmail", new { userId = user.Id, code = code });
					await _emailSender.SendEmailAsync(model.UserName, "Confirmação de cadastro",
				             $"Por favor confirme seu cadastro clicando <a href='{callbackUrl}'>Aqui</a>");

					_logger.LogInformation(3, "User created a new account with password.");
					var url = Url.Link("token", null);
					return Ok(new { message = $"por favor confirme o e-mail enviado para { model.UserName }" });
				}
				AddErrors(result);
			}

			return BadRequest(ModelState);
		}

		[Route("confirmEmail", Name = "confirmEmail")]
		[HttpGet]
		public async Task<IActionResult> ConfirmEmail(string userId, string code)
		{
			if (userId == null || code == null)
			{
				return BadRequest();
			}

			var user = await _userManager.FindByIdAsync(userId);

			if (user == null)
			{
				return BadRequest();
			}

			var result = await _userManager.ConfirmEmailAsync(user, code);

			if (!result.Succeeded) return BadRequest();

			return Ok(new { token = Url.Link("token", null)});
		}

		[Route("ResetPassword")]
		[HttpGet]
		public IActionResult ResetPassword(string code = null)
		{
			if (code == null) return BadRequest();

			return Ok(new { message = "senha confirmada com sucesso!" });
		}

		[HttpPost]
		[ValidateAntiForgeryToken]
		public async Task<IActionResult> ResetPassword(UserCredentials model)
		{
			if (!ModelState.IsValid)
			{
				return BadRequest(ModelState);
			}

			var user = await _userManager.FindByEmailAsync(model.Email);

			if (user == null)
			{
				return Ok(new { message = "confirmação de Email." });
			}

			var result = await _userManager.ResetPasswordAsync(user, model.Code, model.Password);

			if (result.Succeeded)
			{
				return Ok(new { message = "Senha resetada com sucesso." });
			}

			AddErrors(result);
			return BadRequest(ModelState);
		}

		private void AddErrors(IdentityResult result)
		{
			foreach (var error in result.Errors)
			{
				ModelState.AddModelError(string.Empty, error.Description);
			}
		}

	}
}
