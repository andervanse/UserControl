using System;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using UserControl.Models;
using UserControl.Services;

namespace UserControl.Controllers
{
	[Route("api/auth")]
	public class AuthorizationController : Controller
	{
		private ILogger<AuthorizationController> _logger;
		private SignInManager<AppUser> _signInManager;
		private UserManager<AppUser> _userManager;
		private IPasswordHasher<AppUser> _hasher;
		private IEmailSender _emailSender;
		private IConfigurationRoot _config;
		private string _externalCookieScheme;

		public AuthorizationController(ILogger<AuthorizationController> logger,
			SignInManager<AppUser> signInManager,
			UserManager<AppUser> userManager,
			IPasswordHasher<AppUser> hasher,
			IEmailSender emailSender,
			IConfigurationRoot config,
			IOptions<IdentityCookieOptions> identityCookieOptions)
		{
			_logger = logger;
			_signInManager = signInManager;
			_userManager = userManager;
			_hasher = hasher;
			_emailSender = emailSender;
			_config = config;
			_externalCookieScheme = identityCookieOptions.Value.ExternalCookieAuthenticationScheme;
		}

		[Route("token", Name = "token")]
		[HttpPost]
		public async Task<IActionResult> CreateToken([FromBody] UserCredentialsViewModel credentials)
		{
			await HttpContext.Authentication.SignOutAsync(_externalCookieScheme);

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
		public async Task<IActionResult> Register([FromBody] UserModelViewModel model)
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

			return Ok(new { token = Url.Link("token", null) });
		}

		[Route("ResetPassword")]
		[HttpGet]
		public IActionResult ResetPassword(string code = null)
		{
			if (code == null) return BadRequest();

			return Ok(new { Message = "senha confirmada com sucesso!" });
		}

		[Route("ResetPassword")]
		[HttpPost]
		[ValidateAntiForgeryToken]
		public async Task<IActionResult> ResetPassword(UserCredentialsViewModel model)
		{
			if (!ModelState.IsValid)
			{
				return BadRequest(ModelState);
			}

			var user = await _userManager.FindByEmailAsync(model.Email);

			if (user == null)
			{
				return Ok(new { Message = "confirmação de Email." });
			}

			var result = await _userManager.ResetPasswordAsync(user, model.Code, model.Password);

			if (result.Succeeded)
			{
				return Ok(new { Message = "Senha resetada com sucesso." });
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

		//
		// POST: /Account/SendCode
		[Route("SendCode", Name = "SendCode")]
		[HttpPost]
		public async Task<IActionResult> SendCode(string provider)
		{
			if (!ModelState.IsValid)
			{
				return View();
			}

			var user = await _signInManager.GetTwoFactorAuthenticationUserAsync();
			if (user == null)
			{
				return View("Error");
			}

			// Generate the token and send it
			var code = await _userManager.GenerateTwoFactorTokenAsync(user, provider);
			if (string.IsNullOrWhiteSpace(code))
			{
				return View("Error");
			}

			var message = "Your security code is: " + code;
			if (provider == "Email")
			{
				await _emailSender.SendEmailAsync(await _userManager.GetEmailAsync(user), "Security Code", message);
			}

			return Ok();// RedirectToAction(nameof(VerifyCode), new { Provider = model.SelectedProvider, ReturnUrl = model.ReturnUrl, RememberMe = model.RememberMe });
		}


		//Facebook Login

		[WebApiChallenge]
		[Route("FacebookLogin")]
		[HttpGet]		
		public async Task<IActionResult> FacebookLogin(string returnUrl = null)
		{
			await HttpContext.Authentication.SignOutAsync(_externalCookieScheme);
			string provider = "Facebook";

			if (String.IsNullOrEmpty(returnUrl))
				returnUrl = Request.Headers["Referer"];

			var properties = _signInManager.ConfigureExternalAuthenticationProperties(provider, Url.Link("ExternalLoginCallback", returnUrl));
			return Challenge(properties, provider);
		}

		[Route("signin-facebook", Name = "ExternalLoginCallback")]
		[HttpGet]
		[AllowAnonymous]
		public async Task<IActionResult> ExternalLoginCallback(string returnUrl = null, string remoteError = null)
		{
			var info = await _signInManager.GetExternalLoginInfoAsync();
			if (info == null)
			{
				return BadRequest("Could not retrive External login info.");
			}

			// Sign in the user with this external login provider if the user already has a login.
			var result = await _signInManager.ExternalLoginSignInAsync(info.LoginProvider, info.ProviderKey, isPersistent: false);

			if (result.Succeeded)
			{
				_logger.LogInformation(5, "User logged in with {Name} provider.", info.LoginProvider);
				return Ok(new { Message = "Logado com sucesso." });
			}
			if (result.RequiresTwoFactor)
			{
				var redirectUrl = Url.Link("SendCode", "Email");
				return Ok(new { RedirectUrl = redirectUrl});
			}
			if (result.IsLockedOut)
			{
				return BadRequest("User has been Locked out.");
			}
			else
			{
				// If the user does not have an account, then ask the user to create an account.
				var email = info.Principal.FindFirstValue(ClaimTypes.Email);
				var redirectUrl = Url.Link("ExternalLoginConfirmation", new { Email = email });
				return Ok(new { Message = "Confirmar email", RedirectUrl = redirectUrl });
			}
		}

		[Route("ExternalLoginConfirmation", Name = "ExternalLoginConfirmation")]
		[HttpPost]		
		[ValidateAntiForgeryToken]
		public async Task<IActionResult> ExternalLoginConfirmation(ExternalLoginConfirmationViewModel model, string returnUrl = null)
		{
			if (ModelState.IsValid)
			{
				// Get the information about the user from the external login provider
				var info = await _signInManager.GetExternalLoginInfoAsync();
				if (info == null)
				{
					return View("ExternalLoginFailure");
				}
				var user = new AppUser { UserName = model.Email, Email = model.Email };
				var result = await _userManager.CreateAsync(user);
				if (result.Succeeded)
				{
					result = await _userManager.AddLoginAsync(user, info);
					if (result.Succeeded)
					{
						await _signInManager.SignInAsync(user, isPersistent: false);
						_logger.LogInformation(6, "User created an account using {Name} provider.", info.LoginProvider);
						return Ok(returnUrl);
					}
				}
				AddErrors(result);
			}

			ViewData["ReturnUrl"] = returnUrl;
			return View(model);
		}
		
	}
}
