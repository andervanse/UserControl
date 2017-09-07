using System.Diagnostics;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using UserControl.Data;
using UserControl.Models;
using UserControl.Services;

namespace UserControl
{
	public class Startup
	{
		public Startup(IHostingEnvironment env)
		{
			var builder = new ConfigurationBuilder()
				.SetBasePath(env.ContentRootPath)
				.AddJsonFile("appsettings.json", optional: false, reloadOnChange: true)
				.AddJsonFile($"appsettings.{env.EnvironmentName}.json", optional: true)
				.AddEnvironmentVariables();

			if (env.IsDevelopment())
			{
				builder.AddUserSecrets("8e1a5c99-52dc-472e-8b39-0a2326e0db9f");
			}

			_config = builder.Build();
		}

		private IConfigurationRoot _config { get; }

		public void ConfigureServices(IServiceCollection services)
		{
			services.AddOptions();

			//Email Service
			services.AddTransient<IEmailSender, AuthMessageSender>();
			services.AddTransient<ISmsSender, AuthMessageSender>();
			services.Configure<AuthMessageSenderOptions>( _config.GetSection("AuthMessageSenderOptions"));

			services.AddSingleton(_config);
			services.AddDbContext<ApplicationContext>(opt => opt.UseInMemoryDatabase());
			services.AddTransient<ContextInitializer>();
			services.AddIdentity<AppUser, IdentityRole>(config =>
			{
				config.SignIn.RequireConfirmedEmail = true;
			})
			.AddEntityFrameworkStores<ApplicationContext>()
			.AddDefaultTokenProviders();

			services.AddAuthorization(config => {
				config.AddPolicy("SuperUser", p => p.RequireClaim("SuperUser", "True"));
			});

			services.Configure<IdentityOptions>(config =>
			{
				config.Cookies.ApplicationCookie.Events =
				new CookieAuthenticationEvents()
				{
					OnRedirectToLogin = (ctx) =>
					{
						if (ctx.Request.Path.StartsWithSegments("/api") && ctx.Response.StatusCode == 200)
						{
							ctx.Response.StatusCode = 401;
						}

						return Task.CompletedTask;
					},
					OnRedirectToAccessDenied = (ctx) =>
					{
						if (ctx.Request.Path.StartsWithSegments("/api") && ctx.Response.StatusCode == 200)
						{
							ctx.Response.StatusCode = 403;
						}

						return Task.CompletedTask;
					}
				};
			});

			services.Configure<MvcOptions>(opt =>
			{
				opt.Filters.Add(new RequireHttpsAttribute());
			});

			services.AddMvc();
		}

		public void Configure(IApplicationBuilder app,
			IHostingEnvironment env,
			ILoggerFactory loggerFactory,
			ContextInitializer seeder)
		{
			loggerFactory.AddConsole(_config.GetSection("Logging"));
			loggerFactory.AddDebug();
			loggerFactory.AddFile("Logs/userControl-{Date}.txt");

			app.UseCors(config =>
				config.AllowAnyHeader()
				.AllowAnyMethod()
				.WithOrigins(_config["Tokens:Issuer"])
			);

			app.UseIdentity();
			app.UseJwtBearerAuthentication(new JwtBearerOptions() {
				AutomaticAuthenticate = true,
				AutomaticChallenge = true,
				TokenValidationParameters = new TokenValidationParameters()
				{
					ValidIssuer = _config["Tokens:Issuer"],
					ValidAudience = _config["Tokens:Audience"],
					IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["Tokens:Key"])),
					ValidateLifetime = true
				}
			});

			app.UseMvc();
			
			seeder.Seed().Wait();

			if (env.IsDevelopment())
			{
				Debug.WriteLine("DEVELOPMENT MODE.");
				Debug.WriteLine("\tConnectionString=" + _config.GetSection("ConnectionString").Value);
				var authMessage = _config.GetSection("AuthMessageSenderOptions").Get<AuthMessageSenderOptions>();
				Debug.WriteLine("\tSendGrid:User=" + authMessage.SendGridUser);
				Debug.WriteLine("\tTokens:Issuer=" + _config.GetSection("Tokens:Issuer").Value);
				Debug.WriteLine("\tTokens:Audience=" + _config.GetSection("Tokens:Audience").Value);
				Debug.WriteLine("\tAdminUser:Name=" + _config["AdminUser:Name"]);
				Debug.WriteLine("\tAdminUser:Email=" + _config["AdminUser:Email"]);
			}
		}
	}
}
