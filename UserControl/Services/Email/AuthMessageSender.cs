using Microsoft.Extensions.Options;
using SendGrid;
using SendGrid.Helpers.Mail;
using System.Threading.Tasks;

namespace UserControl.Services
{

	public interface IEmailSender
	{
		Task SendEmailAsync(string email, string subject, string message);
	}

	public interface ISmsSender
	{
		Task SendSmsAsync(string number, string message);
	}

	public class AuthMessageSender : IEmailSender, ISmsSender
	{
		private AuthMessageSenderOptions _options;

		public AuthMessageSender(IOptions<AuthMessageSenderOptions> optionsAccessor)
		{
			_options = optionsAccessor.Value;
		}

		public Task SendEmailAsync(string email, string subject, string message)
		{
			return Execute(_options.SendGridKey, subject, message, email);
		}

		public Task Execute(string apiKey, string subject, string message, string email)
		{
			var client = new SendGridClient(apiKey);
			var msg = new SendGridMessage()
			{
				From = new EmailAddress(_options.SendGridUser, "UserControl"),
				Subject = subject,
				PlainTextContent = message,
				HtmlContent = message
			};
			msg.AddTo(new EmailAddress(email));
			return client.SendEmailAsync(msg);
		}

		public Task SendSmsAsync(string number, string message)
		{
			// Plug in your SMS service here to send a text message.
			return Task.FromResult(0);
		}
	}
}
