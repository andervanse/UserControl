using Newtonsoft.Json;

namespace UserControl.Models
{
	public class FacebookToken
    {
		[JsonProperty("access_token")]
		public string Token { get; set; }
		[JsonProperty("token_type")]
		public string TokenType { get; set; }
		[JsonProperty("expires_in")]
		public string ExpiresIn { get; set; }
	}
}
