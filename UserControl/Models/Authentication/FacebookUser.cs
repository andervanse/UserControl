
using Newtonsoft.Json;

namespace UserControl.Models
{
	public class FacebookUser
	{
		[JsonProperty("id")]
		public string Id { get; set; }
		[JsonProperty("name")]
		public string FullName { get; set; }
		[JsonProperty("email")]
		public string Email { get; set; }
		[JsonProperty("first_name")]
		public string FirstName { get; set; }
		[JsonProperty("last_name")]
		public string LastName { get; set; }
		[JsonProperty("birthday")]
		public string Birthday { get; set; }
		[JsonProperty("gender")]
		public string Gender { get; set; }
		[JsonProperty("picture")]
		public Picture Picture { get; set; }
	}

	public class Picture
	{
		[JsonProperty("data")]
		public Data Data { get; set; }
	}

	public class Data
	{
		[JsonProperty("url")]
		public string Url { get; set; }
	}
}
