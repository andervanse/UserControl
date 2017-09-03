using System.ComponentModel.DataAnnotations;

namespace UserControl.Models
{
    public class ForgotPasswordViewModel
    {
		[Required]
		public string Email { get; set; }
	}
}
