using System.ComponentModel.DataAnnotations;

namespace UserControl.Models
{
	public class UserCredentialsViewModel
    {
		[Required(ErrorMessage = "Obrigatório")]
		[EmailAddress(ErrorMessage = "Email inválido")]
		public string Email { get; set; }

		[Required(ErrorMessage = "Obrigatório")]
		[StringLength(100, ErrorMessage = "O {0} deve ser entre {2} e {1} characteres.", MinimumLength = 6)]
		[DataType(DataType.Password)]
		public string Password { get; set; }
		
		public string Code { get; set; }
	}
}
