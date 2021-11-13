using System.ComponentModel.DataAnnotations;

namespace UserAuthApi.Models.Accounts
{
    public class ResetPasswordRequest
    {
        [Required]
        public string Token { get; set; }
        [Required]
       
        [MinLength(6, ErrorMessage = "Minimum Password Length cannot be less than six characters")]
        public string Password { get; set; }
        [Required]
        [Compare("Password", ErrorMessage = "Password does not match")]
        public string ConfirmPassword { get; set; }
    }
}
