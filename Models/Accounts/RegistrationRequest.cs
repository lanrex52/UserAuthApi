using System.ComponentModel.DataAnnotations;

namespace UserAuthApi.Models.Accounts
{
    public class RegistrationRequest
    {
        [Required]
        public string FirstName { get; set; }
        [Required]
        public string LastName { get; set; }
        [Required]
        [EmailAddress]
        public string Email { get; set; }
        [Required]
        public string UserName { get; set; }
        [Required]
        public string Gender { get; set; }
        [Required]
       
        public string PhoneNumber { get; set; }
        [Required]
        [MinLength(6, ErrorMessage ="Minimum Password Length cannot be less than six characters")]
        public string Password { get; set; }
        [Required]
        [Compare("Password", ErrorMessage ="Password does not match")]
        public string ConfirmPassword { get; set; }
        [Range(typeof(bool),"true", "true")]
        public bool AcceptTerms { get; set; }
    }
}
