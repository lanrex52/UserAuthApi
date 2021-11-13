using System.ComponentModel.DataAnnotations;

namespace UserAuthApi.Models.Accounts
{
    public class LoginRequest
    {
        [Required]
        public string UserName { get; set; }
        [Required]
        public string Password {  get; set; }   
    }
}
