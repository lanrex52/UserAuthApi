using System.ComponentModel.DataAnnotations;

namespace UserAuthApi.Models.Accounts
{
    public class VerifyEmailRequest
    {
        [Required]
        public string Token { get; set; }
    }
}
