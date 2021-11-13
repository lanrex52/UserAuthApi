using System.ComponentModel.DataAnnotations;
using UserAuthApi.Entities;

namespace UserAuthApi.Models.Accounts
{
    public class UpdateRequest
    {
        private string _password;
        private string _confirmpassword;

        private string _role;

        private string _email;

        private string _gender;


        [Required]
        public string FirstName { get; set; }
        [Required]
        public string LastName { get; set; }
        [Required]
        [EmailAddress]
        public string Email
        {
            get => _email;
            set => _email = replaceEmptyWithNull(value);
        }

        [Required]
        public string Gender
        {
            get => _gender;
            set => _gender = replaceEmptyWithNull(value);
        }
        [Required]
        [EnumDataType(typeof(Role))]
        public string Role { 
            get => _role;
            set => _role = replaceEmptyWithNull(value); 
            }
        [Required]

        public string PhoneNumber { get; set; }
        [Required]
        [MinLength(6, ErrorMessage = "Minimum Password Length cannot be less than six characters")]
        public string Password
        {
            get => _password;
            set => _password = replaceEmptyWithNull(value);
        }
        [Required]
        [Compare("Password", ErrorMessage = "Password does not match")]
        public string ConfirmPassword
        {
            get => _confirmpassword;
            set => _confirmpassword = replaceEmptyWithNull(value);
        }

        private string? replaceEmptyWithNull(string value)
        {
            return string.IsNullOrEmpty(value) ? null : value;
        }

    }
}
