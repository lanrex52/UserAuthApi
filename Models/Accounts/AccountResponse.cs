﻿namespace UserAuthApi.Models.Accounts
{
    public class AccountResponse
    {
        public int Id {  get; set; }
        public string FirstName { get; set; }
        public string LastName { get; set; }
        public string Email { get; set; }
        public string UserName { get; set; }
        public string? Gender { get; set; }
        public string? PhoneNumber { get; set; }
        public string Role { get; set; }
        public DateTime Created { get; set; }
        public DateTime? Updated { get; set; }
        public bool IsVerified { get; set; }

    }
}
