namespace UserAuthApi.Helpers
{
    public class AppSettings
    {
        public string JwtSecret {  get; set; }

        public int RefreshTokenTTL { get; set; }
        public string SmtpHost {  get; set; }   
        public string SmtpPort {  get; set;}
        public string SmtpUsername {  get; set;}
        public string SmtpPassword {  get; set;}    

    }
}
