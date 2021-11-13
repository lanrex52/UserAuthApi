namespace UserAuthApi.Services.IServices
{
    public interface IEmail
    {
        void SendEmail(string to, string subject, string html);
    }
}
