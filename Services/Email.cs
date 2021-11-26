using Microsoft.Extensions.Options;
using MimeKit;
using MimeKit.Text;

using UserAuthApi.Helpers;
using UserAuthApi.Services.IServices;
using MailKit.Net.Smtp;
using MailKit.Security;

namespace UserAuthApi.Services
{
    public class Email : IEmail
    {
        private readonly AppSettings _appSettings;
        public Email(IOptions<AppSettings> appSettings)
        {
            _appSettings = appSettings.Value;
        }
        public void SendEmail(string to, string subject, string html)
        {
            //create message
            var email = new MimeMessage();
            email.From.Add(MailboxAddress.Parse(""));
            email.To.Add(MailboxAddress.Parse(to));
            email.Subject = subject;
            email.Body = new TextPart(TextFormat.Html) { Text = html};

            using var smtp = new SmtpClient();
            smtp.Connect(_appSettings.SmtpHost, _appSettings.SmtpPort, SecureSocketOptions.StartTls);
            smtp.Authenticate(_appSettings.SmtpUsername, _appSettings.SmtpPassword);
            smtp.Send(email);

            smtp.Disconnect(true);

        }
    }
}
;