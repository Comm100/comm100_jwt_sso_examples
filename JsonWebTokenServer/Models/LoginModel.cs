using System.ComponentModel.DataAnnotations;

namespace JsonWebTokenServer.Models
{
    public class LoginModel
    {
        [Required]
        [EmailAddress]
        public string Username { get; set; }

        [Required]
        public string Password { get; set; }

        public string RedirectUri { get; set; }
    }
}