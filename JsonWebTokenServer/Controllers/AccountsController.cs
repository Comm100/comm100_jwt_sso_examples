using JsonWebTokenServer.Models;
using System.Web.Configuration;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.IdentityModel.Tokens.Jwt;
using System.Web.Mvc;
using System.Web.Security;

namespace JsonWebTokenServer.Controllers
{
    public class AccountsController : Controller
    {
        [HttpGet]
        public ActionResult Login(string redirect_url = "")
        {      
            //if user has authenticated, return directly.
            if (User.Identity.IsAuthenticated)
            {
                var accessToken = GenerateToken(User.Identity.Name);
                var queryStringSeparator = redirect_url.Contains("?") ? "&" : "?";
                var redirectUrl = string.Format("{0}{1}jwt={2}", redirect_url, queryStringSeparator, accessToken);
                return Redirect(redirectUrl);
            }

            return View(new LoginModel {RedirectUri = redirect_url});
        }

        [HttpPost]
        public ActionResult Login(LoginModel model)
        {
            //todo: check username and password in production
            if (!ModelState.IsValid)
            {
                ModelState.AddModelError("", "Username or password is wrong.");
                return View(model);
            }
            var redirect_uri = string.IsNullOrWhiteSpace(model.RedirectUri) ? "" : model.RedirectUri;
            FormsAuthentication.SetAuthCookie(model.Username, false);
            if (string.IsNullOrEmpty(redirect_uri))
            {
                return RedirectToAction("Index", "Home");
            }
            var accessToken = GenerateToken(model.Username);
           
            var queryStringSeparator = redirect_uri.Contains("?") ? "&" : "?";
            var redirectUrl = string.Format("{0}{1}jwt={2}", redirect_uri, queryStringSeparator, accessToken);
            return Redirect(redirectUrl);
        }

        [HttpGet]
        public ActionResult Error(string message = "")
        {
            ViewBag.Message = message;
            return View();
        }

        private string GenerateToken(string username)
        {
            var sharedKey = WebConfigurationManager.AppSettings["SharedKey"]; // Shared secret got from Comm100 Portal.
            var issuer = "jwt server";
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(sharedKey));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256Signature);
            var claims = new List<Claim>
            {
                new Claim("sub", "comm100"),
                new Claim("email", username),  // Required. Comm100 will use it to match an agent in your site.
                new Claim("jti", Guid.NewGuid().ToString()), // Required.
            };
            var audience = "Comm100";
            var issued = DateTime.UtcNow;
            var expireMinutes = Convert.ToInt32(WebConfigurationManager.AppSettings["ExpireMinutes"]);
            var expires = issued.AddMinutes(expireMinutes);
            var token = new JwtSecurityToken(issuer, audience, claims, issued, expires, creds);
            var handler = new JwtSecurityTokenHandler();
            return handler.WriteToken(token);
        }

        // You can validate the redirect uri
        private bool IsRedirectUriValid(string redirectUri, string returnUrl)
        {
            if (string.IsNullOrEmpty(redirectUri))
            {
                return true;
            }
            var returnUrlSubStr = returnUrl.ToLower();
            if (returnUrl.Contains("?"))
            {
                var length = returnUrl.IndexOf('?');
                returnUrlSubStr = returnUrl.Substring(0, length).ToLower();
            }

            return redirectUri.ToLower().Contains(returnUrlSubStr);
        }
    }
}
