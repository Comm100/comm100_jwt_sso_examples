using System.Web.Mvc;
using System.Web.Security;

namespace JsonWebTokenServer.Controllers
{
    [Authorize]
    public class HomeController : Controller
    {
        public ActionResult Index()
        {
            ViewBag.Title = "Home Page";
            ViewBag.Username = User.Identity.Name;
            return View();
        }

        [AllowAnonymous]
        [HttpGet]
        public ActionResult Logout()
        {
            if (User.Identity.IsAuthenticated)
            {
                FormsAuthentication.SignOut();
            }
            return RedirectToAction("Login", "Accounts");
        }
    }
}
