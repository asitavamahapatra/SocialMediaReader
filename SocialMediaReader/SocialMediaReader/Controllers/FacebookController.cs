using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.Owin;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Threading.Tasks;
using System.Web;
using System.Web.Mvc;

namespace SocialMediaReader.Controllers
{
    [Authorize]

        public class FacebookController : Controller
    {
        private ApplicationUserManager _userManager;
        public ApplicationUserManager UserManager
        {
            get
            {
                return _userManager ?? HttpContext.GetOwinContext().GetUserManager<ApplicationUserManager>();
            }
            private set
            {
                _userManager = value;
            }
        }

        // GET: Facebook
        public ActionResult Index()
        {
            return View();
        }

        public async Task<ActionResult> Posts()
        {
            var currentClaims = await UserManager.GetClaimsAsync(HttpContext.User.Identity.GetUserId());
            var accesstoken = currentClaims.FirstOrDefault(x => x.Type == "urn:tokens:facebook");
            if(accesstoken == null)
            {
                return (new HttpStatusCodeResult(HttpStatusCode.NotFound, "Toekn not found"));
            }

            string url = String.Format("https://graph.facebook.com/me?fields=id,name,feed.limit(100){{message,story,created_time,attachments{{description,type,url,title,media,target}},likes{{id,name}},comments{{id,from,message}}}}&access_token={0}", accesstoken.Value);

            HttpWebRequest request = WebRequest.Create(url) as HttpWebRequest;
            request.Method = "GET";

            using (HttpWebResponse response = await request.GetResponseAsync() as HttpWebResponse)
            {
                StreamReader reader = new StreamReader(response.GetResponseStream());

                string result = await reader.ReadToEndAsync();
                dynamic jsonObj = System.Web.Helpers.Json.Decode(result);
                Models.SocialMedia.Facebook.posts posts = new Models.SocialMedia.Facebook.posts(jsonObj);

                ViewBag.JSON = result;
                return View(posts);
            }

            
        }
    }
}