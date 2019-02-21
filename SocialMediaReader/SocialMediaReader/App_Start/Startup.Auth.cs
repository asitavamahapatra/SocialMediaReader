using System;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Owin;
using System.Threading.Tasks;
using Microsoft.Owin.Security.Cookies;
using Owin;
using SocialMediaReader.Models;
using Owin.Security.Providers.Instagram;
using Microsoft.Owin.Security.Facebook;
using System.Configuration;
using Owin.Security.Providers.LinkedIn;

namespace SocialMediaReader
{
    public partial class Startup
    {
        // For more information on configuring authentication, please visit https://go.microsoft.com/fwlink/?LinkId=301864
        public void ConfigureAuth(IAppBuilder app)
        {
            // Configure the db context, user manager and signin manager to use a single instance per request
            app.CreatePerOwinContext(ApplicationDbContext.Create);
            app.CreatePerOwinContext<ApplicationUserManager>(ApplicationUserManager.Create);
            app.CreatePerOwinContext<ApplicationSignInManager>(ApplicationSignInManager.Create);

            // Enable the application to use a cookie to store information for the signed in user
            // and to use a cookie to temporarily store information about a user logging in with a third party login provider
            // Configure the sign in cookie
            app.UseCookieAuthentication(new CookieAuthenticationOptions
            {
                AuthenticationType = DefaultAuthenticationTypes.ApplicationCookie,
                LoginPath = new PathString("/Account/Login"),
                Provider = new CookieAuthenticationProvider
                {
                    // Enables the application to validate the security stamp when the user logs in.
                    // This is a security feature which is used when you change a password or add an external login to your account.  
                    OnValidateIdentity = SecurityStampValidator.OnValidateIdentity<ApplicationUserManager, ApplicationUser>(
                        validateInterval: TimeSpan.FromMinutes(30),
                        regenerateIdentity: (manager, user) => user.GenerateUserIdentityAsync(manager))
                }
            });            
            app.UseExternalSignInCookie(DefaultAuthenticationTypes.ExternalCookie);

            // Enables the application to temporarily store user information when they are verifying the second factor in the two-factor authentication process.
            app.UseTwoFactorSignInCookie(DefaultAuthenticationTypes.TwoFactorCookie, TimeSpan.FromMinutes(5));

            // Enables the application to remember the second login verification factor such as phone or email.
            // Once you check this option, your second step of verification during the login process will be remembered on the device where you logged in from.
            // This is similar to the RememberMe option when you log in.
            app.UseTwoFactorRememberBrowserCookie(DefaultAuthenticationTypes.TwoFactorRememberBrowserCookie);

            // Uncomment the following lines to enable logging in with third party login providers
            app.UseLinkedInAuthentication(
                clientId: "77val1k0uyczya",
                clientSecret: "w3kD1BeIjbrzKT0s");

            //app.UseTwitterAuthentication(
            //   consumerKey: "",
            //   consumerSecret: "");



            var facebookAuteticationOptions = new FacebookAuthenticationOptions()
            {
                AppId = ConfigurationManager.AppSettings["FacebookAppId"],
                AppSecret = ConfigurationManager.AppSettings["FacebookAppSecret"],
                Provider = new FacebookAuthenticationProvider()
                {
                    OnAuthenticated = context =>
                    {
                        context.Identity.AddClaim(new System.Security.Claims.Claim("urn:tokens:facebook", context.AccessToken));

                        return Task.FromResult(0);
                    }
                },
                SignInAsAuthenticationType = DefaultAuthenticationTypes.ExternalCookie,
                SendAppSecretProof = true
            };

            facebookAuteticationOptions.Scope.Add("email user_friends user_likes user_photos");

            app.UseFacebookAuthentication(facebookAuteticationOptions);

            //app.UseFacebookAuthentication(
            // appId: ConfigurationManager.AppSettings["FacebookAppId"],
            //appSecret: ConfigurationManager.AppSettings["FacebookAppSecret"]);

            //Instagram
            app.UseInstagramInAuthentication(new InstagramAuthenticationOptions
            {
                ClientId = "6eff4ab8b0bc488395f42b1c94e54ac6",
                ClientSecret = "f6a4e44b3e2646dd8d739ac097b05ee9"
            });

            //LinkedIn
           /* app.UseLinkedInAuthentication(new LinkedInAuthenticationOptions
            {
                ClientId = "<your client id>",
                ClientSecret = "<your client secret>"
            });*/

            //app.UseGoogleAuthentication(new GoogleOAuth2AuthenticationOptions()
            //{
              //  ClientId = "",
               // ClientSecret = ""
            //});
        }
    }
}