using System;
using System.Collections.Generic;
using System.Configuration;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net.Http;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Web;
using System.Web.Mvc;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using MvcApplication.ViewModels;
using Newtonsoft.Json.Linq;

namespace MvcApplication.Controllers
{
    public class AccountController : Controller
    {
        public ActionResult Login(string returnUrl)
        {
            // PKCE helper functions
            string CreateCodeVerifier()
            {
                var rng = RandomNumberGenerator.Create();
                var bytes = new byte[32];
                rng.GetBytes(bytes);
                return Base64UrlEncoder.Encode(bytes);
            }

            string CreateCodeChallenge(string codeVerifierParam)
            {
                using (var sha256 = SHA256.Create())
                {
                    var challengeBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(codeVerifierParam));
                    return Base64UrlEncoder.Encode(challengeBytes);
                }
            }

            string codeVerifier = CreateCodeVerifier();
            string codeChallenge = CreateCodeChallenge(codeVerifier);

            var authenticationProps = new AuthenticationProperties
            {
                RedirectUri = returnUrl ?? Url.Action("Index", "Home"),
            };

            if (authenticationProps.Dictionary != null)
            {
                //authenticationProps.Dictionary.Add("code_challenge", codeChallenge);
                //authenticationProps.Dictionary.Add("code_challenge_method", "S256");
                //authenticationProps.Dictionary.Add("code_verifier", codeVerifier);
            }

            HttpContext.GetOwinContext().Authentication.Challenge(authenticationProps, "Auth0");
            
            return new HttpUnauthorizedResult();
        }

        [Authorize]
        public void Logout()
        {
            HttpContext.GetOwinContext().Authentication.SignOut(CookieAuthenticationDefaults.AuthenticationType);
            HttpContext.GetOwinContext().Authentication.SignOut("Auth0");
        }

        [HttpPost]
        public async Task Callback(FormCollection form)
        {
            string auth0Domain = ConfigurationManager.AppSettings["auth0:Domain"];
            string auth0ClientId = ConfigurationManager.AppSettings["auth0:ClientId"];
            string auth0ClientSecret = ConfigurationManager.AppSettings["auth0:ClientSecret"];
            string auth0RedirectUri = ConfigurationManager.AppSettings["auth0:RedirectUri"];

            var httpClient = new HttpClient();

            var requestContent = new FormUrlEncodedContent(new[]
            {
                            new KeyValuePair<string, string>("grant_type", "authorization_code"),
                            new KeyValuePair<string, string>("client_id", auth0ClientId),
                            new KeyValuePair<string, string>("client_secret", auth0ClientSecret),
                            new KeyValuePair<string, string>("code", form["code"]),
                            new KeyValuePair<string, string>("redirect_uri", auth0RedirectUri)
                        });

            var response = await httpClient.PostAsync($"https://{auth0Domain}/oauth/token", requestContent);

            if (!response.IsSuccessStatusCode)
            {
                var errorMessage = await response.Content.ReadAsStringAsync();

                throw new Exception($"Error fetching access token. Status Code: {response.StatusCode}");
            }

            var responseContent = await response.Content.ReadAsStringAsync();

            var responseData = JObject.Parse(responseContent);

            var accessToken = responseData.Value<string>("access_token");
            var idToken = responseData.Value<string>("id_token");

            var jwtHandler = new JwtSecurityTokenHandler();

            // Validate the token (Replace constants with actual values)
            var validationParameters = new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(auth0ClientSecret)),
                ValidateIssuer = true,
                ValidIssuer = $"https://{auth0Domain}/",
                ValidateAudience = true,
                ValidAudience = auth0ClientId,
                ValidateLifetime = true,
            };

            SecurityToken validatedToken;
            var principal = jwtHandler.ValidateToken(idToken, validationParameters, out validatedToken);

            // custom code
            var identity = new ClaimsIdentity(principal.Claims, CookieAuthenticationDefaults.AuthenticationType);

            HttpContext.GetOwinContext().Authentication.SignIn(identity);
            HttpContext.GetOwinContext().Authentication.SignOut("Auth0");
        }

        [Authorize]
        public ActionResult UserProfile()
        {
            var claimsIdentity = User.Identity as ClaimsIdentity;

            return View(new UserProfileViewModel()
            {
                Name = claimsIdentity?.FindFirst(c => c.Type == "name").Value,
                EmailAddress = claimsIdentity?.FindFirst(c => c.Type == ClaimTypes.Email)?.Value,
                ProfileImage = claimsIdentity?.FindFirst(c => c.Type == "picture")?.Value
            });
        }

        [Authorize]
        public ActionResult Claims()
        {
            return View();
        }
    }
}
