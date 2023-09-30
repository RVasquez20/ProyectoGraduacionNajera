using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http.Headers;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Web;
using System.Web.Mvc;
using WebApplication1.Models;
using YamlDotNet.RepresentationModel;

namespace WebApplication1.Controllers
{
    public class HomeController : Controller
    {
        public ActionResult Index()
        {
            var rng = new RNGCryptoServiceProvider();
            var bytes = new byte[32];
            rng.GetBytes(bytes);
            var codeVerifier =
                Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace(
                    '/', '_');

            Session["codeVerifier"] = codeVerifier;

            var sha256 = SHA256.Create();
            var challengeBytes =
                sha256.ComputeHash(Encoding.UTF8.GetBytes(codeVerifier));
            var codeChallenge = Convert.ToBase64String(challengeBytes)
                                    .TrimEnd('=')
                                    .Replace('+', '-')
                                    .Replace('/', '_');

            sha256.Dispose();
            var request=new RedirectToken();

            var path = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "config.yaml");
            using (var reader = new StreamReader(path))
            {
                var yamlStream = new YamlStream();
                yamlStream.Load(reader);

                // Accede a las secciones y valores que necesitas
                var rootNode = (YamlMappingNode)yamlStream.Documents[0].RootNode;
                var generateTokenNode = (YamlMappingNode)rootNode.Children[new YamlScalarNode("GenerateToken")];

                var redirect = (YamlMappingNode)generateTokenNode.Children[new YamlScalarNode("Redirection")];
                var clientId = redirect.Children[new YamlScalarNode("clientId")].ToString();
                var state = redirect.Children[new YamlScalarNode("state")].ToString();
                var redirectUri = redirect.Children[new YamlScalarNode("redirectUri")].ToString();

                request.clientId = clientId;
                request.state = state;
                request.redirectUri =  HttpUtility.UrlEncode(redirectUri);

            }
            string authUrl =
          $"https://www.fitbit.com/oauth2/authorize?response_type=code&client_id={request.clientId}&scope={request.scope}&code_challenge={codeChallenge}&code_challenge_method=S256&state={request.state}&redirect_uri={request.redirectUri}";

            return Redirect(authUrl);
        }

        public async Task<ActionResult> callback(string code, string state)
        {
            var request = new RedirectToken();

            var path = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "config.yaml");
            using (var reader = new StreamReader(path))
            {
                var yamlStream = new YamlStream();
                yamlStream.Load(reader);

                // Accede a las secciones y valores que necesitas
                var rootNode = (YamlMappingNode)yamlStream.Documents[0].RootNode;
                var generateTokenNode = (YamlMappingNode)rootNode.Children[new YamlScalarNode("GenerateToken")];

                var redirect = (YamlMappingNode)generateTokenNode.Children[new YamlScalarNode("Redirection")];
                var clientId = redirect.Children[new YamlScalarNode("clientId")].ToString();
                var redirectUri = redirect.Children[new YamlScalarNode("redirectUri")].ToString();

                var AccessToken = (YamlMappingNode)generateTokenNode.Children[new YamlScalarNode("AccessToken")];
                var clientSecret = AccessToken.Children[new YamlScalarNode("clientSecret")].ToString();

                request.clientId = clientId;
                request.redirectUri = HttpUtility.UrlEncode(redirectUri);
                request.clientSecret = clientSecret;

            }
             HttpClient client = new HttpClient();
            var authHeaderValue = Convert.ToBase64String(
                Encoding.UTF8.GetBytes($"{request.clientId}:{request.clientSecret}"));
            client.DefaultRequestHeaders.Authorization =
                new AuthenticationHeaderValue("Basic", authHeaderValue);

            var codeVerifier = Session["codeVerifier"].ToString();

            var tokenRequestParameters = new Dictionary<string, string> {
        { "grant_type", "authorization_code" },
        { "code", code },
        { "redirect_uri", request.redirectUri },
        { "code_verifier", codeVerifier }
      };

            var peticion = new HttpRequestMessage(
                HttpMethod.Post, "https://api.fitbit.com/oauth2/token")
            {
                Content = new FormUrlEncodedContent(tokenRequestParameters)
            };

            var response = await client.SendAsync(peticion);
            var responseString = await response.Content.ReadAsStringAsync();
            client.Dispose();
            if (response.IsSuccessStatusCode)
            {
                // Maneja la respuesta exitosa aquí...
            }
            else
            {
                var errorContent = await response.Content.ReadAsStringAsync();
                // Log o maneja el contenido del error para entender por qué la
                // solicitud falló.
            }

            return View();
        }

        public ActionResult Contact()
        {
            ViewBag.Message = "Your contact page.";

            return View();
        }
    }
}