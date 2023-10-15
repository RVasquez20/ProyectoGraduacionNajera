using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Web;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Caching.Distributed;

namespace WS_NajeraFitbit.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class TokenController : ControllerBase
    {
        private readonly IHttpClientFactory _http;
        private readonly IConfiguration _configuration;
        private readonly IDistributedCache _cache;
        public TokenController(IHttpClientFactory http, IConfiguration configuration, IDistributedCache cache)
        {
            this._http = http;
            this._configuration = configuration;
            _cache = cache;
        }
        [HttpGet("Authorize")]
        public async Task<IActionResult> Authorize()
        {
            string clientId = _configuration["Fitbit:clientId"];
            string scope = "activity+cardio_fitness+electrocardiogram+heartrate+location+nutrition+oxygen_saturation+profile+respiratory_rate+settings+sleep+social+temperature+weight";
            string state = _configuration["Fitbit:state"];
            string redirectUri = HttpUtility.UrlEncode(_configuration["Fitbit:redirectUri"]);
            // Generar el code_verifier
            var rng = new RNGCryptoServiceProvider();
            var bytes = new byte[32];
            rng.GetBytes(bytes);
            var codeVerifier = Convert.ToBase64String(bytes)
                .TrimEnd('=')
                .Replace('+', '-')
                .Replace('/', '_');
            // Generar el code_challenge
            using var sha256 = SHA256.Create();
            var challengeBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(codeVerifier));
            var codeChallenge = Convert.ToBase64String(challengeBytes)
                .TrimEnd('=')
                .Replace('+', '-')
                .Replace('/', '_');
            var cacheKey = $"{state}";
            _cache.SetString(cacheKey, codeVerifier,new DistributedCacheEntryOptions
            {
                AbsoluteExpirationRelativeToNow = TimeSpan.FromMinutes(10)
            });
            string authUrl = $"https://www.fitbit.com/oauth2/authorize?response_type=code&client_id={clientId}&scope={scope}&code_challenge={codeChallenge}&code_challenge_method=S256&state={state}&redirect_uri={redirectUri}";

           

            return Ok(authUrl);
        }
        [HttpGet("callback")]
        public async Task<ActionResult> callback(string code, string state)
        {
            string clientId = _configuration["Fitbit:clientId"];
            string clientSecret = _configuration["Fitbit:clientSecret"];
            string redirectUri = _configuration["Fitbit:redirectUri"];
            string key = _configuration["Fitbit:state"];

            // Crear el cliente usando la fábrica con el nombre "Base"
            var client = _http.CreateClient("Base");

            // Obtener el code_verifier almacenado
            var codeVerifier = _cache.GetString(key);
            if (string.IsNullOrEmpty(codeVerifier))
            {
                return BadRequest("Code verifier not found.");
            }

            var authHeaderValue = Convert.ToBase64String(Encoding.UTF8.GetBytes($"{clientId}:{clientSecret}"));
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Basic", authHeaderValue);

            var tokenRequestParameters = new Dictionary<string, string>
    {
        {"grant_type", "authorization_code"},
        {"code", code},
        {"redirect_uri", redirectUri},
        {"code_verifier", codeVerifier}
    };

            // Solo especifica el endpoint relativo ya que la dirección base ya está configurada
            var request = new HttpRequestMessage(HttpMethod.Post, "/oauth2/token")
            {
                Content = new FormUrlEncodedContent(tokenRequestParameters)
            };

            var response = await client.SendAsync(request);
            var responseString = await response.Content.ReadAsStringAsync();

            if (response.IsSuccessStatusCode)
            {
                return Ok(responseString);
            }
            else
            {
                return BadRequest($"Error: {responseString}");
            }
        }

        [HttpPost("RefreshToken")]
        public async Task<IActionResult> RefreshToken(string refreshToken)
        {
            string clientId = _configuration["Fitbit:clientId"];
            string clientSecret = _configuration["Fitbit:clientSecret"];

            var client = _http.CreateClient();

            var authHeaderValue = Convert.ToBase64String(Encoding.UTF8.GetBytes($"{clientId}:{clientSecret}"));
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Basic", authHeaderValue);

            var tokenRequestParameters = new Dictionary<string, string>
    {
        {"grant_type", "refresh_token"},
        {"refresh_token", refreshToken}
    };

            var request = new HttpRequestMessage(HttpMethod.Post, "https://api.fitbit.com/oauth2/token")
            {
                Content = new FormUrlEncodedContent(tokenRequestParameters)
            };

            var response = await client.SendAsync(request);
            var responseString = await response.Content.ReadAsStringAsync();

            if (response.IsSuccessStatusCode)
            {
                return Ok(responseString);
            }
            else
            {
                return BadRequest($"Error: {responseString}");
            }
        }

    }
}
