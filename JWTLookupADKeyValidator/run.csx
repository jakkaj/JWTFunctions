#r "System.IdentityModel"
#r "System.identitymodel.services"


#r "Newtonsoft.Json"
using System.Net;
using System.IdentityModel.Tokens;
using System.Security.Claims;
using Microsoft.IdentityModel.Protocols;


using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using ExtensionGoo.Standard.Extensions;

public static async Task<HttpResponseMessage> Run(HttpRequestMessage req, TraceWriter log)
{
    log.Info($"C2# HTTP trigger function processed a request. RequestUri={req.RequestUri}");

    // parse query parameter
    string token = req.GetQueryNameValuePairs()
        .FirstOrDefault(q => string.Compare(q.Key, "token", true) == 0)
        .Value;

    string adConfigName = req.GetQueryNameValuePairs()
        .FirstOrDefault(q => string.Compare(q.Key, "config", true) == 0)
        .Value;

    // Get request body
    dynamic data = await req.Content.ReadAsAsync<object>();
   // var keys = data?.jwk.keys;
    // Set name to query string or body data
    token = token ?? data?.token;
    adConfigName = adConfigName ?? data?.adConfigName;
    
var url =
                $"https://login.microsoftonline.com/jordob2c.onmicrosoft.com/v2.0/.well-known/openid-configuration?p={adConfigName}";

            var result = await url.GetAndParse<OpenIdDiscoveryObject>();

            var keysUrl = result.jwks_uri;

            var keys = await keysUrl.GetRaw();

            var failReason = _validate(token, keys);
    
    return token == null
        ? req.CreateResponse(HttpStatusCode.BadRequest, "Please pass a token on the query string or in the request body")
        : req.CreateResponse(HttpStatusCode.OK, failReason == null ? "OK!" : failReason);
}


 private static string _validate(string token, string key)
        {
           
            var tokenHandler = new JwtSecurityTokenHandler();

            string failReason = null;

            ClaimsPrincipal principal = null;

            var keyset = new JsonWebKeySet(key);

            var tokens = keyset.GetSigningTokens().LastOrDefault();
         
             
            var validationParameters = new TokenValidationParameters()
            {
                IssuerSigningToken = tokens,
                ValidIssuer = "https://login.microsoftonline.com/0a7110e8-b2aa-48cf-844f-c43e3533288d/v2.0/",
                ValidateIssuer = true,

            };
            var f = Newtonsoft.Json.Formatting.None;
            validationParameters.AudienceValidator =
                delegate (IEnumerable<string> audiences, SecurityToken securityToken,
                    TokenValidationParameters parameters)
                {
                    var audience = "Aud";
                    if (parameters.ValidAudience != null)
                    {
                        return parameters.ValidAudience == audience;
                    }
                    return true;
                };

            failReason = null;

            try
            {
                SecurityToken validated = null;
                principal = tokenHandler.ValidateToken(token, validationParameters, out validated);
            }
            catch (SecurityTokenValidationException ex)
            {
                failReason = string.Format("SecurityTokenValidationException: {0}", ex.Message);
            }
            catch (ArgumentException ex)
            {
                failReason = string.Format("ArgumentException: {0}", ex.Message);
            }
            catch (Exception ex)
            {
                failReason = string.Format("Exception: {0}", ex.Message);
            }


            return failReason;
        }


        public class OpenIdDiscoveryObject
        {
            public string issuer { get; set; }
            public string authorization_endpoint { get; set; }
            public string token_endpoint { get; set; }
            public string end_session_endpoint { get; set; }
            public string jwks_uri { get; set; }
            public List<string> response_modes_supported { get; set; }
            public List<string> response_types_supported { get; set; }
            public List<string> scopes_supported { get; set; }
            public List<string> subject_types_supported { get; set; }
            public List<string> id_token_signing_alg_values_supported { get; set; }
            public List<string> token_endpoint_auth_methods_supported { get; set; }
            public List<string> claims_supported { get; set; }
        }


 