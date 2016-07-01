#r "System.IdentityModel"
#r "System.identitymodel.services"


#r "Newtonsoft.Json"
using System.Net;
using System.IdentityModel.Tokens;
using System.Security.Claims;
using Microsoft.IdentityModel.Protocols;


using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;


public static async Task<HttpResponseMessage> Run(HttpRequestMessage req, TraceWriter log)
{
    log.Info($"C2# HTTP trigger function processed a request. RequestUri={req.RequestUri}");

    // parse query parameter
    string token = req.GetQueryNameValuePairs()
        .FirstOrDefault(q => string.Compare(q.Key, "token", true) == 0)
        .Value;

    // Get request body
    dynamic data = await req.Content.ReadAsAsync<object>();
   // var keys = data?.jwk.keys;
    // Set name to query string or body data
    token = token ?? data?.token;
    var jwk = data.jwk;
    var keys = jwk.keys;
    
    string k = jwk.ToString(Newtonsoft.Json.Formatting.None);
    log.Info(k);
    var tokenHandler = new JwtSecurityTokenHandler();

    

    ClaimsPrincipal principal = null;

    var keyset = new JsonWebKeySet(k);

    var tokens = keyset.GetSigningTokens().LastOrDefault();
    
     var validationParameters = new TokenValidationParameters()
            {
                IssuerSigningToken = tokens,
                ValidIssuer = "https://login.microsoftonline.com/0a7110e8-b2aa-48cf-844f-c43e3533288d/v2.0/",
                ValidateIssuer = true,

            };
            
    string failReason = null;
    
    
    try
            {
                SecurityToken validated = null;
                principal = tokenHandler.ValidateToken(token, validationParameters, out validated);
            }
            catch (SecurityTokenValidationException ex)
            {
                failReason = string.Format("2SecurityTokenValidationException: {0}", ex.Message);
            }
            catch (ArgumentException ex)
            {
                failReason = string.Format("ArgumentException: {0}", ex.Message);
            }
            catch (Exception ex)
            {
                failReason = string.Format("Exception: {0}", ex.Message);
            }

    
    return token == null
        ? req.CreateResponse(HttpStatusCode.BadRequest, "Please pass a token on the query string or in the request body")
        : req.CreateResponse(HttpStatusCode.OK, failReason == null ? "OK!" : failReason);
}