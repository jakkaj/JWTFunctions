#r "System.IdentityModel"
#r "System.identitymodel.services"


#r "Newtonsoft.Json"
using System.Net;
using System.Net.Http;
using System.IdentityModel.Tokens;
using System.Security.Claims;
using Microsoft.IdentityModel.Protocols;


using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using ExtensionGoo.Standard.Extensions;
using System.Text;

public static async Task<HttpResponseMessage> Run(HttpRequestMessage req, TraceWriter log)
{
    log.Info($"C2# HTTP trigger function processed a request. RequestUri={req.RequestUri}");

    // parse query parameter
  

   
    // Get request body
    dynamic data = await req.Content.ReadAsAsync<object>();
   
    string token = data?.token;
    string rsaKey = data?.rsaKey;
    string audience = data?.audience;
    string issuer = data?.issuer;
    
    if(token == null){
        return req.CreateResponse(HttpStatusCode.BadRequest, "Please pass a token on the query string or in the request body");
    }
    
    var result = ValidateWithRsaKey(token, rsaKey, issuer, audience); 

    var response = req.CreateResponse(HttpStatusCode.OK);
    
    response.Content = new StringContent(result.Serialise(), System.Text.Encoding.UTF8, "application/json");
    
    return response;
    
}


 public static TokenResult ValidateWithRsaKey(string token, string publicKey, string issuer, string audience)
        {
            var keyExtracted = Encoding.UTF8.GetString(Convert.FromBase64String(publicKey));

            var publicOnly = new RSACryptoServiceProvider();
            publicOnly.FromXmlString(keyExtracted);

            var validationParameters = new TokenValidationParameters
            {
                IssuerSigningToken = new RsaSecurityToken(publicOnly),
                ValidIssuer = issuer,
                ValidateIssuer = true,
                ValidAudience = audience,
                AudienceValidator =
                    (audiences, securityToken, parameters) =>
                        parameters.ValidAudience == null || audiences.Contains(parameters.ValidAudience)
            };

            return Validate(token, validationParameters);
        }

        public static TokenResult Validate(string token, TokenValidationParameters validationParameters)
        {
            var tokenHandler = new JwtSecurityTokenHandler();

            string failReason = null;

            var tokenResult = new TokenResult();

            try
            {
                SecurityToken validated = null;
                var principal = tokenHandler.ValidateToken(token, validationParameters, out validated);

                if (principal != null)
                {
                    tokenResult.Claims = _getClaims(principal);
                    tokenResult.IsValid = true;
                }
            }
            catch (SecurityTokenValidationException ex)
            {
                failReason = $"SecurityTokenValidationException: {ex.Message}";
            }
            catch (ArgumentException ex)
            {
                failReason = $"ArgumentException: {ex.Message}";
            }
            catch (Exception ex)
            {
                failReason = $"Exception: {ex.Message}";
            }

            if (failReason == null) return tokenResult;

            tokenResult.IsValid = false;
            tokenResult.FailReason = failReason;

            return tokenResult;
        }


        private static Dictionary<string, string> _getClaims(ClaimsPrincipal principal)
        {
            var dict = new Dictionary<string, string>();
            foreach (var c in principal.Claims.Where(c => !dict.ContainsKey(c.Type)))
            {
                dict.Add(c.Type, c.Value);
            }

            return dict;
        }
        
        public class TokenResult
        {
            public bool IsValid { get; set; }
            public string FailReason { get; set; }
            public Dictionary<string, string> Claims { get; set; }
        }
