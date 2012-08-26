using System;
using System.Collections.Generic;
using System.Text;
using System.Security.Cryptography.X509Certificates;
using System.Net.Security;
using System.IO;
using System.Net;
using OAuth;
using System.Web;
using QueryParameter = System.Collections.Generic.KeyValuePair<string, string>;

namespace OAuth
{
    public struct OAuthToken
    {
        public String Token;
        public String Secret;
    }

    public class OAuthClient
    {
        public String ConsumerKey = String.Empty;
        public String ConsumerSecret = String.Empty;
        public OAuthToken Token = new OAuthToken() { Token = String.Empty, Secret = String.Empty };
        protected OAuthBase oAuthBase;
        protected string unreservedChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.~";
        
        public OAuthClient(String consumerKey, String consumerSecret)
        {
            ConsumerKey = consumerKey;
            ConsumerSecret = consumerSecret;

            ServicePointManager.ServerCertificateValidationCallback =
                   ValidateServerCertficate;
            oAuthBase = new OAuthBase();
        }


        protected WebResponse rawRequest(String method, Uri uri, List<QueryParameter> data)
        {
            string nonce = oAuthBase.GenerateNonce();
            string timeStamp = oAuthBase.GenerateTimeStamp();
            string parameters;
            string normalizedUrl;
            Uri signingUri = new Uri(uri.ToString());
            byte[] postData = null;

            if (method == "POST" || method == "PUT")
            {
                String paramString = "";
                foreach (QueryParameter p in data)
                {
                    paramString += UrlEncode(p.Key) + "=" + UrlEncode(p.Value) + "&";
                }
                paramString = paramString.Remove(paramString.Length - 1);
                if (uri.ToString().Contains("?"))
                    signingUri = new Uri(uri.ToString() + "&" + paramString);
                else
                    signingUri = new Uri(uri.ToString() + "?" + paramString);

                postData = Encoding.ASCII.GetBytes(paramString);
            }

            string signature = oAuthBase.GenerateSignature(signingUri, ConsumerKey, ConsumerSecret,
                Token.Token, Token.Secret, method, timeStamp, nonce, OAuthBase.SignatureTypes.HMACSHA1,
                out normalizedUrl, out parameters);

            signature = HttpUtility.UrlEncode(signature);

            StringBuilder requestUri = new StringBuilder(uri.ToString());
            if (uri.ToString().Contains("?"))
                requestUri.Append("&");
            else
                requestUri.Append("?");
            requestUri.AppendFormat("oauth_consumer_key={0}&", ConsumerKey);
            requestUri.AppendFormat("oauth_nonce={0}&", nonce);
            requestUri.AppendFormat("oauth_timestamp={0}&", timeStamp);
            requestUri.AppendFormat("oauth_signature_method={0}&", "HMAC-SHA1");
            requestUri.AppendFormat("oauth_version={0}&", "1.0");
            requestUri.AppendFormat("oauth_signature={0}", signature);
            if (Token.Token != String.Empty)
                requestUri.AppendFormat("&oauth_token={0}", Token.Token);

            var request = (HttpWebRequest)WebRequest.Create(new Uri(requestUri.ToString()));
            request.Method = method;

            if (postData != null)
            {
                request.ContentType = "application/x-www-form-urlencoded";
                request.ContentLength = postData.Length;
                Stream dataStream = request.GetRequestStream();
                dataStream.Write(postData, 0, postData.Length);
                dataStream.Close();
            }
            
            var response = request.GetResponse();
            return response;
        }

        public String Request(String method, Uri uri, List<QueryParameter> data)
        {
            var response = rawRequest(method, uri, data);
            var respString = new StreamReader(response.GetResponseStream()).ReadToEnd();
            return respString;
        }

        public String Get(Uri uri)
        {
            return Request("GET", uri, null);
        }

        public String Post(Uri uri, List<QueryParameter> data)
        {
            return Request("POST", uri, data);
        }

        public OAuthToken GetToken(Uri uri) 
        {
            var tokenString = Get(uri);
            var parts = tokenString.Split('&');
            var tokenKey = parts[1].Substring(parts[1].IndexOf('=') + 1);
            var tokenSecret = parts[0].Substring(parts[0].IndexOf('=') + 1);
            var token = new OAuthToken() { Token = tokenKey, Secret = tokenSecret };
            return token;
        }


        /// <summary>
        /// This is a different Url Encode implementation since the default .NET one outputs the percent encoding in lower case.
        /// While this is not a problem with the percent encoding spec, it is used in upper case throughout OAuth
        /// </summary>
        /// <param name="value">The value to Url encode</param>
        /// <returns>Returns a Url encoded string</returns>
        protected string UrlEncode(string value)
        {
            StringBuilder result = new StringBuilder();

            foreach (char symbol in value)
            {
                if (unreservedChars.IndexOf(symbol) != -1)
                {
                    result.Append(symbol);
                }
                else
                {
                    result.Append('%' + String.Format("{0:X2}", (int)symbol));
                }
            }

            return result.ToString();
        }


        /// <summary>
        /// Validates the SSL server certificate.
        /// </summary>
        /// <param name="sender">An object that contains state information for this
        /// validation.</param>
        /// <param name="cert">The certificate used to authenticate the remote party.</param>
        /// <param name="chain">The chain of certificate authorities associated with the
        /// remote certificate.</param>
        /// <param name="sslPolicyErrors">One or more errors associated with the remote
        /// certificate.</param>
        /// <returns>Returns a boolean value that determines whether the specified
        /// certificate is accepted for authentication; true to accept or false to
        /// reject.</returns>
        private static bool ValidateServerCertficate(
                object sender,
                X509Certificate cert,
                X509Chain chain,
                SslPolicyErrors sslPolicyErrors)
        {
            return true;
        }
    }
}
