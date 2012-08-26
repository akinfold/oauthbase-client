oauthbase-client
================

Simple HTTP client with OAuth support based on OAuthBase.cs with some fixes on sending POST data.


example
=======

Simple console application example:


    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Net;
    using System.Net.Security;
    using System.Security.Cryptography.X509Certificates;
    using System.Text;
    using OAuth;
    using System.Web;
    using QueryParameter = System.Collections.Generic.KeyValuePair<string, string>;
    
    namespace OAuthTest
    {
        class Program
        {
            static String consumerKey = "your consumer key";
            static String consumerSecret = "your consumer secret";
            static Uri requestTokenUri = new Uri("https://api.someservice.net/oauth/request_token/");
            static Uri accessTokenUri = new Uri("https://api.someservice.net/oauth/access_token/");
        
            static void Main(string[] args)
            {
                OAuthClient c = new OAuthClient(consumerKey, consumerSecret);
                
                // Get request token using consumer key and secret.
                var requestToken = c.GetToken(requestTokenUri);
                c.Token = requestToken;
                Console.WriteLine("Request token/secret: " + requestToken.Token + " / " + requestToken.Secret);
                
                // Here user should authorize your request token in someservice.net and bring to us verification code.
                Console.Write("Verifier: ");
                var verifier = Console.ReadLine();
                
                // Exchange request token to access token using verification code.
                var accessToken = c.GetToken(accessTokenUri + "?oauth_verifier=" + verifier);
                c.Token = accessToken;
                Console.WriteLine("Access token/secret: "accessToken.Token + " / " + accessToken.Secret);
                
                // Now we can do requests to get resources from service.
                var resources = c.Get(new Uri("https://api.someservice.net/v2/resources.json"));
                Console.WriteLine(resources);
                Console.ReadLine();
            }
        }
    }
