using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Security.Cryptography;
using System.Web;
using System.Text;


namespace MasterCard.Core.Security.OAuth
{
	/// <summary>
	/// O auth util, which generates the Oauth signature for a request.
	/// </summary>
	internal static class OAuthUtil
	{
		

		static Random random = new Random();
		static readonly string VALID_CHAR = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";


		/// <summary>
		/// Generates a 17 character Nonce
		/// </summary>
		/// <returns>A string representing the Nonce</returns>
		private static String GetNonce()
		{
			int length = 17;
			var nonceString = new StringBuilder();
			for (int i = 0; i < length; i++)
			{
				nonceString.Append(VALID_CHAR[random.Next(0, VALID_CHAR.Length - 1)]);
			}
			return nonceString.ToString();
		}

		/// <summary>
		/// Generates a timestamp
		/// </summary>
		/// <returns>A string representing the timestamp in milliseconds in GMT</returns>
		static String GetTimestamp()
		{
			long ticks = DateTime.UtcNow.Ticks - DateTime.Parse("01/01/1970 00:00:00").Ticks;
			ticks /= 10000000; //Convert windows ticks to seconds
			return ticks.ToString();
		}

		/// <summary>
		/// Generates BaseString which is used in the OAuth process before the signature is generated
		/// </summary>
		/// <returns>A string representing the OAuth SignatureBaseString</returns>
		public static String GetBaseString(String requestUrl, String httpMethod, SortedDictionary<String, String> baseParameters) {
			return Util.UriEncode(httpMethod.ToUpper()) + "&" + Util.UriEncode(Util.NormalizeUrl(requestUrl)) + "&" + Util.UriEncode(Util.NormalizeParameters(requestUrl, baseParameters));
		}

		/// <summary>
		/// Method to signthe signature base string. 
		/// </summary>
		/// <param name="baseString"></param>
		/// <param name="KeyStore"></param>
		/// <returns></returns>
		public static string RsaSign(string baseString)
		{
			return ApiConfig.getAuthentication ().SignMessage (baseString);
		}




		/// <summary>
		/// This method generates an OAuth signature
		/// </summary>
		/// <param name="URL"></param>
		/// <param name="method"></param>
		/// <param name="body"></param>
		/// <returns></returns>
		public static String GenerateSignature(String URL, String method, String body, String clientId, AsymmetricAlgorithm privateKey )
		{
			OAuthParameters oAuthParameters = new OAuthParameters();
			oAuthParameters.setOAuthConsumerKey(clientId);
			oAuthParameters.setOAuthNonce(OAuthUtil.GetNonce());
			oAuthParameters.setOAuthTimestamp(OAuthUtil.GetTimestamp());
			oAuthParameters.setOAuthSignatureMethod("RSA-SHA1");
		

			if (!string.IsNullOrEmpty (body)) {
				Console.WriteLine (body);
				String encodedHash = Util.Base64Encode (Util.Sha1Encode (body));
				Console.WriteLine (encodedHash);
				oAuthParameters.setOAuthBodyHash (encodedHash);
			}


			String baseString = OAuthUtil.GetBaseString(URL, method, oAuthParameters.getBaseParameters());
			String signature = RsaSign(baseString);
			oAuthParameters.setOAuthSignature(signature);

			StringBuilder builder = new StringBuilder();
			foreach(KeyValuePair<string, string> entry in oAuthParameters.getBaseParameters())
			{
				if (builder.Length == 0) {
					builder.Append (OAuthParameters.OAUTH_KEY).Append (" ");
				} else {
					builder.Append (",");
				}
				builder.Append (Util.UriEncode(entry.Key)).Append ("=\"").Append (Util.UriEncode (entry.Value)).Append ("\"");
			}

			Console.WriteLine(builder.ToString());
			return builder.ToString();
		}
			
	}
}

