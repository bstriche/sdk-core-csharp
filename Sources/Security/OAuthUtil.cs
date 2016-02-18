using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.IO;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Security;
using System.Web;


namespace MasterCard.SDK.Core.Security
{
	/// <summary>
	/// O auth util, which generates the Oauth signature for a request.
	/// </summary>
	internal class OAuthUtil
	{
		private static readonly string VALID_CHAR = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
		private static readonly string[] URIRFC3986CHARSTOESCAPE = new[] { "!", "*", "'", "(", ")" };

		private static Random random = new Random();
		private static UTF8Encoding encoder = new UTF8Encoding();

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
		private static String GetTimestamp()
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
			return UriEncode(httpMethod.ToUpper()) + "&" + UriEncode(normalizeUrl(requestUrl)) + "&" + UriEncode(normalizeParameters(requestUrl, baseParameters));
		}

		/// <summary>
		/// Normalized the request URL by truncading any parts which are not part of the base url, i.e. the request parameters.
		/// </summary>
		/// <returns>A string representing normalised request url</returns>
		private static String normalizeUrl(String requestUrl) {
			Uri myUri = new Uri(requestUrl);
			return String.Format("{0}{1}{2}{3}", myUri.Scheme,  Uri.SchemeDelimiter, myUri.Authority, myUri.AbsolutePath);
		}



		/// <summary>
		/// Normalized the request parameters by generating a string which represent all the url request parameters and oauth request parameters.
		/// </summary>
		/// <returns>A string representing the normalized parameters</returns>
		private static String normalizeParameters(String requestUrl, SortedDictionary<String, String> requestParameters) {

			if (requestUrl.IndexOf ('?') > 0) {
				
				NameValueCollection nameValueCollecion = HttpUtility.ParseQueryString (requestUrl.Substring (requestUrl.IndexOf ('?')));

				foreach (String key in nameValueCollecion) {
					foreach (String value in nameValueCollecion.GetValues(key)) {
						requestParameters.Add (key, value);
					}
				}
			}

			StringBuilder paramString1 = new StringBuilder();

			foreach(KeyValuePair<string, string> entry in requestParameters)
			{
				// do something with entry.Value or entry.Key
				if (paramString1.Length > 0) {
					paramString1.Append ("&");
				}
				paramString1.Append(UriEncode((String)entry.Key)).Append("=").Append(UriEncode((String)entry.Value));
			}

			return paramString1.ToString();
		}




		/// <summary>
		/// Method to signthe signature base string. 
		/// </summary>
		/// <param name="baseString"></param>
		/// <param name="KeyStore"></param>
		/// <returns></returns>
		public static string RsaSign(string baseString, AsymmetricAlgorithm KeyStore)
		{
			byte[] baseStringBytes = encoder.GetBytes(baseString);

			RSACryptoServiceProvider csp = (RSACryptoServiceProvider)KeyStore;
			// Hash the data
			SHA1 sha1= new SHA1CryptoServiceProvider();
			byte[] hash = sha1.ComputeHash(baseStringBytes);

			// Sign the hash
			byte[] SignedHashValue = csp.SignHash(hash, CryptoConfig.MapNameToOID("SHA1"));
			return Convert.ToBase64String(SignedHashValue);
		}


		/// <summary>
		/// This method encodes the string using convention UriRfc3986CharsToEscape
		/// </summary>
		/// <param name="stringToEncode"></param>
		/// <returns></returns>
		private static String UriEncode(String stringToEncode) {
			StringBuilder escaped = new StringBuilder(Uri.EscapeDataString(stringToEncode));
			for (int i = 0; i < URIRFC3986CHARSTOESCAPE.Length; i++)
			{
				escaped.Replace(URIRFC3986CHARSTOESCAPE[i], Uri.HexEscape(URIRFC3986CHARSTOESCAPE[i][0]));
			}
			return escaped.ToString();
		}


		/// <summary>
		/// This method encodes a string using a SHA1 algorithm
		/// </summary>
		/// <param name="input"></param>
		/// <returns></returns>
		public static byte[] Sha1Encode(String input)
		{
			SHA1 sha1= new SHA1CryptoServiceProvider();
			byte[] inputBytes = encoder.GetBytes (input);
			byte[] hashBytes = sha1.ComputeHash(inputBytes);
			return hashBytes;
		}

		/// <summary>
		/// This method encodes the string using BASE64 encoding
		/// </summary>
		/// <param name="textBytes"></param>
		/// <returns></returns>
		public static string Base64Encode(byte[] textBytes) {
			return System.Convert.ToBase64String(textBytes);
		}


		/// <summary>
		/// This method generates an OAuth signature
		/// </summary>
		/// <param name="URL"></param>
		/// <param name="method"></param>
		/// <param name="body"></param>
		/// <returns></returns>
		public static String GenerateSignature(String URL, String method, String body)
		{
			OAuthParameters oAuthParameters = new OAuthParameters();
			oAuthParameters.setOAuthConsumerKey(MasterCardApiConfig.getClientId());
			oAuthParameters.setOAuthNonce(OAuthUtil.GetNonce());
			oAuthParameters.setOAuthTimestamp(OAuthUtil.GetTimestamp());
			oAuthParameters.setOAuthSignatureMethod("RSA-SHA1");
		

			if (body != null && body.Length > 0) {
				String encodedHash = Base64Encode(Sha1Encode(body));
				oAuthParameters.setOAuthBodyHash(encodedHash);
			}


			String baseString = OAuthUtil.GetBaseString(URL, method, oAuthParameters.getBaseParameters());
			String signature = RsaSign(baseString, MasterCardApiConfig.getPrivateKey());
			oAuthParameters.setOAuthSignature(signature);

			StringBuilder builder = new StringBuilder();
			foreach(KeyValuePair<string, string> entry in oAuthParameters.getBaseParameters())
			{
				if (builder.Length == 0) {
					builder.Append (OAuthParameters.OAUTH_KEY).Append (" ");
				} else {
					builder.Append (",");
				}
				builder.Append (entry.Key).Append ("=\"").Append (UriEncode (entry.Value)).Append ("\"");
			}
			return builder.ToString();
		}
			
	}
}

