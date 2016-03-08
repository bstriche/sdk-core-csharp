using System;
using System.Text;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Web;
using System.Security.Cryptography;

namespace MasterCard.Core
{
	public static class Util
	{

		static readonly string[] URIRFC3986CHARSTOESCAPE = new[] { "!", "*", "'", "(", ")" };
		static UTF8Encoding encoder = new UTF8Encoding();


		/// <summary>
		/// Normalized the request URL by truncading any parts which are not part of the base url, i.e. the request parameters.
		/// </summary>
		/// <returns>A string representing normalised request url</returns>
		public static String NormalizeUrl(String requestUrl) {
			Uri myUri = new Uri(requestUrl);
			return String.Format("{0}{1}{2}{3}", myUri.Scheme,  Uri.SchemeDelimiter, myUri.Authority, myUri.AbsolutePath);
		}



		/// <summary>
		/// Normalized the request parameters by generating a string which represent all the url request parameters and oauth request parameters.
		/// </summary>
		/// <returns>A string representing the normalized parameters</returns>
		public static String NormalizeParameters(String requestUrl, SortedDictionary<String, String> requestParameters) {

			if (requestUrl.IndexOf ('?') > 0) {

				NameValueCollection nameValueCollecion = HttpUtility.ParseQueryString (requestUrl.Substring (requestUrl.IndexOf ('?')));

				foreach (String key in nameValueCollecion) {
					foreach (String value in nameValueCollecion.GetValues(key)) {
						requestParameters.Add (key, value);
					}
				}
			}

			var paramString1 = new StringBuilder();

			foreach(KeyValuePair<string, string> entry in requestParameters)
			{
				// do something with entry.Value or entry.Key
				if (paramString1.Length > 0) {
					paramString1.Append ("&");
				}
				paramString1.Append(uriRfc3986((String)entry.Key)).Append("=").Append(uriRfc3986((String)entry.Value));
			}

			return paramString1.ToString();
		}



		/// <summary>
		/// This method encodes the string using convention UriRfc3986CharsToEscape
		/// </summary>
		/// <param name="stringToEncode"></param>
		/// <returns></returns>
		public static String uriRfc3986(String stringToEncode) {
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

	}
}

