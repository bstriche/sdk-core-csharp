/*
 * Copyright 2016 MasterCard International.
 *
 * Redistribution and use in source and binary forms, with or without modification, are 
 * permitted provided that the following conditions are met:
 *
 * Redistributions of source code must retain the above copyright notice, this list of 
 * conditions and the following disclaimer.
 * Redistributions in binary form must reproduce the above copyright notice, this list of 
 * conditions and the following disclaimer in the documentation and/or other materials 
 * provided with the distribution.
 * Neither the name of the MasterCard International Incorporated nor the names of its 
 * contributors may be used to endorse or promote products derived from this software 
 * without specific prior written permission.
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY 
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES 
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT 
 * SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, 
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
 * TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; 
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER 
 * IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING 
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF 
 * SUCH DAMAGE.
 *
 */

using System;
using System.Text;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Web;
using System.Security.Cryptography;
using System.Text.RegularExpressions;

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
        /// return the current assembly path
        /// </summary>
        /// <returns></returns>
        public static String GetCurrenyAssemblyPath()
        {
            String tmpPath = System.IO.Path.GetDirectoryName(System.Reflection.Assembly.GetExecutingAssembly().CodeBase);
            tmpPath = tmpPath.Remove(0, "file:\\".Length);
            return tmpPath;
        }


		/// <summary>
		/// Returns a sub map by selecting the map items contained in the inList
		/// </summary>
		/// <returns>The map.</returns>
		/// <param name="inputMap">Input map. </param>
		/// <param name="inList">Items to select.</param>
		public static IDictionary<String, Object> SubMap(IDictionary<String, Object> inputMap, List<String> inList) {

			IDictionary<String,Object> subMap = new Dictionary<String, Object> ();
			foreach(String key in inList)
			{
				if (inputMap.ContainsKey (key)) {
					subMap.Add(key, inputMap [key]); 
					inputMap.Remove (key);
				}
			}

			return subMap;
		}


		/// <summary>
		/// Gets the replaced path.
		/// </summary>
		/// <returns>The replaced path.</returns>
		/// <param name="path">Path which contains {variable_id}</param>
		/// <param name="inputMap">Input map which contains the key and value for {variable_id}</param>
		public static string GetReplacedPath(String path, IDictionary<String, Object> inputMap) {

			String result = (String) path.Clone ();

			MatchCollection matches = Regex.Matches(path, @"{(.*?)}");

			// Here we check the Match instance.
			foreach (Match match in matches)
			{
				GroupCollection groups = match.Groups;
				string key = groups[1].Value;
				if (inputMap.ContainsKey (key)) {
					//add to the path
					Object value = "";
					inputMap.TryGetValue (key, out value);

					//arizzini: replacing the value in the path
					result = result.Replace ("{" + key + "}", value.ToString ());

					//arizzini: removing the value from the input map
					inputMap.Remove (key);
				} else {
					throw new System.ArgumentException ("Error, path paramer: '" + key + "' expected but not found in input map");
				}
			}

			return result;
		
		}



		/// <summary>
		/// Normalized the request parameters by generating a string which represent all the url request parameters and oauth request parameters.
		/// </summary>
		/// <returns>A string representing the normalized parameters</returns>
		public static String NormalizeParameters(String requestUrl, SortedDictionary<String, String> oauthParameters) {

			var paramString1 = new StringBuilder();

            //arizzini: oauthParamters to the sorted dictionary
            SortedDictionary<String, String> sortedParameters = new SortedDictionary<String, String> (oauthParameters, StringComparer.Ordinal);

			//extract request paramter from the url and sort them
			if (requestUrl.IndexOf ('?') > 0) {
				NameValueCollection nameValueCollecion = HttpUtility.ParseQueryString (requestUrl.Substring (requestUrl.IndexOf ('?')));
				foreach (String key in nameValueCollecion) {
					foreach (String value in nameValueCollecion.GetValues(key)) {
						sortedParameters.Add (key, value);
					}
				}
			}


            //add the sorted request paramters to the base string. 
            foreach (KeyValuePair<string, string> entry in sortedParameters)
			{
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

