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
using System.Collections;
using System.Collections.Generic;
using System.Text;
using System.Net;
using System.Web;
using RestSharp;
using MasterCard.SDK.Core.Model;
using MasterCard.SDK.Core.Security;

namespace MasterCard.SDK
{

	public class ApiController
	{

		private String apiPath;

		private enum ACTION
		{
			show,
			list,
			update,
			create,
			delete
		}

		private enum PORTS
		{
			HTTP = 80,
			HTTPS = 443,
			UNKNOWN = -1
		}


		public ApiController(String basePath) {

			checkState ();

			if (basePath == null || basePath.Trim().Length < 0) {
				throw new System.InvalidOperationException("BasePath cannot be empty");
			}

			String baseUrl =  Constants.API_BASE_LIVE_URL;

			//ApiConfig.sandbox
			if (true) {

				baseUrl = Constants.API_BASE_SANDBOX_URL;
			}
			this.apiPath = baseUrl + basePath;
		}


		/// <summary>
		/// Execute the specified type, action and baseObject.
		/// </summary>
		/// <param name="type">Type.</param>
		/// <param name="action">Action.</param>
		/// <param name="baseObject">Base object.</param>
		public virtual IDictionary<String, Object> execute (string type, string action, BaseObject baseObject)
		{

			checkState ();

			ACTION act = getAction (action);
			Uri uri = getURI (type, act, baseObject);


			int port = uri.Port;
			string scheme = uri.Scheme;
			if (port == (int) PORTS.UNKNOWN) {
				port = (int) PORTS.HTTP;
				if (scheme.Equals (PORTS.HTTPS)) {
					port = (int) PORTS.HTTPS;
				}
			}

			String host = uri.Scheme + "://" + uri.Host + ":" + uri.Port;


			IRestResponse response;

			try {

				var httpClient = new RestClient(host);
				RestRequest request = getRequest (uri, act, baseObject);
				new OAuthAuthentication().sign( uri, request);
				response = httpClient.Execute(request);

			} catch (Exception e) {
				throw new MasterCard.SDK.Core.Exceptions.ApiCommunicationException (e.Message, e);
			} 

			if (response.ErrorException == null) {

				IDictionary<String, Object> responseObj = BaseMap.DeserializeDeep(response.Content);

				if (responseObj is IDictionary) {
					if (response.StatusCode < HttpStatusCode.Ambiguous) {
						return (IDictionary<String, Object>) responseObj;
					} else {
						int status = (int) response.StatusCode;

						if (status == (int) HttpStatusCode.BadRequest) {
							throw new MasterCard.SDK.Core.Exceptions.InvalidRequestException (status, responseObj);
						} else if (status == (int)  HttpStatusCode.Unauthorized) {
							throw new MasterCard.SDK.Core.Exceptions.AuthenticationException (status, responseObj);
						} else if (status == (int)  HttpStatusCode.NotFound) {
							throw new MasterCard.SDK.Core.Exceptions.ObjectNotFoundException (status, responseObj);
						} else if (status == (int)  HttpStatusCode.MethodNotAllowed) {
							throw new MasterCard.SDK.Core.Exceptions.NotAllowedException (status, responseObj);
						} else if (status < (int)  HttpStatusCode.InternalServerError) {
							throw new MasterCard.SDK.Core.Exceptions.InvalidRequestException (status, responseObj);
						} else {
							throw new MasterCard.SDK.Core.Exceptions.SystemException (status, responseObj);
						}
					}
				}
			}

			return null;

		}


		/// <summary>
		/// Checks the state.
		/// </summary>
		private void checkState ()
		{
			try {
				new Uri (Constants.API_BASE_LIVE_URL);
			} catch (UriFormatException e) {
				throw new System.InvalidOperationException ("Invalid URL supplied for API_BASE_LIVE_URL", e);
			}

			try {
				new Uri (Constants.API_BASE_SANDBOX_URL);
			} catch (UriFormatException e) {
				throw new System.InvalidOperationException ("Invalid URL supplied for API_BASE_SANDBOX_URL", e);
			}
		}

		/// <summary>
		/// Appends to query string.
		/// </summary>
		/// <returns>The to query string.</returns>
		/// <param name="s">S.</param>
		/// <param name="stringToAppend">String to append.</param>
		private StringBuilder appendToQueryString (StringBuilder s, string stringToAppend)
		{
			if (s.ToString ().IndexOf ("?") == -1) {
				s.Append ("?");
			}
			if (s.ToString ().IndexOf ("?") != s.Length - 1) {
				s.Append ("&");
			}
			s.Append (stringToAppend);

			return s;
		}

		/// <summary>
		/// Gets the URL encoded string.
		/// </summary>
		/// <returns>The URL encoded string.</returns>
		/// <param name="stringToEncode">String to encode.</param>
		private string getURLEncodedString (object stringToEncode)
		{
			return HttpUtility.UrlEncode (stringToEncode.ToString (), Encoding.UTF8);
		}


		/// <summary>
		/// Gets the UR.
		/// </summary>
		/// <returns>The UR.</returns>
		/// <param name="type">Type.</param>
		/// <param name="action">Action.</param>
		/// <param name="objectMap">Object map.</param>
		private Uri getURI (string type, ACTION action, BaseObject objectMap)
		{
			Uri uri;

			int parameters = 0;
			StringBuilder s = new StringBuilder ("{"+(parameters++)+"}/{"+(parameters++)+"}");

			List<object> objectList = new List<object> ();
			objectList.Add (apiPath.Replace ("/$", ""));
			objectList.Add (type.Replace ("/$", ""));

			switch (action) {
			case ApiController.ACTION.create:
				break;
			case ApiController.ACTION.show:
			case ApiController.ACTION.update:
			case ApiController.ACTION.delete:
				if (!objectMap.ContainsKey ("id")) {
					throw new System.InvalidOperationException ("id required for " + action.ToString () + "action");
				}
				s.Append ("/"+(parameters++));
				objectList.Add (getURLEncodedString (objectMap ["id"]));
				break;

			case ApiController.ACTION.list:
				if (objectMap != null) {
					if (objectMap.ContainsKey ("max")) {
						s = appendToQueryString (s, "max="+(parameters++));
						objectList.Add (getURLEncodedString (objectMap ["max"]));
					}

					if (objectMap.ContainsKey ("offset")) {
						s = appendToQueryString (s, "offset="+(parameters++));
						objectList.Add (getURLEncodedString (objectMap ["offset"]));
					}

					if (objectMap.ContainsKey ("sorting")) {
						if (objectMap ["sorting"] is IDictionary) {
							IDictionary<string, object> sorting = (IDictionary<string, object>)objectMap ["sorting"];
							IEnumerator it = sorting.GetEnumerator ();
							while (it.MoveNext ()) {
								DictionaryEntry entry = (DictionaryEntry)it.Current;
								s = appendToQueryString (s, "sorting["+(parameters++)+"]="+(parameters++));
								objectList.Add (getURLEncodedString (entry.Key.ToString ()));
								objectList.Add (getURLEncodedString (entry.Value.ToString ()));
							}
						}
					}

					if (objectMap.ContainsKey ("filter")) {
						if (objectMap ["filter"] is IDictionary) {
							IDictionary<string, object> filter = (IDictionary<string, object>)objectMap ["filter"];
							IEnumerator it = filter.GetEnumerator ();
							while (it.MoveNext ()) {
								DictionaryEntry entry = (DictionaryEntry)it.Current;
								s = appendToQueryString (s, "filter["+(parameters++)+"]="+(parameters++));
								objectList.Add (getURLEncodedString (entry.Key.ToString ()));
								objectList.Add (getURLEncodedString (entry.Value.ToString ()));
							}
						}
					}

					IEnumerator enumerator = objectMap.GetEnumerator ();
					while (enumerator.MoveNext ()) {
						DictionaryEntry entry = (DictionaryEntry)enumerator.Current;
						s = appendToQueryString (s, (parameters++)+"="+(parameters++));
						objectList.Add (getURLEncodedString (entry.Key.ToString ()));
						objectList.Add (getURLEncodedString (entry.Value.ToString ()));
					}
				}

				break;
			}

			s = appendToQueryString (s, "Format=JSON");

			try {
				uri = new Uri (String.Format (s.ToString (), objectList.ToArray()));
			} catch (UriFormatException e) {
				throw new System.InvalidOperationException ("Failed to build URI", e);
			}

			return uri;
		}

		/// <summary>
		/// Gets the request.
		/// </summary>
		/// <returns>The request.</returns>
		/// <param name="uri">URI.</param>
		/// <param name="action">Action.</param>
		/// <param name="objectMap">Object map.</param>
		private RestRequest getRequest (Uri uri, ACTION action, BaseMap objectMap)
		{

			RestRequest request = null;

			switch (action) {
			case ApiController.ACTION.create:
				//TODO: this needs to be a create // post
				request = new RestRequest (uri, Method.PUT);
				request.AddJsonBody (objectMap);
				break;
			case ApiController.ACTION.delete:
				request = new RestRequest (uri, Method.DELETE);
				break;
			case ApiController.ACTION.update:
				request = new RestRequest (uri, Method.PUT);
				request.AddJsonBody (objectMap);
				break;
			case ApiController.ACTION.show:
				request = new RestRequest (uri, Method.GET);
				break;
			case ApiController.ACTION.list:
				request = new RestRequest (uri, Method.GET);
				break;
			}

			request.AddHeader ("Accept", "application/json");
			request.AddHeader ("Content-Type", "application/json");
			request.AddHeader ("User-Agent", "Java-SDK/" + Constants.VERSION);

			return request;
		}

		/// <summary>
		/// Gets the action.
		/// </summary>
		/// <returns>The action.</returns>
		/// <param name="action">Action.</param>
		private ACTION getAction (string action)
		{
			try {
				return (ACTION) Enum.Parse (typeof(ACTION), action);
			} catch (ArgumentException e) {
				throw new System.InvalidOperationException ("Invalid action supplied: " + action, e);
			}

		}




		/// <summary>
		/// Ises the live public key.
		/// </summary>
		/// <returns><c>true</c>, if live public key was ised, <c>false</c> otherwise.</returns>
		private bool isLivePublicKey ()
		{
			//TODO
			return true;
		}

	}



}