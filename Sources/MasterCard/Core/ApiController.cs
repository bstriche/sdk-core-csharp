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
using MasterCard.Core.Model;

namespace MasterCard.Core
{

	public class ApiController
	{

		String fullUrl;
		IRestClient restClient;

		public ApiController() {

			checkState ();

			fullUrl =  ApiConfig.API_BASE_LIVE_URL;

			//ApiConfig.sandbox
			if (ApiConfig.isSandbox()) {
				fullUrl = ApiConfig.API_BASE_SANDBOX_URL;
			}

			Uri uri = new Uri (this.fullUrl);
			String baseUrl = uri.Scheme + "://" + uri.Host + ":" + uri.Port;
			restClient = new RestClient(baseUrl);
		}



		/// <summary>
		/// Sets the rest client.
		/// </summary>
		/// <param name="restClient">Rest client.</param>
		public void SetRestClient(IRestClient restClient)
		{
			restClient.BaseUrl =  new Uri (this.fullUrl);
			this.restClient = restClient;
		}


		/// <summary>
		/// Execute the specified type, action and baseObject.
		/// </summary>
		/// <param name="resourcePath">Type.</param>
		/// <param name="action">Action.</param>
		/// <param name="baseObject">Base object.</param>
		public virtual IDictionary<String, Object> execute (string action, string resourcePath, BaseObject baseObject)
		{

			Uri uri = getURL (action, resourcePath, baseObject);

			IRestResponse response;
			IRestRequest request;

			try 
			{
				request = getRequest (uri, action, baseObject);


			} catch (Exception e) {
				throw new MasterCard.Core.Exceptions.ApiException (e.Message, e);
			}

			try {
				response = restClient.Execute(request);
			} catch (Exception e) {
				throw new MasterCard.Core.Exceptions.ApiCommunicationException (e.Message, e);
			} 

			if (response.ErrorException == null) {
				if (response.Content != null) {
					IDictionary<String,Object> responseObj = RequestMap.AsDictionary(response.Content);

					if (response.StatusCode < HttpStatusCode.Ambiguous) {
						return responseObj;
					} else {
						int status = (int) response.StatusCode;

						if (status == (int) HttpStatusCode.BadRequest) {
							throw new MasterCard.Core.Exceptions.InvalidRequestException (status, responseObj);
						} else if (status == (int) HttpStatusCode.Redirect) {
							throw new MasterCard.Core.Exceptions.InvalidRequestException (status, responseObj);
						} else if (status == (int)  HttpStatusCode.Unauthorized) {
							throw new MasterCard.Core.Exceptions.AuthenticationException (status, responseObj);
						} else if (status == (int)  HttpStatusCode.NotFound) {
							throw new MasterCard.Core.Exceptions.ObjectNotFoundException (status, responseObj);
						} else if (status == (int)  HttpStatusCode.MethodNotAllowed) {
							throw new MasterCard.Core.Exceptions.NotAllowedException (status, responseObj);
						} else if (status < (int)  HttpStatusCode.InternalServerError) {
							throw new MasterCard.Core.Exceptions.InvalidRequestException (status, responseObj);
						} else {
							throw new MasterCard.Core.Exceptions.SystemException (status, responseObj);
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

			if (ApiConfig.getAuthentication() == null) {
				throw new System.InvalidOperationException ("No ApiConfig.authentication has been configured");
			}

			try {
				new Uri (ApiConfig.API_BASE_LIVE_URL);
			} catch (UriFormatException e) {
				throw new System.InvalidOperationException ("Invalid URL supplied for API_BASE_LIVE_URL", e);
			}

			try {
				new Uri (ApiConfig.API_BASE_SANDBOX_URL);
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
		string getURLEncodedString (object stringToEncode)
		{
			return HttpUtility.UrlEncode (stringToEncode.ToString (), Encoding.UTF8);
		}


		/// <summary>
		/// Gets the UR.
		/// </summary>
		/// <returns>The UR.</returns>
		/// <param name="action">Action.</param>
		/// <param name="resourcePath">Type.</param>
		/// <param name="objectMap">Object map.</param>
		Uri getURL (string action, string resourcePath, BaseObject objectMap)
		{
			Uri uri;

			int parameters = 0;
			StringBuilder s = new StringBuilder ("{"+(parameters++)+"}/{"+(parameters++)+"}");

			List<object> objectList = new List<object> ();
			//arizzini: SAFETY CHECK -- need to strip out any / to the end of the path
			if (fullUrl.Length > 1 && fullUrl.EndsWith ("/")) {
				objectList.Add (fullUrl.Substring (0, fullUrl.Length - 1));
			} else  {
				objectList.Add (fullUrl);
			}

			//arizzini: SAFETY CHECK --  need to strip ou any {id} from the original swagger gen
			resourcePath = resourcePath.Replace ("{id}", "");
			if (resourcePath.EndsWith ("/")) {
				objectList.Add (resourcePath.Substring (0, resourcePath.Length - 1));
			} else {
				objectList.Add (resourcePath);
			}


			switch (action) {
				case "read":
				case "update":
				case "delete":
					if (objectMap.ContainsKey ("id")) {
						//arizzini: lostandfound uses PUT with no ID, so removing this check
						//throw new System.InvalidOperationException ("id required for " + action.ToString () + "action");
						s.Append ("/{"+(parameters++)+"}");
						objectList.Add (getURLEncodedString (objectMap ["id"]));
					}
					break;
				case "list":
					if (objectMap != null && objectMap.Count > 0) {
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
				default: 
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
		RestRequest getRequest (Uri uri, String action, RequestMap objectMap)
		{

			RestRequest request = null;

			switch (action) {
			case "create":
				request = new RestRequest (uri, Method.POST);
				request.AddJsonBody (objectMap);
				break;
			case "delete":
				request = new RestRequest (uri, Method.DELETE);
				break;
			case "update":
				request = new RestRequest (uri, Method.PUT);
				request.AddJsonBody (objectMap);
				break;
			case "read":
				request = new RestRequest (uri, Method.GET);
				break;
			case "list":
				request = new RestRequest (uri, Method.GET);
				break;
			}

			request.AddHeader ("Accept", "application/json");
			request.AddHeader ("Content-Type", "application/json");
			request.AddHeader ("User-Agent", "Java-SDK/" + ApiConfig.VERSION);

			ApiConfig.getAuthentication().SignRequest(uri, request);

			return request;
		}



	}



}