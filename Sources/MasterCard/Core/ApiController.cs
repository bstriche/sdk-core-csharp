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
using log4net;
using log4net.Config;
using System.Linq;
using System.IO;
using MasterCard.Core.Security;

namespace MasterCard.Core
{

	public class ApiController
	{

		private static readonly ILog log = LogManager.GetLogger(typeof(ApiController));
		static ApiController() {

            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;

			if (ApiConfig.isDebug ()) {
				if (File.Exists ("log4net.xml")) {
					XmlConfigurator.Configure (new FileInfo ("log4net.xml"));
				} else {
					BasicConfigurator.Configure();
				}
			} 

		}

		String fullUrl;
        String apiVersion;
		IRestClient restClient;

		public ApiController(string apiVersion) {

            //arizzini: making sure to propagate the version.
            this.apiVersion = apiVersion;

			checkState ();

			fullUrl =  ApiConfig.getLiveUrl();

			//ApiConfig.sandbox
			if (ApiConfig.isSandbox()) {
				fullUrl = ApiConfig.getSandboxUrl();
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
		/// Execute the specified action, resourcePath and baseObject.
		/// </summary>
		/// <param name="action">Action.</param>
		/// <param name="resourcePath">Resource path.</param>
		/// <param name="requestMap">Request Map.</param>
		/// <param name="headerList">Header List.</param>
		public virtual IDictionary<String, Object> execute (string action, string resourcePath, BaseObject requestMap, List<string> headerList, List<string> queryList)
		{
			IRestResponse response;
			IRestRequest request;
			CryptographyInterceptor interceptor;


            Uri uri;

            try 
			{
				IDictionary<String,Object> paramterMap = requestMap.Clone();
				IDictionary<String,Object> headerMap = Util.SubMap(paramterMap, headerList);

				uri = getURL (action, resourcePath, paramterMap, queryList);
				interceptor = ApiConfig.GetCryptographyInterceptor(uri.AbsolutePath);
				request = getRequest (uri, action, paramterMap, headerMap, interceptor);


			} catch (Exception e) {
				throw new MasterCard.Core.Exceptions.ApiException (e.Message, e);
			}

			try {
				log.Debug(">>execute(action='"+action+"', resourcePaht='"+resourcePath+"', requestMap='"+requestMap+"'");
				log.Debug("excute(), request.Method='"+request.Method+"'");
                log.Debug("excute(), request.URL=" + uri.ToString());
				log.Debug("excute(), request.Header=");
                log.Debug(request.Parameters.Where(x => x.Type == ParameterType.HttpHeader));
				log.Debug("excute(), request.Body=");
                log.Debug(request.Parameters.Where(x => x.Type == ParameterType.RequestBody));
                response = restClient.Execute(request);
				log.Debug("execute(), response.Header=");
                log.Debug(response.Headers);
				log.Debug("execute(), response.Body=");
                log.Debug(response.Content.ToString());
			} catch (Exception e) {
				Exception wrapper = new MasterCard.Core.Exceptions.ApiCommunicationException (e.Message, e);
				log.Error (wrapper.Message, wrapper);
				throw wrapper;
			} 

			if (response.ErrorException == null && response.Content != null) {
				IDictionary<String,Object> responseObj = null;

				if (response.Content.StartsWith ("{") || response.Content.StartsWith ("[") || response.ContentType == "application/json") {
					try {
						responseObj = RequestMap.AsDictionary (response.Content);
						if (interceptor != null) {
							responseObj = interceptor.Encrypt(responseObj);
						}
					} catch (Exception) {
						throw new MasterCard.Core.Exceptions.SystemException ("Error: parsing JSON response", response.Content);
					}
				} 
				 
				if (response.StatusCode < HttpStatusCode.Ambiguous) {
					log.Debug ("<<execute()");
					return responseObj;
				} else {
					try {
						throwException (responseObj, response);
					} catch (Exception e) {
						log.Error (e.Message, e);
						throw e;
					}
					return null;
				}
			} else {
				Exception wrapper = new MasterCard.Core.Exceptions.SystemException (response.ErrorMessage, response.ErrorException);
				log.Error (wrapper.Message, wrapper);
				throw wrapper;
			}

		}


		/// <summary>
		/// Throws the exception.
		/// </summary>
		/// <param name="responseObj">Response object.</param>
		/// <param name="response">Response.</param>
		private static void throwException(IDictionary<String,Object> responseObj, IRestResponse response) {
			int status = (int)response.StatusCode;
			if (status == (int)HttpStatusCode.BadRequest) {
				if (responseObj != null) {
					throw new MasterCard.Core.Exceptions.InvalidRequestException (status, responseObj);
				} else {
					throw new MasterCard.Core.Exceptions.InvalidRequestException (status.ToString(), response.Content);
				}
			} else if (status == (int)HttpStatusCode.Redirect) {
				if (responseObj != null) {
					throw new MasterCard.Core.Exceptions.InvalidRequestException (status, responseObj);
				} else {
					throw new MasterCard.Core.Exceptions.InvalidRequestException (status.ToString(), response.Content);
				}
			} else if (status == (int)HttpStatusCode.Unauthorized) {
				if (responseObj != null) {
					throw new MasterCard.Core.Exceptions.AuthenticationException (status, responseObj);
				} else {
					throw new MasterCard.Core.Exceptions.AuthenticationException (status.ToString(), response.Content);
				}
			} else if (status == (int)HttpStatusCode.NotFound) {
				if (responseObj != null) {
					throw new MasterCard.Core.Exceptions.ObjectNotFoundException (status, responseObj);
				} else {
					throw new MasterCard.Core.Exceptions.ObjectNotFoundException (status.ToString(), response.Content);
				}
			} else if (status == (int)HttpStatusCode.MethodNotAllowed) {
				if (responseObj != null) {
					throw new MasterCard.Core.Exceptions.NotAllowedException (status, responseObj);
				} else {
					throw new MasterCard.Core.Exceptions.NotAllowedException (status.ToString(), response.Content);
				}
			} else if (status < (int)HttpStatusCode.InternalServerError) {
				if (responseObj != null) {
					throw new MasterCard.Core.Exceptions.InvalidRequestException (status, responseObj);
				} else {
					throw new MasterCard.Core.Exceptions.InvalidRequestException (status.ToString(), response.Content);
				}
			} else {
				if (responseObj != null) {
					throw new MasterCard.Core.Exceptions.SystemException (status, responseObj);
				} else {
					throw new MasterCard.Core.Exceptions.SystemException (status.ToString(), response.Content);
				}
			}
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
				new Uri (ApiConfig.getLiveUrl());
			} catch (UriFormatException e) {
				throw new System.InvalidOperationException ("Invalid URL supplied for API_BASE_LIVE_URL", e);
			}

			try {
				new Uri (ApiConfig.getSandboxUrl());
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
		private void appendToQueryString (StringBuilder s, string stringToAppend)
		{
			if (s.ToString ().IndexOf ("?") == -1) {
				s.Append ("?");
			}
			if (s.ToString ().IndexOf ("?") != s.Length - 1) {
				s.Append ("&");
			}
			s.Append (stringToAppend);
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
		/// <param name="inputMap">Input map.</param>
		/// <param name="inputMap">additionalQueryParametersList</param>
		Uri getURL (string action, string resourcePath, IDictionary<String, Object> inputMap, List<string> additionalQueryParametersList)
		{
			Uri uri;

			String path = this.fullUrl + resourcePath;
			String resolvedPath = Util.GetReplacedPath (path, inputMap);

			int parameters = 0;
			List<object> objectList = new List<object> ();
			StringBuilder s = new StringBuilder ("{"+(parameters++)+"}");
			objectList.Add (resolvedPath);

			switch(action)
			{
				case "read":
				case "delete":
				case "list":
				case "query":
					if (inputMap != null && inputMap.Count > 0) {
						foreach (KeyValuePair<String,Object> entry in inputMap) {
							appendToQueryString (s, "{" + (parameters++) + "}" + "=" + "{" + (parameters++) + "}");
							objectList.Add (getURLEncodedString (entry.Key.ToString ()));
							objectList.Add (getURLEncodedString (entry.Value.ToString ()));
						}
					}
					break;
				default:
					break;

			}

            // create and update may have Query and Body parameters as part of the request.
            // Check additionalQueryParametersList
            if (additionalQueryParametersList.Count > 0)
            {
                switch (action)
                {
                    case "create":
                    case "update":
                        // Get the submap of query parameters which also removes the values from objectMap
                        IDictionary<String, Object> queryMap = Util.SubMap(inputMap, additionalQueryParametersList);

                        foreach (KeyValuePair<String, Object> entry in queryMap)
                        {
                            appendToQueryString(s, "{" + (parameters++) + "}" + "=" + "{" + (parameters++) + "}");
                            objectList.Add(getURLEncodedString(entry.Key.ToString()));
                            objectList.Add(getURLEncodedString(entry.Value.ToString()));
                        }

                        break;
                }
            }

			appendToQueryString (s, "Format=JSON");

			try {
				uri = new Uri (String.Format (s.ToString (), objectList.ToArray()));
			} catch (UriFormatException e) {
				throw new System.InvalidOperationException ("Failed to build URI", e);
			}

            //Console.WriteLine("url: " + uri.ToString());
			return uri;
		}

		/// <summary>
		/// Gets the request.
		/// </summary>
		/// <returns>The request.</returns>
		/// <param name="uri">URI.</param>
		/// <param name="action">Action.</param>
		/// <param name="objectMap">Object map.</param>
		RestRequest getRequest (Uri uri, String action, IDictionary<String,Object> inputMap, IDictionary<String,Object> headerMap, CryptographyInterceptor interceptor = null)
		{

			RestRequest request = null;



			switch (action) {
			case "create":
				request = new RestRequest (uri, Method.POST);

				//arizzini: adding cryptography interceptor for POST
				if (interceptor != null) {
					inputMap = interceptor.Encrypt (inputMap);
				}

				request.AddJsonBody (inputMap);
				break;
			case "delete":
				request = new RestRequest (uri, Method.DELETE);
				break;
			case "update":
				request = new RestRequest (uri, Method.PUT);

				//arizzini: adding cryptography interceptor for PUT
				if (interceptor != null) {
					inputMap = interceptor.Encrypt (inputMap);
				}

				request.AddJsonBody (inputMap);
				break;
			case "read":
			case "list":
			case "query":
				request = new RestRequest (uri, Method.GET);
				break;
			}

			request.AddHeader ("Accept", "application/json");
			request.AddHeader ("Content-Type", "application/json");
			request.AddHeader ("User-Agent", "CSharp-SDK/" + this.apiVersion);

			//arizzini: adding the header paramter support.
			foreach (KeyValuePair<string, object> entry in headerMap) {
				request.AddHeader (entry.Key, entry.Value.ToString());
			}

			ApiConfig.getAuthentication().SignRequest(uri, request);

			return request;
		}



	}



}