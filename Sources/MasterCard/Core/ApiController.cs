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
using MasterCard.Core.Exceptions;
using Environment = MasterCard.Core.Model.Constants.Environment;

namespace MasterCard.Core
{

	public class ApiController
	{

		private static readonly ILog log = LogManager.GetLogger(typeof(ApiController));
		private static readonly string EnvironmentIdentifier = "#env";
		static ApiController() {

            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;

			if (ApiConfig.IsDebug ()) {
				if (File.Exists ("log4net.xml")) {
					XmlConfigurator.Configure (new FileInfo ("log4net.xml"));
				} else {
					BasicConfigurator.Configure();
				}
			} 

		}

		IRestClient restClient;

		public ApiController() {

			CheckState ();
			
		}


		/// <summary>
		/// Sets the rest client.
		/// </summary>
		/// <param name="restClient">Rest client.</param>
		public void SetRestClient(IRestClient restClient)
		{
			this.restClient = restClient;
		}


		/// <summary>
		/// Execute the specified action, resourcePath and baseObject.
		/// </summary>
		/// <param name="action">Action.</param>
		/// <param name="resourcePath">Resource path.</param>
		/// <param name="requestMap">Request Map.</param>
		/// <param name="headerList">Header List.</param>
		public virtual IDictionary<String, Object> Execute (OperationConfig config, OperationMetadata metadata, BaseObject requestMap)
		{
			IRestResponse response;
			RestyRequest request;
            IRestClient client;
			CryptographyInterceptor interceptor;

            try 
			{

				request = GetRequest (config, metadata, requestMap);
                interceptor = request.interceptor;

                //arizzini: create client
                if (this.restClient != null)
                {
                    client = restClient;
                }
                else
                {
                    client = new RestClient();
				}

				client.BaseUrl = request.BaseUrl;
				client.Proxy = ApiConfig.GetProxy();

				log.Debug(">>Execute(action='"+config.Action+"', resourcePaht='"+config.ResourcePath+"', requestMap='"+requestMap+"'");
				log.Debug("excute(), request.Method='"+request.Method+"'");
                log.Debug("excute(), request.URL=" + request.AbsoluteUrl.ToString());
				log.Debug("excute(), request.Header=");
                log.Debug(request.Parameters.Where(x => x.Type == ParameterType.HttpHeader));
				log.Debug("excute(), request.Body=");
                log.Debug(request.Parameters.Where(x => x.Type == ParameterType.RequestBody));
                response = client.Execute(request);
				log.Debug("Execute(), response.Header=");
                log.Debug(response.Headers);
				log.Debug("Execute(), response.Body=");
                log.Debug(response.Content.ToString());


                if (response.ErrorException == null && response.Content != null) {
                    IDictionary<String, Object> responseObj = new Dictionary<String, Object>();

                    if (response.Content.Length > 0)
                    {
                        if (response.StatusCode < HttpStatusCode.Ambiguous)
                        {
							responseObj = SmartMap.AsDictionary(response.Content);
                            if (interceptor != null)
                            {
                                try
                                {
                                    responseObj = interceptor.Decrypt(responseObj);
                                }
                                catch (Exception e)
                                {
                                    throw new ApiException("Error: decrypting payload", e);
                                }
                            }

                            log.Debug("<<Execute()");
                            return responseObj;
                        }
                        else
                        {
                            int status = (int)response.StatusCode;
                            throw new ApiException(status, SmartMap.AsObject(response.Content));
                        }
                    } else
                    {
                        return responseObj;
                    }
                    
				} else {
					throw new ApiException (response.ErrorMessage, response.ErrorException);
				}

			} catch (ApiException apiE) {
				log.Error (apiE.Message, apiE);
				throw;
			} catch (Exception genE) {
				ApiException wrapper = new ApiException (genE.Message, genE);
				log.Error (wrapper.Message, wrapper);
				throw wrapper;
			}





		}



		/// <summary>
		/// Checks the state.
		/// </summary>
		private void CheckState ()
		{

			if (ApiConfig.GetAuthentication() == null) {
				throw new System.InvalidOperationException ("No ApiConfig.authentication has been configured");
			}
		}

		/// <summary>
		/// Appends to query string.
		/// </summary>
		/// <returns>The to query string.</returns>
		/// <param name="s">S.</param>
		/// <param name="stringToAppend">String to append.</param>
		private void AppendToQueryString (StringBuilder s, string stringToAppend)
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
		string GetURLEncodedString (object stringToEncode)
		{
			return HttpUtility.UrlEncode (stringToEncode.ToString (), Encoding.UTF8);
		}


        /// <summary>
        /// Gets the URL
        /// </summary>
        /// <param name="config"></param>
        /// <param name="metadata"></param>
        /// <param name="inputMap"></param>
        /// <returns></returns>
		public Uri GetURL (OperationConfig config, OperationMetadata metadata, IDictionary<String, Object> inputMap)
		{
			Uri uri;


            List<string> additionalQueryParametersList = config.QueryParams;

            String resolvedHost = metadata.Host;

            if (resolvedHost == null)
            {
                throw new System.InvalidOperationException("Host is '', empty");
            }

			String resourcePath = config.ResourcePath;
			if (resourcePath.Contains(ApiController.EnvironmentIdentifier)) 
			{
				String context = "";
				if (metadata.Context != null) {
                    context = metadata.Context;
				} 
				resourcePath = resourcePath.Replace(ApiController.EnvironmentIdentifier, context);
				resourcePath = resourcePath.Replace("//", "/");
			}

            String path = resolvedHost + resourcePath;
			String resolvedPath = Util.GetReplacedPath (path, inputMap);

			int parameters = 0;
			List<object> objectList = new List<object> ();
			StringBuilder s = new StringBuilder ("{"+(parameters++)+"}");
			objectList.Add (resolvedPath);

			switch(config.Action)
			{
				case "read":
				case "delete":
				case "list":
				case "query":
					if (inputMap != null && inputMap.Count > 0) {
						foreach (KeyValuePair<String,Object> entry in inputMap) {
							AppendToQueryString (s, "{" + (parameters++) + "}" + "=" + "{" + (parameters++) + "}");
							objectList.Add (GetURLEncodedString (entry.Key.ToString ()));
							objectList.Add (GetURLEncodedString (entry.Value.ToString ()));
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
                switch (config.Action)
                {
                    case "create":
                    case "update":
                        // Get the submap of query parameters which also removes the values from objectMap
                        IDictionary<String, Object> queryMap = Util.SubMap(inputMap, additionalQueryParametersList);

                        foreach (KeyValuePair<String, Object> entry in queryMap)
                        {
                            AppendToQueryString(s, "{" + (parameters++) + "}" + "=" + "{" + (parameters++) + "}");
                            objectList.Add(GetURLEncodedString(entry.Key.ToString()));
                            objectList.Add(GetURLEncodedString(entry.Value.ToString()));
                        }

                        break;
                }
            }

			if (!metadata.JsonNative) 
			{
				AppendToQueryString (s, "Format=JSON");
			}
			

			try {
				uri = new Uri (String.Format (s.ToString (), objectList.ToArray()));
			} catch (UriFormatException e) {
				throw new System.InvalidOperationException ("Failed to build URI", e);
			}

            //Console.WriteLine("url: " + uri.ToString());
			return uri;
		}

        /// <summary>
        /// 
        /// </summary>
        /// <param name="action"></param>
        /// <param name="config"></param>
        /// <param name="inputMap"></param>
        /// <returns></returns>
		RestyRequest GetRequest (OperationConfig config, OperationMetadata metadata, RequestMap requestMap)
		{

			RestyRequest request = null;


            // separate the parameterMap and headerMap from requestMap
            IDictionary<String, Object> paramterMap = requestMap.Clone();
            IDictionary<String, Object> headerMap = Util.SubMap(paramterMap, config.HeaderParams);

            Uri url = GetURL(config, metadata, paramterMap);
            String baseUriString = url.Scheme + "://" + url.Host + ":" + url.Port;
            Uri baseUrl = new Uri(baseUriString);

            CryptographyInterceptor interceptor = ApiConfig.GetCryptographyInterceptor(url.AbsolutePath);



            switch (config.Action) {
			case "create":
				request = new RestyRequest(url, Method.POST);

				//arizzini: adding cryptography interceptor for POST
				if (interceptor != null) {
                    paramterMap = interceptor.Encrypt (paramterMap);
				}
				request.AddJsonBody (paramterMap);
				break;
			case "delete":
				request = new RestyRequest(url, Method.DELETE);
				break;
			case "update":
				request = new RestyRequest(url, Method.PUT);

				//arizzini: adding cryptography interceptor for PUT
				if (interceptor != null) {
                    paramterMap = interceptor.Encrypt (paramterMap);
				}
				request.AddJsonBody (paramterMap);
				break;
			case "read":
			case "list":
			case "query":
				request = new RestyRequest(url, Method.GET);
				break;
			}

			request.AddHeader ("Accept", "application/json; charset=utf-8");
			if (request.HasBody) {
				request.AddHeader ("Content-Type", "application/json; charset=utf-8");
			}
			request.AddHeader ("User-Agent", "CSharp-SDK/" + metadata.Version);

			//arizzini: adding the header paramter support.
			foreach (KeyValuePair<string, object> entry in headerMap) {
				request.AddHeader (entry.Key, entry.Value.ToString());
			}

			ApiConfig.GetAuthentication().SignRequest(url, request);


            request.AbsoluteUrl = url;
            request.BaseUrl = baseUrl;
            request.interceptor = interceptor;
               

			return request;
		}



	}



}