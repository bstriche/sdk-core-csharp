/*
 * Copyright 2015 MasterCard International.
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
using RestSharp;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace MasterCard.Core.Security.OAuth
{

	public class OAuthAuthentication : AuthenticationInterface
	{
		private readonly AsymmetricAlgorithm privateKey;
		private readonly String clientId;
		private readonly UTF8Encoding encoder;
        private readonly X509Certificate2 cert;

		public AsymmetricAlgorithm PrivateKey {
			get {
				return privateKey;
			}
		}

		public String ClientId {
			get {
				return clientId;
			}
		}

		public OAuthAuthentication(String clientId, String filePath, String alias, String password)
		{
			cert = new X509Certificate2(filePath, password, X509KeyStorageFlags.Exportable);

			privateKey = cert.PrivateKey;
			this.clientId = clientId;
			encoder =  new UTF8Encoding();
		}

		public void SignRequest(Uri uri, IRestRequest request) {
			String uriString = uri.ToString ();
			String methodString = request.Method.ToString();
			//String bodyString = (String) request.Parameters.FirstOrDefault (p => p.Type == ParameterType.RequestBody).Value;

			String bodyString = "";
			Parameter bodyParam = request.Parameters.FirstOrDefault (p => p.Type == ParameterType.RequestBody);
			if (bodyParam != null) {
				bodyString = bodyParam.Value.ToString ();
			}
				
			String signature = OAuthUtil.GenerateSignature (uriString, methodString, bodyString, clientId, privateKey);
			request.AddHeader ("Authorization", signature);
		}

		public string SignMessage (string message)
		{
			// Hash the data
            byte[] hash = Util.Sha256Encode(message);

            // Sign the hash
            RSACryptoServiceProvider aescsp = new RSACryptoServiceProvider();
            aescsp.FromXmlString(cert.PrivateKey.ToXmlString(true));

            byte[] SignedHashValue = aescsp.SignHash(hash, CryptoConfig.MapNameToOID("SHA256"));
			return Convert.ToBase64String(SignedHashValue);
		}
	}

}