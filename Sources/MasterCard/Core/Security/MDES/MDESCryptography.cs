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
using System.Collections.Generic;
using Newtonsoft.Json;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;
using MasterCard.Core.Model;
using System.IO;

namespace MasterCard.Core.Security.MDES
{
	public class MDESCryptography : CryptographyInterceptor
	{

		private List<String> fieldsToHide = new List<String> () {
			"publicKeyFingerprint",
			"oaepHashingAlgorithm",
			"iv",
			"encryptedData",
			"encryptedKey"
		};

		private String triggeringPath = "/mdes/tokenization/";


		private RSA publicKey;
		private String publicKeyFingerPrint;
		private RSA privateKey;



		public MDESCryptography (String publicKeyLocation, String privateKeyLocation)
		{
			
			var tmpPublicCertificate = new X509Certificate2(publicKeyLocation);
            this.publicKey = tmpPublicCertificate.GetRSAPublicKey();
			this.publicKeyFingerPrint = tmpPublicCertificate.Thumbprint;
                   
			string fullText = File.ReadAllText (privateKeyLocation);
			this.privateKey = CryptUtil.GetRSAFromPrivateKeyString (fullText) as RSA;
			

		}

		public String GetTriggeringPath() {
			return triggeringPath;
		}
		
		public IDictionary<String,Object> Encrypt(IDictionary<String,Object> map) {
			if (map.ContainsKey ("cardInfo")) {
				// 1) extract the encryptedData from map
				IDictionary<String,Object> encryptedDataMap =  (IDictionary<String,Object>)  map["cardInfo"];

				// 2) create json string
				String payload = JsonConvert.SerializeObject(encryptedDataMap);
				// 3) escaping the string
				payload = CryptUtil.SanitizeJson(payload);


				Tuple<byte[], byte[], byte[]> aesResult = CryptUtil.EncryptAES(System.Text.Encoding.UTF8.GetBytes(payload));

				// 4) generate random iv
				byte[] iv = aesResult.Item1;
				// 5) generate AES SecretKey
				byte[] key = aesResult.Item2;
				// 6) encrypt payload
				byte[] encryptedData = aesResult.Item3;

				String hexIv = CryptUtil.HexEncode (iv);
				String hexEncryptedData = CryptUtil.HexEncode(encryptedData);

				// 7) encrypt secretKey with issuer key


				byte[] encryptedSecretKey = CryptUtil.EncrytptRSA(key, this.publicKey);
				String hexEncryptedKey = CryptUtil.HexEncode(encryptedSecretKey);

				String fingerprintHexString = publicKeyFingerPrint;


				Dictionary<String,Object> encryptedMap = new Dictionary<String,Object>();
				encryptedMap.Add("publicKeyFingerprint", fingerprintHexString);
				encryptedMap.Add("encryptedKey", hexEncryptedKey);
				encryptedMap.Add("oaepHashingAlgorithm", "SHA256");
				encryptedMap.Add("iv", hexIv);
				encryptedMap.Add("encryptedData", hexEncryptedData);

				map.Remove ("cardInfo");
				map.Add("cardInfo", encryptedMap);
			}
			return map;
		}

		public IDictionary<String,Object> Decrypt(IDictionary<String,Object> map) {
			if (map.ContainsKey ("token")) {
				// 1) extract the encryptedData from map
				IDictionary<String,Object> tokenMap =  (IDictionary<String,Object>)  map["token"];

				if (tokenMap.ContainsKey ("") && tokenMap.ContainsKey ("")) {

					//need to read the key
					String encryptedKey = (String) tokenMap["encryptedKey"];
					byte[] encryptedKeyByteArray = CryptUtil.HexDecode(encryptedKey);

					//need to decryt with RSA
					byte[] decryptedKeyByteArray = CryptUtil.DecryptRSA(encryptedKeyByteArray, this.privateKey);

					//need to read the iv
					String ivString = (String) tokenMap["iv"];
					byte[] ivByteArray = CryptUtil.HexDecode(ivString);

					//need to decrypt the data
					String encryptedData = (String) tokenMap["encryptedData"];
					byte[] encryptedDataByteArray = CryptUtil.HexDecode(encryptedData);

					byte[] decryptedDataArray = CryptUtil.DecryptAES (ivByteArray, decryptedKeyByteArray, encryptedDataByteArray);
					String decryptedDataString = System.Text.Encoding.UTF8.GetString (decryptedDataArray);

					// remove the field that are not required in the map
					foreach(String toHide in fieldsToHide) {
						tokenMap.Remove(toHide);
					}

					// add the decrypted data map to the token.
					Dictionary<String,Object> decryptedDataMap = (Dictionary<String,Object>) RequestMap.AsDictionary(decryptedDataString);
					foreach(KeyValuePair<String,Object> pair in decryptedDataMap) {
						tokenMap.Add(pair.Key, pair.Value);
					}
				}
			}
			return map;
	}
}

}