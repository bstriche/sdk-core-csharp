using System;
using System.Collections.Generic;
using Newtonsoft.Json;
using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Crypto.Parameters;
using System.Security.Cryptography;
using MasterCard.Core.Model;
using Org.BouncyCastle.Crypto;
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


		private RsaKeyParameters publicKey;
		private String publicKeyFingerPrint;
		private AsymmetricKeyParameter privateKey;

		public MDESCryptography (String publicKeyLocation, String privateKeyLocation)
		{
			if (!File.Exists (publicKeyLocation)) {
				throw new InvalidParameterException ("Invalid MasterCard MDES public key location");
			}


			if (!File.Exists (privateKeyLocation)) {
				throw new InvalidParameterException ("Invalid MasterCard MDES private key location");
			}


			var tmpPublicCertificate = new X509Certificate2 (publicKeyLocation);
			this.publicKey = DotNetUtilities.GetRsaPublicKey (tmpPublicCertificate.PublicKey.Key as RSA);
			this.publicKeyFingerPrint = tmpPublicCertificate.Thumbprint;



			string fullText = File.ReadAllText (privateKeyLocation);
		
			RSA rsa = CryptUtil.GetRSAFromPrivateKeyString (fullText) as RSA;
			AsymmetricCipherKeyPair keyPair = DotNetUtilities.GetKeyPair (rsa);

			this.privateKey = keyPair.Private;


		}

		public String GetTriggeringPath() {
			return triggeringPath;
		}
		
		public Dictionary<String,Object> Encrypt(IDictionary<String,Object> map) {
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
			return new Dictionary<String,Object>(map);
		}

		public Dictionary<String,Object> Decrypt(IDictionary<String,Object> map) {
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
			return new Dictionary<String,Object>(map);
	}
}

}