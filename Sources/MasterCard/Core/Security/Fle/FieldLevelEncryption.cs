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
using System.Text;

namespace MasterCard.Core.Security.Fle
{
    public class FieldLevelEncryption : CryptographyInterceptor
	{
		private RSA publicKey;
		private String publicKeyFingerPrint;
		private RSA privateKey;

        internal readonly Config Config;

        public FieldLevelEncryption (String publicKeyLocation, String privateKeyLocation, Config config, X509KeyStorageFlags keyStorageFlags = X509KeyStorageFlags.DefaultKeySet)
		{

            if (publicKeyLocation != null) {
                var tmpPublicCertificate = new X509Certificate2(publicKeyLocation, String.Empty, keyStorageFlags);
                this.publicKey = tmpPublicCertificate.GetRSAPublicKey();
			    this.publicKeyFingerPrint = tmpPublicCertificate.Thumbprint;
            }
                   
            if (privateKeyLocation != null) {
                string fullText = File.ReadAllText (privateKeyLocation);
			    this.privateKey = CryptUtil.GetRSAFromPrivateKeyString (fullText) as RSA;
            }
			

            this.Config = config;
			

		}

    public FieldLevelEncryption(byte[] rawPublicKeyData, byte[] rawPrivateKeyData, Config config, X509KeyStorageFlags keyStorageFlags = X509KeyStorageFlags.DefaultKeySet) {

      if(rawPublicKeyData != null && rawPublicKeyData.LongLength > 0L) {
        var tmpPublicCertificate = new X509Certificate2(rawPublicKeyData, String.Empty, keyStorageFlags);
        this.publicKey = tmpPublicCertificate.GetRSAPublicKey();
        this.publicKeyFingerPrint = tmpPublicCertificate.Thumbprint;
      }

      if(rawPrivateKeyData != null) {
        string fullText = Encoding.UTF8.GetString(rawPrivateKeyData);
        this.privateKey = CryptUtil.GetRSAFromPrivateKeyString(fullText) as RSA;
      }


      this.Config = config;


    }

    public List<String> GetTriggeringPath() {
			return Config.TriggeringEndPath;
		}

        
		public IDictionary<String,Object> Encrypt(IDictionary<String,Object> map) {

            //requestMap is a SmartMap it offers a easy way to do nested lookups.
            SmartMap smartMap = new SmartMap(map);
            if (this.publicKey != null) 
            {
                foreach (String fieldToEncrypt in Config.FieldsToEncrypt) 
                {
                    if (smartMap.ContainsKey (fieldToEncrypt)) 
                    {
                        String payload = null;

                        // 1) extract the encryptedData from map
                        Object tmpObjectToEncrypt = smartMap.Get(fieldToEncrypt);
                        smartMap.Remove(fieldToEncrypt);

                        if (tmpObjectToEncrypt.GetType() == typeof(Dictionary<String,Object>)) {
                            // 2) create json string
                            payload = JsonConvert.SerializeObject(tmpObjectToEncrypt);
                            // 3) escaping the string
                            payload = CryptUtil.SanitizeJson(payload);
                        } else {
                            payload = tmpObjectToEncrypt.ToString();
                        }

                        Tuple<byte[], byte[], byte[]> aesResult = CryptUtil.EncryptAES(System.Text.Encoding.UTF8.GetBytes(payload), Config.SymmetricKeysize, Config.SymmetricMode, Config.SymmetricPadding);

                        // 4) generate random iv
                        byte[] ivBytes = aesResult.Item1;
                        // 5) generate AES SecretKey
                        byte[] secretKeyBytes = aesResult.Item2;
                        // 6) encrypt payload
                        byte[] encryptedDataBytes = aesResult.Item3;

                        String ivValue = CryptUtil.Encode(ivBytes, Config.DataEncoding);
                        String encryptedDataValue = CryptUtil.Encode(encryptedDataBytes, Config.DataEncoding);

                        // 7) encrypt secretKey with issuer key
                        byte[] encryptedSecretKey = CryptUtil.EncrytptRSA(secretKeyBytes, this.publicKey, Config.OaepEncryptionPadding);
                        String encryptedKeyValue = CryptUtil.Encode(encryptedSecretKey, Config.DataEncoding);

                        String fingerprintHexString = publicKeyFingerPrint;

                        String baseKey = "";
                        if (fieldToEncrypt.IndexOf(".") > 0 ) {
                            baseKey = fieldToEncrypt.Substring(0, fieldToEncrypt.IndexOf("."));
                            baseKey += ".";
                        }

                        if (Config.PublicKeyFingerprintFiledName != null) {
                            smartMap.Add(baseKey+Config.PublicKeyFingerprintFiledName, fingerprintHexString);
                        }
                        if (Config.OaepHashingAlgorithmFieldName != null) {
                            smartMap.Add(baseKey+Config.OaepHashingAlgorithmFieldName, Config.OaepHashingAlgorithm);
                        }
                        smartMap.Add(baseKey+Config.IvFieldName, ivValue);
                        smartMap.Add(baseKey+Config.EncryptedKeyFiledName, encryptedKeyValue);
                        smartMap.Add(baseKey+Config.EncryptedDataFieldName, encryptedDataValue);

                        break;
                    }
                }
            }
            return smartMap;
			
		}

		public IDictionary<String,Object> Decrypt(IDictionary<String,Object> map) {
			SmartMap smartMap = new SmartMap(map);
            foreach (String fieldToDecrypt in Config.FieldsToDecrypt) {
                if (smartMap.ContainsKey (fieldToDecrypt)) 
                {
                    String baseKey = "";
                    if (fieldToDecrypt.IndexOf(".")> 0) {
                        baseKey = fieldToDecrypt.Substring(0, fieldToDecrypt.LastIndexOf("."));
                        baseKey += ".";
                    }





                    //need to read the key
                    String encryptedKey = (String) smartMap.Get(baseKey + Config.EncryptedKeyFiledName);
                    smartMap.Remove(baseKey + Config.EncryptedKeyFiledName);

                    byte[] encryptedKeyByteArray = CryptUtil.Decode(encryptedKey, Config.DataEncoding);

                    //need to decryt with RSA
                    byte[] secretKeyBytes = CryptUtil.DecryptRSA(encryptedKeyByteArray, this.privateKey, Config.OaepEncryptionPadding);

                    //need to read the iv
                    String ivString = (String) smartMap.Get(baseKey + Config.IvFieldName);
                    smartMap.Remove(baseKey + Config.IvFieldName);

                    byte[] ivByteArray = CryptUtil.Decode(ivString.ToString(), Config.DataEncoding);

                    // remove the field that are not required in the map
                    if (smartMap.ContainsKey(Config.PublicKeyFingerprintFiledName)) {
                        smartMap.Remove(Config.PublicKeyFingerprintFiledName);
                    }

                    //need to decrypt the data
                    String encryptedData = (String) smartMap.Get(baseKey+Config.EncryptedDataFieldName);
                    byte[] encryptedDataByteArray = CryptUtil.Decode(encryptedData, Config.DataEncoding);

                    byte[] decryptedDataByteArray = CryptUtil.DecryptAES (ivByteArray, secretKeyBytes, encryptedDataByteArray, Config.SymmetricKeysize, Config.SymmetricMode, Config.SymmetricPadding);
                    String decryptedDataString = System.Text.Encoding.UTF8.GetString (decryptedDataByteArray);

                    if (decryptedDataString.StartsWith("{")) {
                        Dictionary<String,Object> decryptedDataMap =JsonConvert.DeserializeObject<Dictionary<String, Object>>(decryptedDataString);
                        foreach(KeyValuePair<String, Object> entry in decryptedDataMap) {
                            smartMap.Add(baseKey+Config.EncryptedDataFieldName+"."+entry.Key, entry.Value);
                        }
                    } else {
                        smartMap.Add(baseKey+Config.EncryptedDataFieldName, decryptedDataString);
                    }

                    break;
                }
            }
			return smartMap;
	    }

        public bool Equals(CryptographyInterceptor other)
        {
            return this.GetConfig().Equals(other.GetConfig());
        }

        public Config GetConfig()
        {
            return this.Config;
        }
    }
}