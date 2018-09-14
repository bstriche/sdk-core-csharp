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
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using MasterCard.Core.Model;
using MasterCard.Core.Security.Fle;
using Newtonsoft.Json;

namespace MasterCard.Core.Security.MpqrMes
{
    public class MESCryptography : FieldLevelEncryption
    {
        public MESCryptography(String publicKeyLocation, String privateKeyLocation, X509KeyStorageFlags keyStorageFlags = X509KeyStorageFlags.DefaultKeySet)
        : base(publicKeyLocation, privateKeyLocation, config(), null, keyStorageFlags)
        {

        }

        public MESCryptography(byte[] rawPublicKeyData, byte[] rawPrivateKeyData, X509KeyStorageFlags keyStorageFlags = X509KeyStorageFlags.DefaultKeySet)
        : base(rawPublicKeyData, rawPrivateKeyData, config(), null, keyStorageFlags)
        {

        }

        public MESCryptography(String publicKeyLocation, String privateKeyLocation, String publicKeyFingerprint, X509KeyStorageFlags keyStorageFlags = X509KeyStorageFlags.DefaultKeySet)
        : base(publicKeyLocation, privateKeyLocation, config(), publicKeyFingerprint, keyStorageFlags)
        {

        }

        public MESCryptography(byte[] rawPublicKeyData, byte[] rawPrivateKeyData, String publicKeyFingerprint, X509KeyStorageFlags keyStorageFlags = X509KeyStorageFlags.DefaultKeySet)
        : base(rawPublicKeyData, rawPrivateKeyData, config(), publicKeyFingerprint, keyStorageFlags)
        {

        }

        private static Config config()
        {
            Config tmpConfig = new Config();
            tmpConfig.TriggeringEndPath = new List<String>(new String[] {
                "/mes/api/v1/merchants/.*/transactions",
                "/paygo/api/v1/merchants/.*/transactions",
                "/mpqr-mes/api/v1/merchants/.*/transactions",
                "/mpqr-paygo/api/v1/merchants/.*/transactions",

                "/mes/api/v1/transactions",
                "/paygo/api/v1/transactions",
                "/mpqr-mes/api/v1/transactions",
                "/mpqr-paygo/api/v1/transactions"
            });
            tmpConfig.FieldsToEncrypt = new List<String>();
            tmpConfig.FieldsToDecrypt = new List<String>(new String[] { "items", "data.extraData" });

            tmpConfig.SymmetricMode = CipherMode.CBC;
            tmpConfig.SymmetricPadding = PaddingMode.PKCS7;
            tmpConfig.SymmetricKeysize = 128;

            tmpConfig.OaepEncryptionPadding = RSAEncryptionPadding.OaepSHA512;
            tmpConfig.OaepHashingAlgorithm = "SHA512";

            tmpConfig.PublicKeyFingerprintHashing = HashingAlgorithm.SHA256;

            tmpConfig.IvFieldName = "iv";
            tmpConfig.OaepHashingAlgorithmFieldName = "oaepHashingAlgorithm";
            tmpConfig.EncryptedKeyFiledName = "encryptedKey";
            tmpConfig.PublicKeyFingerprintFiledName = "publicKeyFingerprint";
            tmpConfig.DataEncoding = DataEncoding.BASE64;

            return tmpConfig;
        }

        public override IDictionary<String, Object> Encrypt(IDictionary<String, Object> map)
        {
            SmartMap smartMap = new SmartMap(map);
            if (this.publicKey == null) {
                return smartMap;
            }

            foreach (String fieldToEncrypt in configuration.FieldsToEncrypt)
            {
                if (!smartMap.ContainsKey(fieldToEncrypt))
                {
                    continue;
                }

                String payload = null;

                // Extract the encrypted payload from map
                Object tmpObjectToEncrypt = smartMap.Get(fieldToEncrypt);
                smartMap.Remove(fieldToEncrypt);

                if (tmpObjectToEncrypt.GetType() == typeof(Dictionary<String, Object>) || tmpObjectToEncrypt.GetType() == typeof(List<Dictionary<String, Object>>))
                {
                    // Create JSON string
                    payload = JsonConvert.SerializeObject(tmpObjectToEncrypt);
                }
                else
                {
                    payload = tmpObjectToEncrypt.ToString();
                }

                Tuple<byte[], byte[], byte[]> aesResult = CryptUtil.EncryptAES(System.Text.Encoding.UTF8.GetBytes(payload), configuration.SymmetricKeysize, configuration.SymmetricMode, configuration.SymmetricPadding);

                // Generate a random IV
                byte[] ivBytes = aesResult.Item1;
                // Generate an AES secret key
                byte[] secretKeyBytes = aesResult.Item2;
                // Encrypt payload
                byte[] encryptedDataBytes = aesResult.Item3;

                String ivValue = CryptUtil.Encode(ivBytes, configuration.DataEncoding);
                String encryptedDataValue = CryptUtil.Encode(encryptedDataBytes, configuration.DataEncoding);

                // Encrypt secret key with issuer's key
                byte[] encryptedSecretKey = CryptUtil.EncrytptRSA(secretKeyBytes, this.publicKey, configuration.OaepEncryptionPadding);
                String encryptedKeyValue = CryptUtil.Encode(encryptedSecretKey, configuration.DataEncoding);

                String fingerprintHexString = publicKeyFingerPrint;

                String baseKey = "";
                String fieldName = fieldToEncrypt;
                if (fieldToEncrypt.IndexOf(".") > 0)
                {
                    baseKey = fieldToEncrypt.Substring(0, fieldToEncrypt.IndexOf("."));
                    baseKey += ".";

                    fieldName = fieldToEncrypt.Substring(fieldToEncrypt.LastIndexOf(".") + 1);
                }

                if (configuration.PublicKeyFingerprintFiledName != null)
                {
                    smartMap.Add(baseKey + configuration.PublicKeyFingerprintFiledName, fingerprintHexString);
                }
                if (configuration.OaepHashingAlgorithmFieldName != null)
                {
                    smartMap.Add(baseKey + configuration.OaepHashingAlgorithmFieldName, configuration.OaepHashingAlgorithm);
                }
                smartMap.Add(baseKey + configuration.IvFieldName, ivValue);
                smartMap.Add(baseKey + configuration.EncryptedKeyFiledName, encryptedKeyValue);
                smartMap.Add(baseKey + fieldName, encryptedDataValue);

            }
            return smartMap;

        }

        public override IDictionary<String, Object> Decrypt(IDictionary<String, Object> map)
        {
            SmartMap smartMap = new SmartMap(map);
            if (this.privateKey == null) {
                return smartMap;
            }

            foreach (String fieldToDecrypt in configuration.FieldsToDecrypt)
            {
                if (!smartMap.ContainsKey(fieldToDecrypt))
                {
                    continue;
                }

                String baseKey = "";
                String encryptedDataFieldName = fieldToDecrypt;

                if (fieldToDecrypt.IndexOf(".") > 0)
                {
                    baseKey = fieldToDecrypt.Substring(0, fieldToDecrypt.LastIndexOf("."));
                    encryptedDataFieldName = fieldToDecrypt.Substring(fieldToDecrypt.LastIndexOf(".") + 1);
                }

                //need to read the key
                String encryptedKeyFieldPath = buildFieldPath(baseKey, configuration.EncryptedKeyFiledName);
                String encryptedKey = (String)smartMap.Get(encryptedKeyFieldPath);
                smartMap.Remove(encryptedKeyFieldPath);

                byte[] encryptedKeyByteArray = CryptUtil.Decode(encryptedKey, configuration.DataEncoding);

                //need to decrypt with RSA
                byte[] secretKeyBytes = null;
                String oaepHashingAlgorithmFieldPath = buildFieldPath(baseKey, configuration.OaepHashingAlgorithmFieldName);
                if (smartMap.ContainsKey(oaepHashingAlgorithmFieldPath))
                {
                    string oaepHashingAlgorithm = (String) smartMap.Get(oaepHashingAlgorithmFieldPath);
                    oaepHashingAlgorithm = oaepHashingAlgorithm.Replace("SHA", "SHA-");

                    smartMap.Remove(oaepHashingAlgorithmFieldPath);

                    RSAEncryptionPadding customEncryptionPadding = configuration.OaepEncryptionPadding;
                    if (oaepHashingAlgorithm.Equals("SHA-256"))
                    {
                        customEncryptionPadding = RSAEncryptionPadding.OaepSHA256;
                    }
                    else if (oaepHashingAlgorithm.Equals("SHA-512"))
                    {
                        customEncryptionPadding = RSAEncryptionPadding.OaepSHA512;
                    }
                    secretKeyBytes = CryptUtil.DecryptRSA(encryptedKeyByteArray, this.privateKey, customEncryptionPadding);

                }
                else
                {
                    secretKeyBytes = CryptUtil.DecryptRSA(encryptedKeyByteArray, this.privateKey, configuration.OaepEncryptionPadding);
                }

                //need to read the iv
                String ivFieldPath = buildFieldPath(baseKey, configuration.IvFieldName);
                String ivString = (String) smartMap.Get(ivFieldPath);
                smartMap.Remove(ivFieldPath);

                byte[] ivByteArray = CryptUtil.Decode(ivString.ToString(), configuration.DataEncoding);

                // remove the field that are not required in the map
                String publicKeyFingerprintFieldPath = buildFieldPath(baseKey, configuration.PublicKeyFingerprintFiledName);
                if (smartMap.ContainsKey(publicKeyFingerprintFieldPath))
                {
                    smartMap.Remove(publicKeyFingerprintFieldPath);
                }

                //need to decrypt the data
                String encryptedDataFieldPath = buildFieldPath(baseKey, encryptedDataFieldName);
                String encryptedData = (String) smartMap.Get(encryptedDataFieldPath);
                smartMap.Remove(encryptedDataFieldPath);
                byte[] encryptedDataByteArray = CryptUtil.Decode(encryptedData, configuration.DataEncoding);

                byte[] decryptedDataByteArray = CryptUtil.DecryptAES(ivByteArray, secretKeyBytes, encryptedDataByteArray, configuration.SymmetricKeysize, configuration.SymmetricMode, configuration.SymmetricPadding);
                String decryptedDataString = System.Text.Encoding.UTF8.GetString(decryptedDataByteArray);

                if (decryptedDataString.StartsWith("{"))
                {
                    Dictionary<String, Object> decryptedDataMap = JsonConvert.DeserializeObject<Dictionary<String, Object>>(decryptedDataString);
                    foreach (KeyValuePair<String, Object> entry in decryptedDataMap)
                    {
                        smartMap.Add(encryptedDataFieldPath + "." + entry.Key, entry.Value);
                    }
                }
                else if (decryptedDataString.StartsWith("["))
                {
                    List<Dictionary<String, Object>> decryptedDataList = JsonConvert.DeserializeObject<List<Dictionary<String, Object>>>(decryptedDataString);
                    smartMap.Add(encryptedDataFieldPath, decryptedDataList);
                }
                else
                {
                    smartMap.Add(encryptedDataFieldPath, decryptedDataString);
                }

            }
            return smartMap;
        }

        private String buildFieldPath(String baseKey, String fieldName)
        {
            StringBuilder fieldPath = new StringBuilder();
            if (!string.IsNullOrEmpty(baseKey))
            {
                fieldPath.Append(baseKey).Append(".");
            }
            fieldPath.Append(fieldName);
            return fieldPath.ToString();
        }
    }
}
