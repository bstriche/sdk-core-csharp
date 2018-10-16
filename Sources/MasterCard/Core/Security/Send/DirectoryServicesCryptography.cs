using MasterCard.Core.Model;
using MasterCard.Core.Security;
using MasterCard.Core.Security.Fle;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using RestSharp;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace MasterCard.Core.Security.Send
{
    public class DirectoryServicesCryptography : FieldLevelEncryption, HttpRequestCryptographyInterceptor
    {
        public static String ENCRYPTED_PAYLOAD = "encrypted_payload";
        public static String ENCRYPTED_PAYLOAD_DATA = ENCRYPTED_PAYLOAD + ".data";

        public DirectoryServicesCryptography(String publicKeyLocation, String privateKeyLocation, X509KeyStorageFlags keyStorageFlags = X509KeyStorageFlags.DefaultKeySet)
            : base(publicKeyLocation, privateKeyLocation, config(), null, keyStorageFlags) { }

        public DirectoryServicesCryptography(byte[] rawPublicKeyData, byte[] rawPrivateKeyData, X509KeyStorageFlags keyStorageFlags = X509KeyStorageFlags.DefaultKeySet)
    : base(rawPublicKeyData, rawPrivateKeyData, config(), null, keyStorageFlags)
        {
        }

        public DirectoryServicesCryptography(String publicKeyLocation, String privateKeyLocation, String publicKeyFingerprint, X509KeyStorageFlags keyStorageFlags = X509KeyStorageFlags.DefaultKeySet)
        : base(publicKeyLocation, privateKeyLocation, config(), publicKeyFingerprint, keyStorageFlags)
        {
        }

        public DirectoryServicesCryptography(byte[] rawPublicKeyData, byte[] rawPrivateKeyData, String publicKeyFingerprint, X509KeyStorageFlags keyStorageFlags = X509KeyStorageFlags.DefaultKeySet)
        : base(rawPublicKeyData, rawPrivateKeyData, config(), publicKeyFingerprint, keyStorageFlags)
        {
        }


        private static Config config()
        {
            Config tmpConfig = new Config();
            tmpConfig.TriggeringEndPath = new List<String>(new String[] {
                "/send/.*/partners/.*/mappings",
                "/send/.*/partners/.*/mappings/.*",
                "/send/.*/partners/.*/mappings/.*/accounts",
                "/send/.*/partners/.*/mappings/.*/accounts/.*",
                "/send/.*/partners/.*/mappings/.*/accounts/.*/additional-data",
                "/send/.*/partners/.*/mappings/.*/accounts/.*/additional-data/.*",
                "/send/.*/partners/.*/mappings/search"
            });
            tmpConfig.FieldsToEncrypt = new List<String>(new String[] {
                "mapping",
                "search",
                "account",
                "additional_data"
            });
            tmpConfig.FieldsToDecrypt = new List<String>(new String[] { ENCRYPTED_PAYLOAD_DATA });

            
            tmpConfig.SymmetricMode = CipherMode.CBC;
            tmpConfig.SymmetricPadding = PaddingMode.PKCS7; //PKCS5 and PKCS7 are considered the same. https://social.msdn.microsoft.com/Forums/en-US/13a20d89-7d84-4f7d-8f5c-5ae108a7f5cf
            tmpConfig.SymmetricKeysize = 128;

            tmpConfig.OaepEncryptionPadding = RSAEncryptionPadding.OaepSHA256;
            tmpConfig.OaepHashingAlgorithmFieldName = "x-oaep-hashing-algorithm";
            tmpConfig.OaepHashingAlgorithm = "SHA256";

            tmpConfig.PublicKeyFingerprintHashing = HashingAlgorithm.SHA256;
            tmpConfig.PublicKeyFingerprintFiledName = "x-public-key-fingerprint";

            tmpConfig.IvFieldName = "x-iv";
             
            tmpConfig.EncryptedKeyFiledName = "x-encrypted-key";
            tmpConfig.EncryptedDataFieldName = ENCRYPTED_PAYLOAD_DATA;
            tmpConfig.DataEncoding = DataEncoding.BASE64;
  
            //tmpConfig.symmetricCipher = "AES";

            //tmpConfig.asymmetricCipher = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";

            return tmpConfig;

        }

        public IDictionary<string, object> AddCustomHeaders(IDictionary<string, object> headerMap, IDictionary<string, object> objectMap)
        {
            List<String> headers = new List<String>(new String[] {
                config().EncryptedKeyFiledName,
                config().OaepHashingAlgorithmFieldName,
                config().PublicKeyFingerprintFiledName,
                config().IvFieldName
            });

            foreach (String header in headers)
            {
                object o;
                objectMap.TryGetValue(header, out o);
                headerMap.Add(header, o);
                objectMap.Remove(header);
            }

            return headerMap;
        }

      

        public IDictionary<string, object> RemoveCustomHeaders(IList<Parameter> headers, IDictionary<String, Object> objectMap)
        {
            SmartMap smartmap = new SmartMap(objectMap);

            if (!smartmap.ContainsKey(ENCRYPTED_PAYLOAD_DATA)) { 
                return objectMap;
            }

            foreach (Parameter header in headers)
            {
                if (header.Name.Equals(config().EncryptedKeyFiledName))
                {
                    smartmap.Add(ENCRYPTED_PAYLOAD + "." + config().EncryptedKeyFiledName, header.Value);
                }
                else if (header.Name.Equals(config().IvFieldName))
                {
                    smartmap.Add(ENCRYPTED_PAYLOAD + "." + config().IvFieldName, header.Value);
                }
                else if (header.Name.Equals(config().PublicKeyFingerprintFiledName))
                {
                    smartmap.Add(ENCRYPTED_PAYLOAD + "." + config().PublicKeyFingerprintFiledName, header.Value);
                }
                else if (header.Name.Equals(config().OaepHashingAlgorithmFieldName))
                {
                    smartmap.Add(ENCRYPTED_PAYLOAD + "." + config().OaepHashingAlgorithmFieldName, header.Value);
                }
            }

            
            return smartmap;
        }

        public override IDictionary<String, Object> Encrypt(IDictionary<String, Object> map)
        {

            //requestMap is a SmartMap it offers a easy way to do nested lookups.
            SmartMap smartMap = new SmartMap(map);
            if (this.publicKey != null)
            {
                // 1) Extract the encrypted_payload from map
                Object tmpObjectToEncrypt = smartMap;

                String payload;

                // 2) Create JSON string
                payload = JsonConvert.SerializeObject(tmpObjectToEncrypt);
                // 3) Escape the JSON string
                payload = CryptUtil.SanitizeJson(payload);

                Tuple<byte[], byte[], byte[]> aesResult = CryptUtil.EncryptAES(System.Text.Encoding.UTF8.GetBytes(payload), configuration.SymmetricKeysize, configuration.SymmetricMode, configuration.SymmetricPadding);

                // 4) generate random iv
                byte[] ivBytes = aesResult.Item1;
                // 5) generate AES SecretKey
                byte[] secretKeyBytes = aesResult.Item2;
                // 6) encrypt payload
                byte[] encryptedDataBytes = aesResult.Item3;

                String ivValue = CryptUtil.Encode(ivBytes, configuration.DataEncoding);
                String encryptedDataValue = CryptUtil.Encode(encryptedDataBytes, configuration.DataEncoding);

                // 7) encrypt secretKey with issuer key
                byte[] encryptedSecretKey = CryptUtil.EncrytptRSA(secretKeyBytes, this.publicKey, configuration.OaepEncryptionPadding);
                String encryptedKeyValue = CryptUtil.Encode(encryptedSecretKey, configuration.DataEncoding);

                String fingerprintHexString = publicKeyFingerPrint;
 
                if (configuration.PublicKeyFingerprintFiledName != null)
                {
                    smartMap.Add(configuration.PublicKeyFingerprintFiledName, fingerprintHexString);
                }
                if (configuration.OaepHashingAlgorithmFieldName != null)
                {
                    smartMap.Add(configuration.OaepHashingAlgorithmFieldName, configuration.OaepHashingAlgorithm);
                }
                smartMap.Add(configuration.IvFieldName, ivValue);
                smartMap.Add(configuration.EncryptedKeyFiledName, encryptedKeyValue);
                smartMap.Add(configuration.EncryptedDataFieldName, encryptedDataValue);


                foreach (String fieldToEncrypt in config().FieldsToEncrypt)
                {
                    smartMap.Remove(fieldToEncrypt);
                }
            }
            return smartMap;
        }

        public override IDictionary<String, Object> Decrypt(IDictionary<String, Object> map)
        {
            RequestMap decryptedResponse = new RequestMap(base.Decrypt(map));

            if (decryptedResponse.ContainsKey(ENCRYPTED_PAYLOAD_DATA)
                && decryptedResponse.Get(ENCRYPTED_PAYLOAD_DATA) is IDictionary<String, Object>)
            {
                return (IDictionary<String, Object>)decryptedResponse.Get(ENCRYPTED_PAYLOAD_DATA);
            }

            return map;
        }

    }
}

