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
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using MasterCard.Core.Security.Fle;

namespace MasterCard.Core.Security.MDES
{
	public class MDESCryptography : FieldLevelEncryption
	{
        public MDESCryptography(String publicKeyLocation, String privateKeyLocation, X509KeyStorageFlags keyStorageFlags = X509KeyStorageFlags.DefaultKeySet) 
        : base(publicKeyLocation, privateKeyLocation, config(), null, keyStorageFlags){

		}

        public MDESCryptography(byte[] rawPublicKeyData, byte[] rawPrivateKeyData, X509KeyStorageFlags keyStorageFlags = X509KeyStorageFlags.DefaultKeySet) 
        : base(rawPublicKeyData, rawPrivateKeyData, config(), null, keyStorageFlags) {

        }

        public MDESCryptography(String publicKeyLocation, String privateKeyLocation, String publicKeyFingerprint, X509KeyStorageFlags keyStorageFlags = X509KeyStorageFlags.DefaultKeySet) 
        : base(publicKeyLocation, privateKeyLocation, config(), publicKeyFingerprint, keyStorageFlags){

		}

        public MDESCryptography(byte[] rawPublicKeyData, byte[] rawPrivateKeyData, String publicKeyFingerprint, X509KeyStorageFlags keyStorageFlags = X509KeyStorageFlags.DefaultKeySet) 
        : base(rawPublicKeyData, rawPrivateKeyData, config(), publicKeyFingerprint, keyStorageFlags) {

        }

        //publicKeyFingerprint

		private static Config config()
        {
            Config tmpConfig = new Config();
            tmpConfig.TriggeringEndPath = new List<String>(new String[] { "/tokenize", "/searchTokens", "/getToken", "/transact", "/notifyTokenUpdated" });
            tmpConfig.FieldsToEncrypt = new List<String>(new String[] { "cardInfo.encryptedData", "encryptedPayload.encryptedData" });
            tmpConfig.FieldsToDecrypt = new List<String>(new String[] { "encryptedPayload.encryptedData", "tokenDetail.encryptedData" });

            tmpConfig.SymmetricMode = CipherMode.CBC;
            tmpConfig.SymmetricPadding = PaddingMode.PKCS7;
            tmpConfig.SymmetricKeysize = 128;

            tmpConfig.OaepEncryptionPadding = RSAEncryptionPadding.OaepSHA256;
            tmpConfig.OaepHashingAlgorithm = "SHA256";

            tmpConfig.PublicKeyFingerprintHashing = HashingAlgorithm.SHA256;

            tmpConfig.IvFieldName = "iv";
            tmpConfig.OaepHashingAlgorithmFieldName = "oaepHashingAlgorithm";
            tmpConfig.EncryptedKeyFiledName = "encryptedKey";
            tmpConfig.EncryptedDataFieldName = "encryptedData";
            tmpConfig.PublicKeyFingerprintFiledName = "publicKeyFingerprint";
            tmpConfig.DataEncoding = DataEncoding.HEX;

            return tmpConfig;
        }

	}
}