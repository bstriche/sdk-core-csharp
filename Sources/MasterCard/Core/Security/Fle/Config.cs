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

namespace MasterCard.Core.Security.Fle
{
    public class Config : IEquatable<Config>
	{
        public List<String> TriggeringEndPath { get; protected set; }
        public List<String> FieldsToEncrypt { get; protected set; }
        public List<String> FieldsToDecrypt { get; protected set; }

        public CipherMode SymmetricMode { get; protected set; }
        public PaddingMode SymmetricPadding { get; protected set; }
        public int SymmetricKeysize { get; protected set; }

        public RSAEncryptionPadding OaepEncryptionPadding { get; protected set; }
        public String OaepHashingAlgorithm { get; protected set; }

        public HashingAlgorithm PublicKeyFingerprintHashing { get; protected set; }
        public String IvFieldName { get; protected set; }
        public String OaepHashingAlgorithmFieldName { get; protected set; }
        public String EncryptedKeyFiledName { get; protected set; }
        public String EncryptedDataFieldName { get; protected set; }
        public String PublicKeyFingerprintFiledName { get; protected set; }
        public DataEncoding DataEncoding { get; protected set; }

        private Config() {

        }


        public static Config MDES() {
            Config tmpConfig = new Config();
            tmpConfig.TriggeringEndPath = new List<String>(new String[] {"/tokenize", "/searchTokens", "/getToken", "/transact", "/notifyTokenUpdated"});
            tmpConfig.FieldsToEncrypt = new List<String>(new String[] {"cardInfo.encryptedData", "encryptedPayload.encryptedData"});
            tmpConfig.FieldsToDecrypt = new List<String>(new String[] {"encryptedPayload.encryptedData", "tokenDetail.encryptedData"});

            tmpConfig.SymmetricMode = CipherMode.CBC;
            tmpConfig.SymmetricPadding = PaddingMode.PKCS7;
            tmpConfig.SymmetricKeysize = 256;

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


        public static Config Installments() {
            Config tmpConfig = new Config();
            tmpConfig.TriggeringEndPath = new List<String>(new String[] {"/instalmentConfigdata","/calculateInstalment", "/processInstalment"});
            tmpConfig.FieldsToEncrypt = new List<String>(new String[] {"configReqData.primaryAccountNumber", "calculatorReqData.primaryAccountNumber", "processInstalmentReqData.primaryAccountNumber"});
            tmpConfig.FieldsToDecrypt = new List<String>(new String[] {""});

            tmpConfig.SymmetricMode = CipherMode.CBC;
            tmpConfig.SymmetricPadding = PaddingMode.PKCS7;
            tmpConfig.SymmetricKeysize = 256;

            tmpConfig.OaepEncryptionPadding = RSAEncryptionPadding.OaepSHA256;
            tmpConfig.OaepHashingAlgorithm = "SHA256";

            tmpConfig.PublicKeyFingerprintHashing = HashingAlgorithm.SHA256;

            tmpConfig.IvFieldName = "iv";
            tmpConfig.OaepHashingAlgorithmFieldName = null;
            tmpConfig.EncryptedKeyFiledName = "wrappedKey";
            tmpConfig.EncryptedDataFieldName = "primaryAccountNumber";
            tmpConfig.PublicKeyFingerprintFiledName = null;
            tmpConfig.DataEncoding = DataEncoding.BASE64;


            return tmpConfig;
        }

        public bool Equals(Config other)
        {
            return this.TriggeringEndPath.Equals(other.TriggeringEndPath) &&
                this.FieldsToEncrypt.Equals(other.FieldsToEncrypt) &&
                this.FieldsToDecrypt.Equals(other.FieldsToDecrypt) &&
                this.SymmetricMode == other.SymmetricMode &&
                this.SymmetricPadding == other.SymmetricPadding &&
                this.SymmetricKeysize == other.SymmetricKeysize &&
                this.OaepEncryptionPadding == other.OaepEncryptionPadding &&
                this.OaepHashingAlgorithm.Equals(other.OaepHashingAlgorithm) &&
                this.PublicKeyFingerprintHashing == other.PublicKeyFingerprintHashing &&
                this.IvFieldName.Equals(other.IvFieldName) &&
                this.OaepHashingAlgorithmFieldName.Equals(other.OaepHashingAlgorithmFieldName) &&
                this.EncryptedKeyFiledName.Equals(other.EncryptedKeyFiledName) &&
                this.EncryptedDataFieldName.Equals(other.EncryptedDataFieldName) &&
                this.PublicKeyFingerprintFiledName.Equals(other.PublicKeyFingerprintFiledName) &&
                this.DataEncoding == other.DataEncoding;
        }
    }

    public enum DataEncoding {HEX, BASE64};  

    public enum HashingAlgorithm {SHA1, SHA256, SHA512}; 
}