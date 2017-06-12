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
        public List<String> TriggeringEndPath { get;   set; }
        public List<String> FieldsToEncrypt { get;   set; }
        public List<String> FieldsToDecrypt { get;   set; }

        public CipherMode SymmetricMode { get;   set; }
        public PaddingMode SymmetricPadding { get;   set; }
        public int SymmetricKeysize { get;   set; }

        public RSAEncryptionPadding OaepEncryptionPadding { get;   set; }
        public String OaepHashingAlgorithm { get;   set; }

        public HashingAlgorithm PublicKeyFingerprintHashing { get;   set; }
        public String IvFieldName { get;   set; }
        public String OaepHashingAlgorithmFieldName { get;   set; }
        public String EncryptedKeyFiledName { get;   set; }
        public String EncryptedDataFieldName { get;   set; }
        public String PublicKeyFingerprintFiledName { get;   set; }
        public DataEncoding DataEncoding { get;   set; }

        public Config() {

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