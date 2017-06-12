﻿/*
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

namespace MasterCard.Core.Security.Installments
{
	public class InstallmentCryptography : FieldLevelEncryption
	{

        public InstallmentCryptography(String publicKeyLocation, String privateKeyLocation, X509KeyStorageFlags keyStorageFlags = X509KeyStorageFlags.DefaultKeySet) 
        : base(publicKeyLocation, privateKeyLocation, Installments(), keyStorageFlags){

		}

        public InstallmentCryptography(byte[] rawPublicKeyData, byte[] rawPrivateKeyData, X509KeyStorageFlags keyStorageFlags = X509KeyStorageFlags.DefaultKeySet) 
        : base(rawPublicKeyData, rawPrivateKeyData, Installments(), keyStorageFlags) {

        }

		private static Config Installments()
        {
            Config tmpConfig = new Config();
            tmpConfig.TriggeringEndPath = new List<String>(new String[] { "/installmentConfigdata", "/calculateInstallment", "/processInstallment", "/receiveApproval" });
            tmpConfig.FieldsToEncrypt = new List<String>(new String[] { "configReqData.primaryAccountNumber", "calculatorReqData.primaryAccountNumber", "processInstallmentReqData.primaryAccountNumber", "receiveIssuerApprReqData.primaryAccountNumber" });
            tmpConfig.FieldsToDecrypt = new List<String>(new String[] { "" });

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
	}
}