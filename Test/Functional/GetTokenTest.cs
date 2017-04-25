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
using NUnit.Framework;
using Test;


using MasterCard.Core;
using MasterCard.Core.Exceptions;
using MasterCard.Core.Model;
using MasterCard.Core.Security.OAuth;
using MasterCard.Core.Security.MDES;
using MasterCard.Core.Security.Installments;
using System.Threading;
using Environment = MasterCard.Core.Model.Constants.Environment;


namespace TestMasterCard
{


	[TestFixture ()]
	public class GetTokenTest : BaseTest
	{

		[SetUp]
		public void setup ()
		{
			ApiConfig.SetDebug(true);
			ResourceConfig.Instance.SetEnvironment(Environment.SANDBOX_STATIC);

            var path = MasterCard.Core.Util.GetCurrenyAssemblyPath();

            var authentication = new OAuthAuthentication("L5BsiPgaF-O3qA36znUATgQXwJB6MRoMSdhjd7wt50c97279!50596e52466e3966546d434b7354584c4975693238513d3d", path + "\\Test\\mcapi_sandbox_key.p12", "test", "password");
            ApiConfig.SetAuthentication(authentication);

            var interceptor = new MDESCryptography(path+"\\Test\\mastercard_public.crt", path+"\\Test\\mastercard_private.pem");
			ApiConfig.AddCryptographyInterceptor (interceptor);

			var interceptor2 = new InstallmentCryptography(path+"\\Test\\installments_public.crt", null);
			ApiConfig.AddCryptographyInterceptor (interceptor2);

		}

		[Test()]
		public void Test_example_get_token()
		{
			// 

			

			

			RequestMap map = new RequestMap();
			map.Set ("requestId", "123456");
			map.Set ("paymentAppInstanceId", "123456789");
			map.Set ("tokenUniqueReference", "DWSPMC000000000132d72d4fcb2f4136a0532d3093ff1a45");
			map.Set ("includeTokenDetail", "true");

			List<string> ignoreAsserts = new List<string>();

			GetToken response = GetToken.Create(map);
			BaseTest.assertEqual(ignoreAsserts, response, "responseId", "123456");
			BaseTest.assertEqual(ignoreAsserts, response, "token.tokenUniqueReference", "DWSPMC000000000132d72d4fcb2f4136a0532d3093ff1a45");
			BaseTest.assertEqual(ignoreAsserts, response, "token.status", "ACTIVE");
			BaseTest.assertEqual(ignoreAsserts, response, "token.productConfig.brandLogoAssetId", "800200c9-629d-11e3-949a-0739d27e5a67");
			BaseTest.assertEqual(ignoreAsserts, response, "token.productConfig.isCoBranded", "true");
			BaseTest.assertEqual(ignoreAsserts, response, "token.productConfig.coBrandName", "Test CoBrand Name");
			BaseTest.assertEqual(ignoreAsserts, response, "token.productConfig.coBrandLogoAssetId", "Test coBrand Logo AssetId");
			BaseTest.assertEqual(ignoreAsserts, response, "token.productConfig.cardBackgroundCombinedAssetId", "739d27e5-629d-11e3-949a-0800200c9a66");
			BaseTest.assertEqual(ignoreAsserts, response, "token.productConfig.foregroundColor", "000000");
			BaseTest.assertEqual(ignoreAsserts, response, "token.productConfig.issuerName", "Issuing Bank");
			BaseTest.assertEqual(ignoreAsserts, response, "token.productConfig.shortDescription", "Bank Rewards MasterCard");
			BaseTest.assertEqual(ignoreAsserts, response, "token.productConfig.longDescription", "Bank Rewards MasterCard with the super duper rewards program");
			BaseTest.assertEqual(ignoreAsserts, response, "token.productConfig.customerServiceUrl", "https://bank.com/customerservice");
			BaseTest.assertEqual(ignoreAsserts, response, "token.productConfig.termsAndConditionsUrl", "https://bank.com/termsAndConditions");
			BaseTest.assertEqual(ignoreAsserts, response, "token.productConfig.privacyPolicyUrl", "https://bank.com/privacy");
			BaseTest.assertEqual(ignoreAsserts, response, "token.productConfig.issuerProductConfigCode", "123456");
			BaseTest.assertEqual(ignoreAsserts, response, "token.tokenInfo.tokenPanSuffix", "1234");
			BaseTest.assertEqual(ignoreAsserts, response, "token.tokenInfo.accountPanSuffix", "5675");
			BaseTest.assertEqual(ignoreAsserts, response, "token.tokenInfo.tokenExpiry", "1018");
			BaseTest.assertEqual(ignoreAsserts, response, "token.tokenInfo.dsrpCapable", "true");
			BaseTest.assertEqual(ignoreAsserts, response, "token.tokenInfo.tokenAssuranceLevel", "1");
			BaseTest.assertEqual(ignoreAsserts, response, "tokenDetail.encryptedData.tokenNumber", "5123456789012345");
			BaseTest.assertEqual(ignoreAsserts, response, "tokenDetail.encryptedData.expiryMonth", "12");
			BaseTest.assertEqual(ignoreAsserts, response, "tokenDetail.encryptedData.expiryYear", "22");
			BaseTest.assertEqual(ignoreAsserts, response, "tokenDetail.tokenUniqueReference", "DWSPMC000000000132d72d4fcb2f4136a0532d3093ff1a45");

			BaseTest.putResponse("example_get_token", response);
			
		}

    




	}
}
