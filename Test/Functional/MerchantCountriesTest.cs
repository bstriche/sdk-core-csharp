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


using MasterCard.Core;
using MasterCard.Core.Exceptions;
using MasterCard.Core.Model;
using MasterCard.Core.Security.OAuth;
using MasterCard.Core.Security.MDES;



namespace TestMasterCard
{



    [Ignore("Tests actual sandbox API - Change to TestFixture and enter correct creds below to test")]
    public class MerchantCountriesTest
	{

		[SetUp]
		public void setup ()
		{
            ApiConfig.SetDebug (true);
            ApiConfig.SetSandbox(true);
            var currentPath = MasterCard.Core.Util.GetAssemblyPath();
            var authentication = new OAuthAuthentication("TESTING00-O3qA36znUATgQXwJB6MRoMSdhjd7wt50c9TEST!50596e52466e3966546d434b7354584c497569323851TEST", currentPath + "\\Test\\certs\\fake-key.p12", "fake-key", "fakepassword", System.Security.Cryptography.X509Certificates.X509KeyStorageFlags.MachineKeySet);
            ApiConfig.SetAuthentication (authentication);

            var interceptor = new MDESCryptography(currentPath + "\\Test\\certs\\fake-encryption-public.crt", currentPath + "\\Test\\certs\\fake-encryption-private.pem");
            ApiConfig.AddCryptographyInterceptor(interceptor);
        }


        
            
            
            
            
            
            
                        

        [Test ()]
        public void example_merchants_country_Test()
        {


            RequestMap parameters = new RequestMap();
            
            parameters.Set ("details", "acceptance.paypass");
            
            MerchantCountries response = MerchantCountries.Query(parameters);
            Assert.That("AUSTRALIA", Is.EqualTo(response["Countries.Country[0].Name"].ToString()).IgnoreCase);
            Assert.That("AUS", Is.EqualTo(response["Countries.Country[0].Code"].ToString()).IgnoreCase);
            Assert.That("TRUE", Is.EqualTo(response["Countries.Country[0].Geocoding"].ToString()).IgnoreCase);
            Assert.That("AUSTRIA", Is.EqualTo(response["Countries.Country[1].Name"].ToString()).IgnoreCase);
            Assert.That("AUT", Is.EqualTo(response["Countries.Country[1].Code"].ToString()).IgnoreCase);
            Assert.That("TRUE", Is.EqualTo(response["Countries.Country[1].Geocoding"].ToString()).IgnoreCase);
            Assert.That("BELGIUM", Is.EqualTo(response["Countries.Country[2].Name"].ToString()).IgnoreCase);
            Assert.That("BEL", Is.EqualTo(response["Countries.Country[2].Code"].ToString()).IgnoreCase);
            Assert.That("TRUE", Is.EqualTo(response["Countries.Country[2].Geocoding"].ToString()).IgnoreCase);
            

        }
        
            
        

    }
}
