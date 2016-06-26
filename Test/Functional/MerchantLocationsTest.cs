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


	[TestFixture ()]
	public class MerchantLocationsTest
	{

		[SetUp]
		public void setup ()
		{
            ApiConfig.setDebug (true);
            ApiConfig.setSandbox(true);
            var path = MasterCard.Core.Util.GetCurrenyAssemblyPath();

            var authentication = new OAuthAuthentication ("L5BsiPgaF-O3qA36znUATgQXwJB6MRoMSdhjd7wt50c97279!50596e52466e3966546d434b7354584c4975693238513d3d", path+"\\Test\\mcapi_sandbox_key.p12", "alias", "password");
            ApiConfig.setAuthentication (authentication);

            var interceptor = new MDESCryptography(path+ "\\Test\\mastercard_public.crt", path+ "\\Test\\mastercard_private.pem");
            ApiConfig.AddCryptographyInterceptor (interceptor);
		}


        
            
            
            
            
            
            
                        

        [Test ()]
        public void example_merchants_Test()
        {
            RequestMap parameters = new RequestMap();
            
            parameters.Set ("Details", "acceptance.paypass");
            parameters.Set ("PageOffset", "0");
            parameters.Set ("PageLength", "5");
            parameters.Set ("Latitude", "38.53463");
            parameters.Set ("Longitude", "-90.286781");
            
            

            MerchantLocations response = MerchantLocations.Query(parameters);
            Assert.That("0", Is.EqualTo(response["Merchants.PageOffset"].ToString()).IgnoreCase);
            Assert.That("3", Is.EqualTo(response["Merchants.TotalCount"].ToString()).IgnoreCase);
            Assert.That("36564", Is.EqualTo(response["Merchants.Merchant[0].Id"].ToString()).IgnoreCase);
            Assert.That("Merchant 36564", Is.EqualTo(response["Merchants.Merchant[0].Name"].ToString()).IgnoreCase);
            Assert.That("7 - Dry Cleaners And Laundry Services", Is.EqualTo(response["Merchants.Merchant[0].Category"].ToString()).IgnoreCase);
            Assert.That("Merchant 36564", Is.EqualTo(response["Merchants.Merchant[0].Location.Name"].ToString()).IgnoreCase);
            Assert.That("0.9320591049747101", Is.EqualTo(response["Merchants.Merchant[0].Location.Distance"].ToString()).IgnoreCase);
            Assert.That("MILE", Is.EqualTo(response["Merchants.Merchant[0].Location.DistanceUnit"].ToString()).IgnoreCase);
            Assert.That("3822 West Fork Street", Is.EqualTo(response["Merchants.Merchant[0].Location.Address.Line1"].ToString()).IgnoreCase);
            Assert.That("Great Falls", Is.EqualTo(response["Merchants.Merchant[0].Location.Address.City"].ToString()).IgnoreCase);
            Assert.That("51765", Is.EqualTo(response["Merchants.Merchant[0].Location.Address.PostalCode"].ToString()).IgnoreCase);
            Assert.That("Country Subdivision 517521", Is.EqualTo(response["Merchants.Merchant[0].Location.Address.CountrySubdivision.Name"].ToString()).IgnoreCase);
            Assert.That("Country Subdivision Code 517521", Is.EqualTo(response["Merchants.Merchant[0].Location.Address.CountrySubdivision.Code"].ToString()).IgnoreCase);
            Assert.That("Country 5175215", Is.EqualTo(response["Merchants.Merchant[0].Location.Address.Country.Name"].ToString()).IgnoreCase);
            Assert.That("Country Code 5175215", Is.EqualTo(response["Merchants.Merchant[0].Location.Address.Country.Code"].ToString()).IgnoreCase);
            Assert.That("38.52114017591121", Is.EqualTo(response["Merchants.Merchant[0].Location.Point.Latitude"].ToString()).IgnoreCase);
            Assert.That("-90.28678100000002", Is.EqualTo(response["Merchants.Merchant[0].Location.Point.Longitude"].ToString()).IgnoreCase);
            Assert.That("true", Is.EqualTo(response["Merchants.Merchant[0].Acceptance.PayPass.Register"].ToString()).IgnoreCase);
            

        }
        
            
        

    }
}
