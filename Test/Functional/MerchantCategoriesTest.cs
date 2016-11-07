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
	public class MerchantCategoriesTest
	{

		[SetUp]
		public void setup ()
		{
            ApiConfig.SetDebug (true);
            ApiConfig.SetSandbox(true);
            var path = MasterCard.Core.Util.GetCurrenyAssemblyPath();

            var authentication = new OAuthAuthentication ("L5BsiPgaF-O3qA36znUATgQXwJB6MRoMSdhjd7wt50c97279!50596e52466e3966546d434b7354584c4975693238513d3d", path+ "\\Test\\mcapi_sandbox_key.p12", "test", "password");
            ApiConfig.SetAuthentication (authentication);

            var interceptor = new MDESCryptography(path+ "\\Test\\mastercard_public.crt", path+ "\\Test\\mastercard_private.pem");
            ApiConfig.AddCryptographyInterceptor (interceptor);
		}


        
            
            
            
            
            
            
                        

        [Test ()]
        public void example_merchants_category_Test()
        {
            RequestMap parameters = new RequestMap();
            

            MerchantCategories response = MerchantCategories.Query(parameters);
            Assert.That("1Apparel", Is.EqualTo(response["Categories.Category[0]"].ToString()).IgnoreCase);
            Assert.That("2Automotive", Is.EqualTo(response["Categories.Category[1]"].ToString()).IgnoreCase);
            Assert.That("3Beauty", Is.EqualTo(response["Categories.Category[2]"].ToString()).IgnoreCase);
            Assert.That("4Book Stores", Is.EqualTo(response["Categories.Category[3]"].ToString()).IgnoreCase);
            Assert.That("5Convenience Stores", Is.EqualTo(response["Categories.Category[4]"].ToString()).IgnoreCase);
            Assert.That("7Dry Cleaners And Laundry Services", Is.EqualTo(response["Categories.Category[5]"].ToString()).IgnoreCase);
            Assert.That("8Fast Food Restaurants", Is.EqualTo(response["Categories.Category[6]"].ToString()).IgnoreCase);
            Assert.That("9Gift Shops, Hobbies, Jewelers", Is.EqualTo(response["Categories.Category[7]"].ToString()).IgnoreCase);
            Assert.That("10Grocery Stores And Supermarkets", Is.EqualTo(response["Categories.Category[8]"].ToString()).IgnoreCase);
            Assert.That("11Health", Is.EqualTo(response["Categories.Category[9]"].ToString()).IgnoreCase);
            

        }
        
            
        

    }
}
