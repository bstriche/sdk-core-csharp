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

using NUnit.Framework;
using MasterCard.Core;
using MasterCard.Core.Model;
using MasterCard.Core.Security.OAuth;
using MasterCard.Api.LostStolen;

namespace MasterCard.Api.LostStolen
{


	[TestFixture ()]
	public class AccountInquiryTest
	{

		[SetUp ()]
		public void setup ()
		{
            var authentication = new OAuthAuthentication ("gVaoFbo86jmTfOB4NUyGKaAchVEU8ZVPalHQRLTxeaf750b6!414b543630362f426b4f6636415a5973656c33735661383d", "../../prod_key.p12", "alias", "password");
            ApiConfig.setAuthentication (authentication);
		}


        
            
            
                        

        [Test ()]
        public void example_stolen_Test()
        {
            //example_stolen
            var map = new BaseMap();
            map.Set ("AccountInquiry.AccountNumber", "5343434343434343");
            
            AccountInquiry response = new AccountInquiry(map).Update ();
            Assert.AreEqual("True", response["Account.Listed"]);
            Assert.AreEqual("S", response["Account.ReasonCode"]);
            Assert.AreEqual("STOLEN", response["Account.Reason"]);
            
        }
        

        [Test ()]
        public void example_lost_Test()
        {
            //example_lost
            var map = new BaseMap();
            map.Set ("AccountInquiry.AccountNumber", "5222222222222200");
            
            AccountInquiry response = new AccountInquiry(map).Update ();
            Assert.AreEqual("True", response["Account.Listed"]);
            Assert.AreEqual("L", response["Account.ReasonCode"]);
            Assert.AreEqual("LOST", response["Account.Reason"]);
            
        }
        
            
            
            
            
        
    }
}
