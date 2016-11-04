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
using System.Threading;


namespace TestMasterCard
{


	[TestFixture ()]
	public class UserPostHeaderTest : BaseTest
	{

		[SetUp]
		public void setup ()
		{
            ApiConfig.SetDebug(true);
            ApiConfig.SetSandbox(true);
            var path = MasterCard.Core.Util.GetCurrenyAssemblyPath();

            BaseTest.resetAuthentication();

		}

        
            
            
            
                        

        [Test ()]
        public void Test_get_user_posts_with_header()
        {
            

            

            RequestMap map = new RequestMap();
            map.Set ("user_id", "1");
            
            
            List<UserPostHeader> responseList = UserPostHeader.List(map);
            UserPostHeader response = responseList[0];

            List<string> ignoreAsserts = new List<string>();
            
            BaseTest.assertEqual(ignoreAsserts, response, "id", "1");
            BaseTest.assertEqual(ignoreAsserts, response, "title", "My Title");
            BaseTest.assertEqual(ignoreAsserts, response, "body", "some body text");
            BaseTest.assertEqual(ignoreAsserts, response, "userId", "1");
            

            BaseTest.putResponse("get_user_posts_with_header", responseList[0]);
            
        }
        
            
            
            
            
        
    }
}
