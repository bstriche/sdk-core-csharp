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
	public class MultiplePathUserPostTest : BaseTest
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
        public void Test_get_user_posts_with_mutplie_path()
        {
            

            

            RequestMap map = new RequestMap();
            map.Set ("user_id", "1");
            map.Set ("post_id", "2");
            
            
            List<MultiplePathUserPost> responseList = MultiplePathUserPost.List(map);
            MultiplePathUserPost response = responseList[0];

            List<string> ignoreAsserts = new List<string>();
            
            BaseTest.assertEqual(ignoreAsserts, response, "id", "1");
            BaseTest.assertEqual(ignoreAsserts, response, "title", "My Title");
            BaseTest.assertEqual(ignoreAsserts, response, "body", "some body text");
            BaseTest.assertEqual(ignoreAsserts, response, "userId", "1");
            

            BaseTest.putResponse("get_user_posts_with_mutplie_path", responseList[0]);
            
        }
        
            
            
            
            
        
            
            
                        

        [Test ()]
        public void Test_update_user_posts_with_mutplie_path()
        {
            

            

            RequestMap map = new RequestMap();
            map.Set ("user_id", "1");
            map.Set ("post_id", "1");
            map.Set ("testQuery", "testQuery");
            map.Set ("name", "Joe Bloggs");
            map.Set ("username", "jbloggs");
            map.Set ("email", "name@example.com");
            map.Set ("phone", "1-770-736-8031");
            map.Set ("website", "hildegard.org");
            map.Set ("address.line1", "2000 Purchase Street");
            map.Set ("address.city", "New York");
            map.Set ("address.state", "NY");
            map.Set ("address.postalCode", "10577");
            
            
            MultiplePathUserPost response = new MultiplePathUserPost(map).Update ();

            List<string> ignoreAsserts = new List<string>();
            

            BaseTest.assertEqual(ignoreAsserts, response, "website", "hildegard.org");
            BaseTest.assertEqual(ignoreAsserts, response, "address.instructions.doorman", "true");
            BaseTest.assertEqual(ignoreAsserts, response, "address.instructions.text", "some delivery instructions text");
            BaseTest.assertEqual(ignoreAsserts, response, "address.city", "New York");
            BaseTest.assertEqual(ignoreAsserts, response, "address.postalCode", "10577");
            BaseTest.assertEqual(ignoreAsserts, response, "address.id", "1");
            BaseTest.assertEqual(ignoreAsserts, response, "address.state", "NY");
            BaseTest.assertEqual(ignoreAsserts, response, "address.line1", "2000 Purchase Street");
            BaseTest.assertEqual(ignoreAsserts, response, "phone", "1-770-736-8031");
            BaseTest.assertEqual(ignoreAsserts, response, "name", "Joe Bloggs");
            BaseTest.assertEqual(ignoreAsserts, response, "id", "1");
            BaseTest.assertEqual(ignoreAsserts, response, "email", "name@example.com");
            BaseTest.assertEqual(ignoreAsserts, response, "username", "jbloggs");
            

            BaseTest.putResponse("update_user_posts_with_mutplie_path", response);
            
        }
        
            
            
            
            
            
        
            
            
            
            
                        

        [Test ()]
        public void Test_delete_user_posts_with_mutplie_path()
        {
            

            
        
            RequestMap map = new RequestMap();
            map.Set ("user_id", "1");
            map.Set ("post_id", "2");
            
            
            MultiplePathUserPost response = MultiplePathUserPost.Delete("",map);
            Assert.NotNull (response);

            List<string> ignoreAsserts = new List<string>();
            

            

            BaseTest.putResponse("delete_user_posts_with_mutplie_path", response);
            
        }
        

            
            
            
        
    }
}
