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
	public class UserTest : BaseTest
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
        public void Test_list_users()
        {
            

            

            RequestMap map = new RequestMap();
            
            
            List<User> responseList = User.List(map);
            User response = responseList[0];

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
            

            BaseTest.putResponse("list_users", responseList[0]);
            
        }
        

        [Test ()]
        public void Test_list_users_query()
        {
            

            

            RequestMap map = new RequestMap();
            map.Set ("max", "10");
            
            
            List<User> responseList = User.List(map);
            User response = responseList[0];

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
            

            BaseTest.putResponse("list_users_query", responseList[0]);
            
        }
        
            
            
            
            
        
            
                        

        [Test ()]
        public void Test_create_user()
        {
            

            

            RequestMap map = new RequestMap();
            map.Set ("website", "hildegard.org");
            map.Set ("address.city", "New York");
            map.Set ("address.postalCode", "10577");
            map.Set ("address.state", "NY");
            map.Set ("address.line1", "2000 Purchase Street");
            map.Set ("phone", "1-770-736-8031");
            map.Set ("name", "Joe Bloggs");
            map.Set ("email", "name@example.com");
            map.Set ("username", "jbloggs");
            
            

            List<string> ignoreAsserts = new List<string>();
            

            User response = User.Create(map);
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
            

            BaseTest.putResponse("create_user", response);
            
        }
        
            
            
            
            
            
            
        
            
            
            
            
            
                        

        [Test ()]
        public void Test_get_user()
        {
            

            
        
            RequestMap map = new RequestMap();
            
            map.Set("id", BaseTest.resolveResponseValue("create_user.id"));
            
            User response = User.Read("",map);

            List<string> ignoreAsserts = new List<string>();
            ignoreAsserts.Add("address.city");
            

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
            

            BaseTest.putResponse("get_user", response);
            
        }
        

        [Test ()]
        public void Test_get_user_query()
        {
            

            
        
            RequestMap map = new RequestMap();
            map.Set ("min", "1");
            map.Set ("max", "10");
            
            map.Set("id", BaseTest.resolveResponseValue("create_user.id"));
            
            User response = User.Read("",map);

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
            

            BaseTest.putResponse("get_user_query", response);
            
        }
        
            
            
        
            
            
                        

        [Test ()]
        public void Test_update_user()
        {
            

            

            RequestMap map = new RequestMap();
            map.Set ("name", "Joe Bloggs");
            map.Set ("username", "jbloggs");
            map.Set ("email", "name@example.com");
            map.Set ("phone", "1-770-736-8031");
            map.Set ("website", "hildegard.org");
            map.Set ("address.line1", "2000 Purchase Street");
            map.Set ("address.city", "New York");
            map.Set ("address.state", "NY");
            map.Set ("address.postalCode", "10577");
            
            map.Set("id", BaseTest.resolveResponseValue("create_user.id"));
            map.Set("id2", BaseTest.resolveResponseValue("create_user.id"));
            map.Set("prepend", "prepend"+BaseTest.resolveResponseValue("create_user.id"));
            map.Set("append", BaseTest.resolveResponseValue("create_user.id")+"append");
            map.Set("complex", "prepend-"+BaseTest.resolveResponseValue("create_user.id")+"-"+BaseTest.resolveResponseValue("create_user.name"));
            map.Set("name", BaseTest.resolveResponseValue("val:Andrea Rizzini"));
            
            User response = new User(map).Update ();

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
            

            BaseTest.putResponse("update_user", response);
            
        }
        
            
            
            
            
            
        
            
            
            
            
                        

        [Test ()]
        public void Test_delete_user()
        {
            

            
        
            RequestMap map = new RequestMap();
            
            map.Set("id", BaseTest.resolveResponseValue("create_user.id"));
            
            User response = User.Delete("ssss",map);
            Assert.NotNull (response);

            List<string> ignoreAsserts = new List<string>();
            

            

            BaseTest.putResponse("delete_user", response);
            
        }
        

            
            
            
        
            
            
            
            
                        

        [Test ()]
        public void Test_delete_user_200()
        {
            

            
        
            RequestMap map = new RequestMap();
            
            map.Set("id", BaseTest.resolveResponseValue("create_user.id"));
            
            User response = User.delete200("ssss",map);
            Assert.NotNull (response);

            List<string> ignoreAsserts = new List<string>();
            

            

            BaseTest.putResponse("delete_user_200", response);
            
        }
        

            
            
            
        
            
            
            
            
                        

        [Test ()]
        public void Test_delete_user_204()
        {
            

            
        
            RequestMap map = new RequestMap();
            
            map.Set("id", BaseTest.resolveResponseValue("create_user.id"));
            
            User response = User.delete204("ssss",map);
            Assert.NotNull (response);

            List<string> ignoreAsserts = new List<string>();
            

            

            BaseTest.putResponse("delete_user_204", response);
            
        }
        

            
            
            
        
    }
}
