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
using MasterCard.Core.Model;
using MasterCard.Core.Security.OAuth;
using TestMasterCard;


namespace TestMasterCard
{


	[TestFixture ()]
	public class UserTest
	{

		[SetUp]
		public void setup ()
		{
            var currentPath = MasterCard.Core.Util.GetCurrenyAssemblyPath();
            var authentication = new OAuthAuthentication("L5BsiPgaF-O3qA36znUATgQXwJB6MRoMSdhjd7wt50c97279!50596e52466e3966546d434b7354584c4975693238513d3d", currentPath + "\\Test\\mcapi_sandbox_key.p12", "alias", "password");
            ApiConfig.SetAuthentication (authentication);
            ApiConfig.SetDebug(true);

        }


        [Test ()]
        public void list_users_Test()
        {
            

            List<User> responseList = User.List();
            User response = responseList[0];
            Assert.That("1-770-736-8031", Is.EqualTo(response["phone"].ToString()).IgnoreCase );
			Assert.That("hildegard.org", Is.EqualTo(response["website"].ToString()).IgnoreCase );
            Assert.That("true", Is.EqualTo(response["address.instructions.doorman"].ToString()).IgnoreCase );
            Assert.That("2000 Purchase Street", Is.EqualTo(response["address.line1"].ToString()).IgnoreCase );
            Assert.That("NY", Is.EqualTo(response["address.state"].ToString()).IgnoreCase );
            Assert.That("some delivery instructions text", Is.EqualTo(response["address.instructions.text"].ToString()).IgnoreCase );
            Assert.That("1", Is.EqualTo(response["id"].ToString()).IgnoreCase );
            Assert.That("jbloggs", Is.EqualTo(response["username"].ToString()).IgnoreCase );
            Assert.That("name@example.com", Is.EqualTo(response["email"].ToString()).IgnoreCase );
            Assert.That("Joe Bloggs", Is.EqualTo(response["name"].ToString()).IgnoreCase );
            Assert.That("10577", Is.EqualTo(response["address.postalCode"].ToString()).IgnoreCase );
            Assert.That("1", Is.EqualTo(response["address.id"].ToString()).IgnoreCase );
            Assert.That("New York", Is.EqualTo(response["address.city"].ToString()).IgnoreCase );
            
        }
        

        [Test ()]
        public void list_users_query_Test()
        {
            
            RequestMap map = new RequestMap();
            map.Set ("max", "10");
            
            

            List<User> responseList = User.List(map);
            User response = responseList[0];
            Assert.That("1-770-736-8031", Is.EqualTo(response["phone"].ToString()).IgnoreCase );
			Assert.That("hildegard.org", Is.EqualTo(response["website"].ToString()).IgnoreCase );
            Assert.That("true", Is.EqualTo(response["address.instructions.doorman"].ToString()).IgnoreCase );
            Assert.That("2000 Purchase Street", Is.EqualTo(response["address.line1"].ToString()).IgnoreCase );
            Assert.That("NY", Is.EqualTo(response["address.state"].ToString()).IgnoreCase );
            Assert.That("some delivery instructions text", Is.EqualTo(response["address.instructions.text"].ToString()).IgnoreCase );
            Assert.That("1", Is.EqualTo(response["id"].ToString()).IgnoreCase );
            Assert.That("jbloggs", Is.EqualTo(response["username"].ToString()).IgnoreCase );
            Assert.That("name@example.com", Is.EqualTo(response["email"].ToString()).IgnoreCase );
            Assert.That("Joe Bloggs", Is.EqualTo(response["name"].ToString()).IgnoreCase );
            Assert.That("10577", Is.EqualTo(response["address.postalCode"].ToString()).IgnoreCase );
            Assert.That("1", Is.EqualTo(response["address.id"].ToString()).IgnoreCase );
            Assert.That("New York", Is.EqualTo(response["address.city"].ToString()).IgnoreCase );
            
        }
        
            
            
            
            
        
            
                        

        [Test ()]
        public void create_user_Test()
        {
            RequestMap map = new RequestMap();
            map.Set ("username", "jbloggs");
            map.Set ("phone", "1-770-736-8031");
            map.Set ("email", "name@example.com");
            map.Set ("website", "hildegard.org");
            map.Set ("name", "Joe Bloggs");
            map.Set ("address.line1", "2000 Purchase Street");
            map.Set ("address.state", "NY");
            map.Set ("address.postalCode", "10577");
            map.Set ("address.city", "New York");
            
            User response = User.Create(map);
            Assert.That("1-770-736-8031", Is.EqualTo(response["phone"].ToString()).IgnoreCase );
            Assert.That("hildegard.org", Is.EqualTo(response["website"].ToString()).IgnoreCase );
            Assert.That("true", Is.EqualTo(response["address.instructions.doorman"].ToString()).IgnoreCase );
            Assert.That("2000 Purchase Street", Is.EqualTo(response["address.line1"].ToString()).IgnoreCase );
            Assert.That("NY", Is.EqualTo(response["address.state"].ToString()).IgnoreCase );
            Assert.That("some delivery instructions text", Is.EqualTo(response["address.instructions.text"].ToString()).IgnoreCase );
            Assert.That("1", Is.EqualTo(response["id"].ToString()).IgnoreCase );
            Assert.That("jbloggs", Is.EqualTo(response["username"].ToString()).IgnoreCase );
            Assert.That("name@example.com", Is.EqualTo(response["email"].ToString()).IgnoreCase );
            Assert.That("Joe Bloggs", Is.EqualTo(response["name"].ToString()).IgnoreCase );
            Assert.That("10577", Is.EqualTo(response["address.postalCode"].ToString()).IgnoreCase );
            Assert.That("1", Is.EqualTo(response["address.id"].ToString()).IgnoreCase );
            Assert.That("New York", Is.EqualTo(response["address.city"].ToString()).IgnoreCase );
            
        }
        
            
            
            
            
            
            
        
            
            
            
            
            
                        

        [Test ()]
        public void get_user_Test()
        {
            String id = "1";

            

            User response = User.Read(id);
            Assert.That("1-770-736-8031", Is.EqualTo(response["phone"].ToString()).IgnoreCase);
            Assert.That("hildegard.org", Is.EqualTo(response["website"].ToString()).IgnoreCase);
            Assert.That("true", Is.EqualTo(response["address.instructions.doorman"].ToString()).IgnoreCase);
            Assert.That("2000 Purchase Street", Is.EqualTo(response["address.line1"].ToString()).IgnoreCase);
            Assert.That("NY", Is.EqualTo(response["address.state"].ToString()).IgnoreCase);
            Assert.That("some delivery instructions text", Is.EqualTo(response["address.instructions.text"].ToString()).IgnoreCase);
            Assert.That("1", Is.EqualTo(response["id"].ToString()).IgnoreCase);
            Assert.That("jbloggs", Is.EqualTo(response["username"].ToString()).IgnoreCase);
            Assert.That("name@example.com", Is.EqualTo(response["email"].ToString()).IgnoreCase);
            Assert.That("Joe Bloggs", Is.EqualTo(response["name"].ToString()).IgnoreCase);
            Assert.That("10577", Is.EqualTo(response["address.postalCode"].ToString()).IgnoreCase);
            Assert.That("1", Is.EqualTo(response["address.id"].ToString()).IgnoreCase);
            Assert.That("New York", Is.EqualTo(response["address.city"].ToString()).IgnoreCase);
            

        }
        

        [Test ()]
        public void get_user_query_Test()
        {
            String id = "1";

            
            RequestMap parameters = new RequestMap();
            parameters.Set ("min", "1");
            parameters.Set ("max", "10");
            
            

            User response = User.Read(id,parameters);
            Assert.That("1-770-736-8031", Is.EqualTo(response["phone"].ToString()).IgnoreCase);
            Assert.That("hildegard.org", Is.EqualTo(response["website"].ToString()).IgnoreCase);
            Assert.That("true", Is.EqualTo(response["address.instructions.doorman"].ToString()).IgnoreCase);
            Assert.That("2000 Purchase Street", Is.EqualTo(response["address.line1"].ToString()).IgnoreCase);
            Assert.That("NY", Is.EqualTo(response["address.state"].ToString()).IgnoreCase);
            Assert.That("some delivery instructions text", Is.EqualTo(response["address.instructions.text"].ToString()).IgnoreCase);
            Assert.That("1", Is.EqualTo(response["id"].ToString()).IgnoreCase);
            Assert.That("jbloggs", Is.EqualTo(response["username"].ToString()).IgnoreCase);
            Assert.That("name@example.com", Is.EqualTo(response["email"].ToString()).IgnoreCase);
            Assert.That("Joe Bloggs", Is.EqualTo(response["name"].ToString()).IgnoreCase);
            Assert.That("10577", Is.EqualTo(response["address.postalCode"].ToString()).IgnoreCase);
            Assert.That("1", Is.EqualTo(response["address.id"].ToString()).IgnoreCase);
            Assert.That("New York", Is.EqualTo(response["address.city"].ToString()).IgnoreCase);
            

        }
        
            
            
        
            
            
                        

        [Test ()]
        public void update_user_Test()
        {
            RequestMap map = new RequestMap();
            map.Set ("id", "1");
            map.Set ("phone", "1-770-736-8031");
            map.Set ("username", "jbloggs");
            map.Set ("website", "hildegard.org");
            map.Set ("email", "name@example.com");
            map.Set ("address.line1", "2000 Purchase Street");
            map.Set ("name", "Joe Bloggs");
            map.Set ("address.state", "NY");
            map.Set ("address.postalCode", "10577");
            map.Set ("address.city", "New York");
            
            User response = new User(map).Update ();
            Assert.That("1-770-736-8031", Is.EqualTo(response["phone"].ToString()).IgnoreCase);
            Assert.That("hildegard.org", Is.EqualTo(response["website"].ToString()).IgnoreCase);
            Assert.That("true", Is.EqualTo(response["address.instructions.doorman"].ToString()).IgnoreCase);
            Assert.That("2000 Purchase Street", Is.EqualTo(response["address.line1"].ToString()).IgnoreCase);
            Assert.That("NY", Is.EqualTo(response["address.state"].ToString()).IgnoreCase);
            Assert.That("some delivery instructions text", Is.EqualTo(response["address.instructions.text"].ToString()).IgnoreCase);
            Assert.That("1", Is.EqualTo(response["id"].ToString()).IgnoreCase);
            Assert.That("jbloggs", Is.EqualTo(response["username"].ToString()).IgnoreCase);
            Assert.That("name@example.com", Is.EqualTo(response["email"].ToString()).IgnoreCase);
            Assert.That("Joe Bloggs", Is.EqualTo(response["name"].ToString()).IgnoreCase);
            Assert.That("10577", Is.EqualTo(response["address.postalCode"].ToString()).IgnoreCase);
            Assert.That("1", Is.EqualTo(response["address.id"].ToString()).IgnoreCase);
            Assert.That("New York", Is.EqualTo(response["address.city"].ToString()).IgnoreCase);
            
        }
        
            
            
            
            
            
        
            
            
            
            
                        

        [Test ()]
        public void delete_user_Test()
        {
            User response = User.Delete ("1");
            Assert.NotNull (response);
            
        }
        

            
            
            
        
    }
}


