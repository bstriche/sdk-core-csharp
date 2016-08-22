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



namespace TestMasterCard
{


	[TestFixture ()]
	public class PostTest
	{

		[SetUp]
		public void setup ()
		{
            var currentPath = MasterCard.Core.Util.GetCurrenyAssemblyPath();
            var authentication = new OAuthAuthentication ("L5BsiPgaF-O3qA36znUATgQXwJB6MRoMSdhjd7wt50c97279!50596e52466e3966546d434b7354584c4975693238513d3d", currentPath+"\\Test\\mcapi_sandbox_key.p12", "alias", "password");
            ApiConfig.SetAuthentication (authentication);
            ApiConfig.SetDebug(true);

		}

        

        [Test ()]
        public void list_posts_query_1_Test()
        {
            

            List<Post> responseList = Post.List();
            Post response = responseList[0];
            Assert.That("1", Is.EqualTo(response["id"].ToString()).IgnoreCase );
            Assert.That("some body text", Is.EqualTo(response["body"].ToString()).IgnoreCase );
            Assert.That("My Title", Is.EqualTo(response["title"].ToString()).IgnoreCase );
            Assert.That("1", Is.EqualTo(response["userId"].ToString()).IgnoreCase );
            
        }
        

        [Test ()]
        public void list_posts_query_2_Test()
        {
            
            RequestMap map = new RequestMap();
            map.Set ("max", "10");
            
            

            List<Post> responseList = Post.List(map);
            Post response = responseList[0];
            Assert.That("1", Is.EqualTo(response["id"].ToString()).IgnoreCase );
            Assert.That("some body text", Is.EqualTo(response["body"].ToString()).IgnoreCase );
            Assert.That("My Title", Is.EqualTo(response["title"].ToString()).IgnoreCase );
            Assert.That("1", Is.EqualTo(response["userId"].ToString()).IgnoreCase );
            
        }
        
            
            
            
            
        
            
                        

        [Test ()]
        public void create_post_Test()
        {
            RequestMap map = new RequestMap();
            map.Set ("body", "Some text as a body");
            map.Set ("title", "Title of Post");
            
            Post response = Post.Create(map);
            Assert.That("1", Is.EqualTo(response["id"].ToString()).IgnoreCase );
            Assert.That("some body text", Is.EqualTo(response["body"].ToString()).IgnoreCase );
            Assert.That("My Title", Is.EqualTo(response["title"].ToString()).IgnoreCase );
            Assert.That("1", Is.EqualTo(response["userId"].ToString()).IgnoreCase );
            
        }
        
            
            
            
            
            
            
        
            
            
            
            
            
                        

        [Test ()]
        public void get_post_query_1_Test()
        {
            String id = "1";

            

            Post response = Post.Read(id);
            Assert.That("1", Is.EqualTo(response["id"].ToString()).IgnoreCase);
            Assert.That("some body text", Is.EqualTo(response["body"].ToString()).IgnoreCase);
            Assert.That("My Title", Is.EqualTo(response["title"].ToString()).IgnoreCase);
            Assert.That("1", Is.EqualTo(response["userId"].ToString()).IgnoreCase);
            

        }
        

        [Test ()]
        public void get_post_query_2_Test()
        {
            String id = "1";

            
            RequestMap parameters = new RequestMap();
            parameters.Set ("min", "1");
            parameters.Set ("max", "10");
            
            

            Post response = Post.Read(id,parameters);
            Assert.That("1", Is.EqualTo(response["id"].ToString()).IgnoreCase);
            Assert.That("some body text", Is.EqualTo(response["body"].ToString()).IgnoreCase);
            Assert.That("My Title", Is.EqualTo(response["title"].ToString()).IgnoreCase);
            Assert.That("1", Is.EqualTo(response["userId"].ToString()).IgnoreCase);
            

        }
        
            
            
        
            
            
                        

        [Test ()]
        public void update_post_Test()
        {
            RequestMap map = new RequestMap();
            map.Set ("id", "1111");
            map.Set ("body", "updated body");
            map.Set ("title", "updated title");
            
            Post response = new Post(map).Update ();
            Assert.That("1", Is.EqualTo(response["id"].ToString()).IgnoreCase);
            Assert.That("updated body", Is.EqualTo(response["body"].ToString()).IgnoreCase);
            Assert.That("updated title", Is.EqualTo(response["title"].ToString()).IgnoreCase);
            Assert.That("1", Is.EqualTo(response["userId"].ToString()).IgnoreCase);
            
        }
        
            
            
            
            
            
        
            
            
            
            
                        

        [Test ()]
        public void delete_post_Test()
        {
            Post response = Post.Delete ("1");
            Assert.NotNull (response);
            
        }
        

            
            
            
        
    }
}

