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
	public class PostTest : BaseTest
	{

		[SetUp]
		public void setup ()
		{
            ApiConfig.SetDebug(true);
            ApiConfig.SetSandbox(true);
            var path = MasterCard.Core.Util.GetAssemblyPath();

            BaseTest.resetAuthentication();

          
		}

        
            
            
            
                        

        [Test ()]
        public void Test_list_posts_query_1()
        {
            

            

            RequestMap map = new RequestMap();
            
            
            List<Post> responseList = Post.List(map);
            Post response = responseList[0];

            List<string> ignoreAsserts = new List<string>();
            
            BaseTest.assertEqual(ignoreAsserts, response, "id", "1");
            BaseTest.assertEqual(ignoreAsserts, response, "title", "My Title");
            BaseTest.assertEqual(ignoreAsserts, response, "body", "some body text");
            BaseTest.assertEqual(ignoreAsserts, response, "userId", "1");
            

            BaseTest.putResponse("list_posts_query_1", responseList[0]);
            
        }
        

        [Test ()]
        public void Test_list_posts_query_2()
        {
            

            

            RequestMap map = new RequestMap();
            map.Set ("max", "10");
            
            
            List<Post> responseList = Post.List(map);
            Post response = responseList[0];

            List<string> ignoreAsserts = new List<string>();
            
            BaseTest.assertEqual(ignoreAsserts, response, "id", "1");
            BaseTest.assertEqual(ignoreAsserts, response, "title", "My Title");
            BaseTest.assertEqual(ignoreAsserts, response, "body", "some body text");
            BaseTest.assertEqual(ignoreAsserts, response, "userId", "1");
            

            BaseTest.putResponse("list_posts_query_2", responseList[0]);
            
        }
        
            
            
            
            
        
            
                        

      
        
            
            
            
            
            
            
        
            
            
            
            
            
                        

        [Test ()]
        public void Test_get_post_query_1()
        {
            

            
        
            RequestMap map = new RequestMap();
            
            
            Post response = Post.Read("1",map);

            List<string> ignoreAsserts = new List<string>();
            

            BaseTest.assertEqual(ignoreAsserts, response, "id", "1");
            BaseTest.assertEqual(ignoreAsserts, response, "title", "My Title");
            BaseTest.assertEqual(ignoreAsserts, response, "body", "some body text");
            BaseTest.assertEqual(ignoreAsserts, response, "userId", "1");
            

            BaseTest.putResponse("get_post_query_1", response);
            
        }
        

        [Test ()]
        public void Test_get_post_query_2()
        {
            

            
        
            RequestMap map = new RequestMap();
            map.Set ("min", "1");
            map.Set ("max", "10");
            
            
            Post response = Post.Read("1",map);

            List<string> ignoreAsserts = new List<string>();
            

            BaseTest.assertEqual(ignoreAsserts, response, "id", "1");
            BaseTest.assertEqual(ignoreAsserts, response, "title", "My Title");
            BaseTest.assertEqual(ignoreAsserts, response, "body", "some body text");
            BaseTest.assertEqual(ignoreAsserts, response, "userId", "1");
            

            BaseTest.putResponse("get_post_query_2", response);
            
        }
        
            
            
        
            
            
                        

        [Test ()]
        public void Test_update_post()
        {
            

            

            RequestMap map = new RequestMap();
            map.Set ("id", "1111");
            map.Set ("title", "updated title");
            map.Set ("body", "updated body");
            
            
            Post response = new Post(map).Update ();

            List<string> ignoreAsserts = new List<string>();
            

            BaseTest.assertEqual(ignoreAsserts, response, "id", "1");
            BaseTest.assertEqual(ignoreAsserts, response, "title", "updated title");
            BaseTest.assertEqual(ignoreAsserts, response, "body", "updated body");
            BaseTest.assertEqual(ignoreAsserts, response, "userId", "1");
            

            BaseTest.putResponse("update_post", response);
            
        }
        
            
            
            
            
            
        
            
            
            
            
                        

        [Test ()]
        public void Test_delete_post()
        {
            

            
        
            RequestMap map = new RequestMap();
            
            
            Post response = Post.Delete("1",map);
            Assert.NotNull (response);

            List<string> ignoreAsserts = new List<string>();
            

            

            BaseTest.putResponse("delete_post", response);
            
        }
        

            
            
            
        
    }
}
