using System;
using NUnit.Framework;
using MasterCard.Core.Security.OAuth;
using MasterCard.Core;
using System.Collections.Generic;
using MasterCard.Core.Model;
using MasterCard.Core.Exceptions;

namespace TestMasterCard
{
	[TestFixture ()]
	public class NodeJSMockServerSpec
	{

		[SetUp]
		public void setup ()
		{
            var currentPath = MasterCard.Core.Util.GetCurrenyAssemblyPath();
            var authentication = new OAuthAuthentication ("L5BsiPgaF-O3qA36znUATgQXwJB6MRoMSdhjd7wt50c97279!50596e52466e3966546d434b7354584c4975693238513d3d", currentPath+"\\Test\\mcapi_sandbox_key.p12", "test", "password");
			ApiConfig.SetAuthentication(authentication);
			ApiConfig.SetSandbox (true);


		}



		[TearDown]
		public void teardown ()
		{


		}

		#if DEBUG

		[Test]
		public void testActionReadPostEqual200()
		{
			Post read = Post.Read ("1");
			Assert.AreEqual (read.Get("id"), 1);
			Assert.AreEqual (read.Get("title"), "My Title");
			Assert.AreEqual (read.Get("body"), "some body text");
			Assert.AreEqual (read.Get("userId"), 1);
		}


		[Test]
		public void testActionReadPostEqual500()
		{
			Assert.Throws<MasterCard.Core.Exceptions.ApiException> (() => Post.Read("aaa"), "500");
		}


		[Test]
		public void testActionListPostWithCriteriaEqual200()
		{
			Dictionary<string, object> inputMap = new Dictionary<string, object>
			{
				{ "one", "1" },
				{ "two", "2" },
				{ "three", "3" },
				{ "four", "4" }
			};

			List<Post> aListOfPosts = Post.List (new RequestMap(inputMap));
			Assert.AreEqual (1, aListOfPosts.Count);

			Post firstItem = aListOfPosts [0];
				
			Assert.AreEqual (firstItem.Get("id"), 1);
			Assert.AreEqual (firstItem.Get("title"), "My Title");
			Assert.AreEqual (firstItem.Get("body"), "some body text");
			Assert.AreEqual (firstItem.Get("userId"), 1);
		}

		[Test]
		public void testActionCreatePostEqual200()
		{
			RequestMap inputMap = new RequestMap ();
			inputMap.Add ("id", 1);
			inputMap.Add ("title", "My Title");
			inputMap.Add ("body", "Some Long text of Body");
			Post createdItem = Post.Create (new RequestMap(inputMap));

			Assert.AreEqual (createdItem.Get("id"), 1);
			Assert.AreEqual (createdItem.Get("title"), "My Title");
			Assert.AreEqual (createdItem.Get("body"), "some body text");
			Assert.AreEqual (createdItem.Get("userId"), 1);
		}

		[Test]
		public void testActionUpdatePostEqual200()
		{
			RequestMap inputMap = new RequestMap ();
			inputMap.Add ("id", 1);
			inputMap.Add ("title", "My Title");
			inputMap.Add ("body", "Some Long text of Body");
			Post createdItem = Post.Create (new RequestMap(inputMap));

			Assert.AreEqual (createdItem.Get("id"), 1);
			Assert.AreEqual (createdItem.Get("title"), "My Title");
			Assert.AreEqual (createdItem.Get("body"), "some body text");
			Assert.AreEqual (createdItem.Get("userId"), 1);

			createdItem.Set ("title", "updated title");
			createdItem.Set ("body", "updated body");

			Post updatedItem = createdItem.Update ();

			Assert.AreEqual (updatedItem.Get("id"), 1);
			Assert.AreEqual (updatedItem.Get("title"), "updated title");
			Assert.AreEqual (updatedItem.Get("body"), "updated body");
			Assert.AreEqual (updatedItem.Get("userId"), 1);

		}

		[Test]
		public void testActionDeletePostEqual200()
		{
			RequestMap inputMap = new RequestMap ();
			inputMap.Add ("id", 1);
			inputMap.Add ("title", "My Title");
			inputMap.Add ("body", "Some Long text of Body");
			Post createdItem = Post.Create (new RequestMap(inputMap));



			Post deletedItem = createdItem.Delete ();

			Assert.AreEqual (0, deletedItem.Count);

		}

		[Test]
		public void testActionDeleteWithIdPostEqual200()
		{

			Post deletedItem = Post.Delete ("1");

			Assert.AreEqual (0, deletedItem.Count);

		}


		//test Action.list from UserPostPath --> 200
		[Test]
		public void testActionListWithUserPostPath200()
		{

			RequestMap inputMap = new RequestMap ();
			inputMap.Set ("user_id", 11);
			List<UserPostPath> items = UserPostPath.List (inputMap);

			Assert.AreEqual (1, items.Count);

			UserPostPath item = items [0];
			Assert.AreEqual (item.Get("id"), 1);
			Assert.AreEqual (item.Get("title"), "My Title");
			Assert.AreEqual (item.Get("body"), "some body text");
			Assert.AreEqual (item.Get("userId"), 1);


		}


		//test Action.list from UserPostPath --> 200
		[Test]
		public void testActionListWithUserPostPath500()
		{

			Assert.Throws<MasterCard.Core.Exceptions.ApiException> (() => UserPostPath.List(), "Error, path paramer: 'user_id' expected but not found in input map");


		}


		//test Action.list from UserPostPath --> 200
		[Test]
		public void testActionListWithUserPostHeader200()
		{

			RequestMap inputMap = new RequestMap ();
			inputMap.Set ("user_id", 11);
			List<UserPostHeader> items = UserPostHeader.List (inputMap);

			Assert.AreEqual (1, items.Count);

			UserPostHeader item = items [0];
			Assert.AreEqual (item.Get("id"), 1);
			Assert.AreEqual (item.Get("title"), "My Title");
			Assert.AreEqual (item.Get("body"), "some body text");
			Assert.AreEqual (item.Get("userId"), 1);


		}


		//test Action.list from UserPostPath --> 200
		[Test]
		public void testActionListWithUserHdearPath500()
		{

			ApiException ex = Assert.Throws<ApiException> (() => UserPostHeader.List());


		}

		#endif

	}
}

