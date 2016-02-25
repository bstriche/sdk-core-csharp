using System;
using NUnit.Framework;
using RestSharp;
using Moq;
using System.Net;

using MasterCard.Core.Model;
using Newtonsoft.Json;
using System.Collections.Generic;
using MasterCard.Core.Security;

namespace MasterCard.Test
{
	[TestFixture ()]
	public class ApiControllerTest
	{

		[SetUp]
		public void setup ()
		{
			var authentication = new OAuthAuthentication ("gVaoFbo86jmTfOB4NUyGKaAchVEU8ZVPalHQRLTxeaf750b6!414b543630362f426b4f6636415a5973656c33735661383d", "../../Test/prod_key.p12", "alias", "password");
			ApiConfig.setAuthentication (authentication);
		}


		/// <summary>
		/// Test base object.
		/// </summary>
		public class TestBaseObject : BaseObject
		{

			public TestBaseObject(BaseMap bm) : base(bm)
			{
			}

			public TestBaseObject() : base()
			{
			}


			protected internal override string BasePath
			{
				get
				{
					return "/testurl";
				}
			}

			protected internal override string ObjectType
			{
				get
				{
					return "test-base-object";
				}
			}

		}

		/// <summary>
		/// Mocks the client.
		/// </summary>
		/// <returns>The client.</returns>
		/// <param name="responseCode">Response code.</param>
		/// <param name="responseMap">Response map.</param>
		public IRestClient mockClient(HttpStatusCode responseCode, BaseMap responseMap) {

			var restClient = new Mock<IRestClient>();

			restClient.Setup(x => x.Execute(It.IsAny<IRestRequest>()))
				.Returns(new RestResponse
					{
						StatusCode = responseCode,
						Content = (responseMap != null ) ? JsonConvert.SerializeObject(responseMap).ToString() : ""
					});

			return restClient.Object;
		}


		[Test]
		public void Test200WithMap ()
		{

			BaseMap responseMap = new BaseMap (" { \"user.name\":\"andrea\", \"user.surname\":\"rizzini\" }");
			TestBaseObject testBaseObject = new TestBaseObject ();
			ApiController controller = new ApiController (testBaseObject.BasePath);

			controller.SetRestClient (mockClient (HttpStatusCode.OK, responseMap));

			IDictionary<String,Object> result = controller.execute ("test1", "create", new TestBaseObject (responseMap));
			BaseMap responseMapFromResponse = new BaseMap (result);

			Assert.IsTrue (responseMapFromResponse.ContainsKey ("user"));
			Assert.IsTrue (responseMapFromResponse.ContainsKey ("user.name"));
			Assert.IsTrue (responseMapFromResponse.ContainsKey ("user.surname"));

			Assert.AreEqual("andrea", responseMapFromResponse["user.name"]);
			Assert.AreEqual("rizzini", responseMapFromResponse["user.surname"]);

		}

		[Test]
		public void Test200WithList ()
		{

			BaseMap responseMap = new BaseMap ("[ { \"name\":\"andrea\", \"surname\":\"rizzini\" } ]");
			TestBaseObject testBaseObject = new TestBaseObject ();
			ApiController controller = new ApiController (testBaseObject.BasePath);

			controller.SetRestClient (mockClient (HttpStatusCode.OK, responseMap));

			IDictionary<String,Object> result = controller.execute ("test1", "create", new TestBaseObject ());
			BaseMap responseMapFromResponse = new BaseMap (result);

			Assert.IsTrue (responseMapFromResponse.ContainsKey ("list"));
			Assert.AreEqual (typeof(List<Dictionary<String,Object>>), responseMapFromResponse ["list"].GetType () );

			Assert.AreEqual("andrea", responseMapFromResponse["list[0].name"]);
			Assert.AreEqual("rizzini", responseMapFromResponse["list[0].surname"]);

		}



		[Test]
		public void Test204 ()
		{

			BaseMap responseMap = new BaseMap (" { \"user.name\":\"andrea\", \"user.surname\":\"rizzini\" }");
			TestBaseObject testBaseObject = new TestBaseObject ();
			ApiController controller = new ApiController (testBaseObject.BasePath);

			controller.SetRestClient (mockClient (HttpStatusCode.NoContent, null));

			IDictionary<String,Object> result = controller.execute ("test1", "create", new TestBaseObject (responseMap));

			Assert.IsTrue (result == null);

		}


		[Test]
		public void Test405_NotAllowedException ()
		{

			BaseMap responseMap = new BaseMap ("{\"Errors\":{\"Error\":{\"Source\":\"System\",\"ReasonCode\":\"METHOD_NOT_ALLOWED\",\"Description\":\"Method not Allowed\",\"Recoverable\":\"false\"}}}");
			TestBaseObject testBaseObject = new TestBaseObject ();
			ApiController controller = new ApiController (testBaseObject.BasePath);

			controller.SetRestClient (mockClient (HttpStatusCode.MethodNotAllowed, responseMap));

			Assert.Throws<MasterCard.Core.Exceptions.NotAllowedException> (() => controller.execute ("test1", "create", new TestBaseObject (responseMap)), "Method not Allowed");
		}


		[Test]
		public void Test40O_InvalidRequestException ()
		{

			BaseMap responseMap = new BaseMap ("{\"Errors\":{\"Error\":[{\"Source\":\"Validation\",\"ReasonCode\":\"INVALID_TYPE\",\"Description\":\"The supplied field: 'date' is of an unsupported format\",\"Recoverable\":false,\"Details\":null}]}}\n");
			TestBaseObject testBaseObject = new TestBaseObject ();
			ApiController controller = new ApiController (testBaseObject.BasePath);

			controller.SetRestClient (mockClient (HttpStatusCode.BadRequest, responseMap));

			Assert.Throws<MasterCard.Core.Exceptions.InvalidRequestException> (() => controller.execute ("test1", "create", new TestBaseObject (responseMap)), "The supplied field: 'date' is of an unsupported format");
		}


		[Test]
		public void Test401_AuthenticationException ()
		{

			BaseMap responseMap = new BaseMap ("{\"Errors\":{\"Error\":[{\"Source\":\"OAuth.ConsumerKey\",\"ReasonCode\":\"INVALID_CLIENT_ID\",\"Description\":\"Oauth customer key invalid\",\"Recoverable\":false,\"Details\":null}]}}");
			TestBaseObject testBaseObject = new TestBaseObject ();
			ApiController controller = new ApiController (testBaseObject.BasePath);

			controller.SetRestClient (mockClient (HttpStatusCode.Unauthorized, responseMap));

			Assert.Throws<MasterCard.Core.Exceptions.AuthenticationException> (() => controller.execute ("test1", "create", new TestBaseObject (responseMap)), "Oauth customer key invalid");
		}


		[Test]
		public void Test500_InvalidRequestException ()
		{

			BaseMap responseMap = new BaseMap ("{\"Errors\":{\"Error\":[{\"Source\":\"OAuth.ConsumerKey\",\"ReasonCode\":\"INVALID_CLIENT_ID\",\"Description\":\"Something went wrong\",\"Recoverable\":false,\"Details\":null}]}}");
			TestBaseObject testBaseObject = new TestBaseObject ();
			ApiController controller = new ApiController (testBaseObject.BasePath);

			controller.SetRestClient (mockClient (HttpStatusCode.InternalServerError, responseMap));

			Assert.Throws<MasterCard.Core.Exceptions.SystemException> (() => controller.execute ("test1", "create", new TestBaseObject (responseMap)), "Something went wrong");
		}


		[Test]
		public void Test200ShowById ()
		{

			BaseMap requestMap = new BaseMap ("{\n\"id\":\"1\"\n}");
			BaseMap responseMap = new BaseMap ("{\"Account\":{\"Status\":\"true\",\"Listed\":\"true\",\"ReasonCode\":\"S\",\"Reason\":\"STOLEN\"}}");
			TestBaseObject testBaseObject = new TestBaseObject ();
			ApiController controller = new ApiController (testBaseObject.BasePath);

			controller.SetRestClient (mockClient (HttpStatusCode.OK, responseMap));

			IDictionary<String,Object> result = controller.execute ("test1", "read", new TestBaseObject (requestMap));
			BaseMap responseMapFromResponse = new BaseMap (result);

			Assert.AreEqual("true", responseMapFromResponse["Account.Status"]);
			Assert.AreEqual("STOLEN", responseMapFromResponse["Account.Reason"]);
		}
	}
}

