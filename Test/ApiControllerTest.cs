

using System;
using System.Net;
using System.Collections.Generic;
using NUnit.Framework;
using Newtonsoft.Json;
using RestSharp;
using Moq;


using MasterCard.Core;
using MasterCard.Core.Model;
using MasterCard.Core.Security.OAuth;
using MasterCard.Core.Exceptions;

namespace TestMasterCard
{
	[TestFixture ()]
	public class ApiControllerTest
	{

		List<String> headerList = new List<String> ();

		[SetUp]
		public void setup ()
		{
            var currentPath = MasterCard.Core.Util.GetCurrenyAssemblyPath();
            var authentication = new OAuthAuthentication("L5BsiPgaF-O3qA36znUATgQXwJB6MRoMSdhjd7wt50c97279!50596e52466e3966546d434b7354584c4975693238513d3d", currentPath + "\\Test\\mcapi_sandbox_key.p12", "alias", "password");
            ApiConfig.setAuthentication (authentication);
		}


		/// <summary>
		/// Mocks the client.
		/// </summary>
		/// <returns>The client.</returns>
		/// <param name="responseCode">Response code.</param>
		/// <param name="responseMap">Response map.</param>
		public IRestClient mockClient(HttpStatusCode responseCode, RequestMap responseMap) {

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

			RequestMap responseMap = new RequestMap (" { \"user.name\":\"andrea\", \"user.surname\":\"rizzini\" }");
			ApiController controller = new ApiController ("0.0.1");

			controller.SetRestClient (mockClient (HttpStatusCode.OK, responseMap));

			IDictionary<String,Object> result = controller.execute ("create", "/test1", new TestBaseObject (responseMap), headerList);
			RequestMap responseMapFromResponse = new RequestMap (result);

			Assert.IsTrue (responseMapFromResponse.ContainsKey ("user"));
			Assert.IsTrue (responseMapFromResponse.ContainsKey ("user.name"));
			Assert.IsTrue (responseMapFromResponse.ContainsKey ("user.surname"));

			Assert.AreEqual("andrea", responseMapFromResponse["user.name"]);
			Assert.AreEqual("rizzini", responseMapFromResponse["user.surname"]);

		}

		[Test]
		public void Test200WithList ()
		{

			RequestMap responseMap = new RequestMap ("[ { \"name\":\"andrea\", \"surname\":\"rizzini\" } ]");
			ApiController controller = new ApiController ("0.0.1");

			controller.SetRestClient (mockClient (HttpStatusCode.OK, responseMap));

			IDictionary<String,Object> result = controller.execute ("create", "/test1", new TestBaseObject (), headerList);
			RequestMap responseMapFromResponse = new RequestMap (result);

			Assert.IsTrue (responseMapFromResponse.ContainsKey ("list"));
			Assert.AreEqual (typeof(List<Dictionary<String,Object>>), responseMapFromResponse ["list"].GetType () );

			Assert.AreEqual("andrea", responseMapFromResponse["list[0].name"]);
			Assert.AreEqual("rizzini", responseMapFromResponse["list[0].surname"]);

		}



		[Test]
		public void Test204 ()
		{

			RequestMap responseMap = new RequestMap (" { \"user.name\":\"andrea\", \"user.surname\":\"rizzini\" }");
			ApiController controller = new ApiController ("0.0.1");

			controller.SetRestClient (mockClient (HttpStatusCode.NoContent, null));

			IDictionary<String,Object> result = controller.execute ("create", "/test1", new TestBaseObject (responseMap), headerList);

			Assert.IsTrue (result == null);

		}


		[Test]
		public void Test405_NotAllowedException ()
		{

			RequestMap responseMap = new RequestMap ("{\"Errors\":{\"Error\":{\"Source\":\"System\",\"ReasonCode\":\"METHOD_NOT_ALLOWED\",\"Description\":\"Method not Allowed\",\"Recoverable\":\"false\"}}}");
			ApiController controller = new ApiController ("0.0.1");

			controller.SetRestClient (mockClient (HttpStatusCode.MethodNotAllowed, responseMap));

			Assert.Throws<NotAllowedException> (() => controller.execute ("create", "/test1", new TestBaseObject (responseMap), headerList), "Method not Allowed");
		}


		[Test]
		public void Test40O_InvalidRequestException ()
		{

			RequestMap responseMap = new RequestMap ("{\"Errors\":{\"Error\":[{\"Source\":\"Validation\",\"ReasonCode\":\"INVALID_TYPE\",\"Description\":\"The supplied field: 'date' is of an unsupported format\",\"Recoverable\":false,\"Details\":null}]}}\n");

			ApiController controller = new ApiController ("0.0.1");

			controller.SetRestClient (mockClient (HttpStatusCode.BadRequest, responseMap));

			Assert.Throws<InvalidRequestException> (() => controller.execute ("create", "/test1", new TestBaseObject (responseMap), headerList), "The supplied field: 'date' is of an unsupported format");
		}


		[Test]
		public void Test401_AuthenticationException ()
		{

			RequestMap responseMap = new RequestMap ("{\"Errors\":{\"Error\":[{\"Source\":\"OAuth.ConsumerKey\",\"ReasonCode\":\"INVALID_CLIENT_ID\",\"Description\":\"Oauth customer key invalid\",\"Recoverable\":false,\"Details\":null}]}}");
			ApiController controller = new ApiController ("0.0.1");

			controller.SetRestClient (mockClient (HttpStatusCode.Unauthorized, responseMap));

			Assert.Throws<AuthenticationException> (() => controller.execute ("create", "/test1", new TestBaseObject (responseMap), headerList), "Oauth customer key invalid");
		}


		[Test]
		public void Test500_InvalidRequestException ()
		{

			RequestMap responseMap = new RequestMap ("{\"Errors\":{\"Error\":[{\"Source\":\"OAuth.ConsumerKey\",\"ReasonCode\":\"INVALID_CLIENT_ID\",\"Description\":\"Something went wrong\",\"Recoverable\":false,\"Details\":null}]}}");
			ApiController controller = new ApiController ("0.0.1");

			controller.SetRestClient (mockClient (HttpStatusCode.InternalServerError, responseMap));

			Assert.Throws<MasterCard.Core.Exceptions.SystemException> (() => controller.execute ( "create", "/test1", new TestBaseObject (responseMap), headerList), "Something went wrong");
		}


		[Test]
		public void Test200ShowById ()
		{

			RequestMap requestMap = new RequestMap ("{\n\"id\":\"1\"\n}");
			RequestMap responseMap = new RequestMap ("{\"Account\":{\"Status\":\"true\",\"Listed\":\"true\",\"ReasonCode\":\"S\",\"Reason\":\"STOLEN\"}}");
			ApiController controller = new ApiController ("0.0.1");

			controller.SetRestClient (mockClient (HttpStatusCode.OK, responseMap));

			IDictionary<String,Object> result = controller.execute ("read", "/test1", new TestBaseObject (requestMap), headerList);
			RequestMap responseMapFromResponse = new RequestMap (result);

			Assert.AreEqual("true", responseMapFromResponse["Account.Status"]);
			Assert.AreEqual("STOLEN", responseMapFromResponse["Account.Reason"]);
		}
	}
}

