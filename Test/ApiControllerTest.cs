

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
using Environment = MasterCard.Core.Model.Constants.Environment;

namespace TestMasterCard
{
	[TestFixture ()]
	public class ApiControllerTest
	{

		List<String> headerList = new List<String> ();
		List<String> queryList = new List<String> ();

		[SetUp]
		public void setup ()
		{
            var currentPath = MasterCard.Core.Util.GetCurrenyAssemblyPath();
            var authentication = new OAuthAuthentication("L5BsiPgaF-O3qA36znUATgQXwJB6MRoMSdhjd7wt50c97279!50596e52466e3966546d434b7354584c4975693238513d3d", currentPath + "\\Test\\mcapi_sandbox_key.p12", "test", "password");
            ApiConfig.SetAuthentication (authentication);
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


        /// <summary>
        /// Mocks the client.
        /// </summary>
        /// <returns>The client.</returns>
        /// <param name="responseCode">Response code.</param>
        /// <param name="responseMap">Response map.</param>
        public IRestClient mockClient(HttpStatusCode responseCode, String response)
        {

            var restClient = new Mock<IRestClient>();

            restClient.Setup(x => x.Execute(It.IsAny<IRestRequest>()))
                .Returns(new RestResponse
                {
                    StatusCode = responseCode,
                    Content = response
                });

            return restClient.Object;

        }


        [Test]
		public void Test200WithMap ()
		{

			RequestMap responseMap = new RequestMap (" { \"user.name\":\"andrea\", \"user.surname\":\"rizzini\" }");
			TestApiController controller = new TestApiController ();

			controller.SetRestClient (mockClient (HttpStatusCode.OK, responseMap));

            var config = new OperationConfig("/test1", "create", headerList, queryList);
            var metadata = new OperationMetadata("0.0.1", "http://locahost:8081");

            IDictionary <String,Object> result = controller.Execute (config, metadata, new TestBaseObject (responseMap));
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
			TestApiController controller = new TestApiController ();

			controller.SetRestClient (mockClient (HttpStatusCode.OK, responseMap));

            var config = new OperationConfig("/test1", "create", headerList, queryList);
            var metadata = new OperationMetadata("0.0.1", "http://locahost:8081");
            //new Tuple<string, string, List<string>, List<string>>("/test1", null, headerList, queryList);

            IDictionary<String, Object> result = controller.Execute(config, metadata, new TestBaseObject());
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
			TestApiController controller = new TestApiController ();

			controller.SetRestClient (mockClient (HttpStatusCode.NoContent, ""));

            // new Tuple<string, string, List<string>, List<string>>("/test1", null, headerList, queryList);
            var config = new OperationConfig("/test1", "create", headerList, queryList);
            var metadata = new OperationMetadata("0.0.1", "http://locahost:8081");

            IDictionary<String, Object> result = controller.Execute(config, metadata, new TestBaseObject(responseMap));

            Assert.IsTrue (result.Count == 0);

		}


		[Test]
		public void Test405_NotAllowedException ()
		{

			RequestMap responseMap = new RequestMap ("{\"Errors\":{\"Error\":{\"Source\":\"System\",\"ReasonCode\":\"METHOD_NOT_ALLOWED\",\"Description\":\"Method not Allowed\",\"Recoverable\":\"false\"}}}");
			TestApiController controller = new TestApiController ();

			controller.SetRestClient (mockClient (HttpStatusCode.MethodNotAllowed, responseMap));

            //new Tuple<string, string, List<string>, List<string>>("/test1", null, headerList, queryList);
            var config = new OperationConfig("/test1", "create", headerList, queryList);
            var metadata = new OperationMetadata("0.0.1", "http://locahost:8081");

            ApiException ex = Assert.Throws<ApiException> (() => controller.Execute(config, metadata, new TestBaseObject(responseMap)));
            Assert.That(ex.Message, Is.EqualTo("Method not Allowed"));
            Assert.That(ex.ReasonCode, Is.EqualTo("METHOD_NOT_ALLOWED"));
            Assert.That(ex.Source, Is.EqualTo("System"));
            Assert.That(ex.Recoverable, Is.EqualTo(false));


        }


        [Test]
        public void Test405_NotAllowedExceptionCaseInsensitive()
        {

            RequestMap responseMap = new RequestMap("{\"errors\":{\"error\":{\"source\":\"System\",\"reasonCode\":\"METHOD_NOT_ALLOWED\",\"description\":\"Method not Allowed\",\"Recoverable\":\"false\"}}}");
            TestApiController controller = new TestApiController();

            controller.SetRestClient(mockClient(HttpStatusCode.MethodNotAllowed, responseMap));

            //new Tuple<string, string, List<string>, List<string>>("/test1", null, headerList, queryList);
            var config = new OperationConfig("/test1", "create", headerList, queryList);
            var metadata = new OperationMetadata("0.0.1", "http://locahost:8081");

            ApiException ex = Assert.Throws<ApiException>(() => controller.Execute(config, metadata, new TestBaseObject(responseMap)));
            Assert.That(ex.Message, Is.EqualTo("Method not Allowed"));
            Assert.That(ex.ReasonCode, Is.EqualTo("METHOD_NOT_ALLOWED"));
            Assert.That(ex.Source, Is.EqualTo("System"));
            Assert.That(ex.Recoverable, Is.EqualTo(false));


        }


        [Test]
		public void Test400_InvalidRequestException ()
		{

			RequestMap responseMap = new RequestMap ("{\"Errors\":{\"Error\":[{\"Source\":\"Validation\",\"ReasonCode\":\"INVALID_TYPE\",\"Description\":\"The supplied field: 'date' is of an unsupported format\",\"Recoverable\":false,\"Details\":null}]}}\n");

			TestApiController controller = new TestApiController ();

			controller.SetRestClient (mockClient (HttpStatusCode.BadRequest, responseMap));

            // new Tuple<string, string, List<string>, List<string>>("/test1", null, headerList, queryList);
            var config = new OperationConfig("/test1", "create", headerList, queryList);
            var metadata = new OperationMetadata("0.0.1", "http://locahost:8081");

            ApiException ex = Assert.Throws<ApiException> (() => controller.Execute (config, metadata, new TestBaseObject (responseMap)), "The supplied field: 'date' is of an unsupported format");
            Assert.That(ex.Message, Is.EqualTo("The supplied field: 'date' is of an unsupported format"));
            Assert.That(ex.ReasonCode, Is.EqualTo("INVALID_TYPE"));
            Assert.That(ex.Source, Is.EqualTo("Validation"));
            Assert.That(ex.Recoverable, Is.EqualTo(false));
        }

        [Test]
        public void Test400_InvalidRequestExceptionCaseInsensitive()
        {

            RequestMap responseMap = new RequestMap("{\"errors\":{\"error\":[{\"source\":\"validation\",\"reasonCode\":\"INVALID_TYPE\",\"description\":\"The supplied field: 'date' is of an unsupported format\",\"Recoverable\":false,\"Details\":null}]}}\n");

            TestApiController controller = new TestApiController();

            controller.SetRestClient(mockClient(HttpStatusCode.BadRequest, responseMap));

            // new Tuple<string, string, List<string>, List<string>>("/test1", null, headerList, queryList);
            var config = new OperationConfig("/test1", "create", headerList, queryList);
            var metadata = new OperationMetadata("0.0.1", "http://locahost:8081");

            ApiException ex = Assert.Throws<ApiException>(() => controller.Execute(config, metadata, new TestBaseObject(responseMap)));
            Assert.That(ex.Message, Is.EqualTo("The supplied field: 'date' is of an unsupported format"));
            Assert.That(ex.ReasonCode, Is.EqualTo("INVALID_TYPE"));
            Assert.That(ex.Source, Is.EqualTo("validation"));
            Assert.That(ex.Recoverable, Is.EqualTo(false));
            Assert.That(ex.RawErrorData.Get("errors.error[0].source").ToString(), Is.EqualTo("validation"));
            Assert.That(ex.RawErrorData.Get("Errors.Error[0].Source").ToString(), Is.EqualTo("validation"));

            Assert.That(ex.Error.Get("Recoverable").ToString(), Is.EqualTo("False"));
        }


        [Test]
        public void Test400_InvalidRequestExceptionCaseInsensitive_ListOfErrors()
        {

            String response = "{\"errors\":[{\"source\":\"validation\",\"reasonCode\":\"INVALID_TYPE\",\"description\":\"The supplied field: 'date' is of an unsupported format\",\"Recoverable\":false,\"Details\":null}]}\n";

            TestApiController controller = new TestApiController();

            controller.SetRestClient(mockClient(HttpStatusCode.BadRequest, response));

            // new Tuple<string, string, List<string>, List<string>>("/test1", null, headerList, queryList);
            var config = new OperationConfig("/test1", "create", headerList, queryList);
            var metadata = new OperationMetadata("0.0.1", "http://locahost:8081");

            ApiException ex = Assert.Throws<ApiException>(() => controller.Execute(config, metadata, new TestBaseObject()));
            Assert.That(ex.Message, Is.EqualTo("The supplied field: 'date' is of an unsupported format"));
            Assert.That(ex.ReasonCode, Is.EqualTo("INVALID_TYPE"));
            Assert.That(ex.Source, Is.EqualTo("validation"));
            Assert.That(ex.Recoverable, Is.EqualTo(false));
            Assert.That(ex.RawErrorData.Get("errors[0].source").ToString(), Is.EqualTo("validation"));
            Assert.That(ex.RawErrorData.Get("Errors[0].Source").ToString(), Is.EqualTo("validation"));
        }

        [Test]
        public void Test400_InvalidRequestExceptionCaseInsensitive_JSONNative()
        {

            String response = "[{\"source\":\"validation\",\"reasonCode\":\"INVALID_TYPE\",\"description\":\"The supplied field: 'date' is of an unsupported format\",\"Recoverable\":false,\"Details\":null}]";

            TestApiController controller = new TestApiController();

            controller.SetRestClient(mockClient(HttpStatusCode.BadRequest, response));

            // new Tuple<string, string, List<string>, List<string>>("/test1", null, headerList, queryList);
            var config = new OperationConfig("/test1", "create", headerList, queryList);
            var metadata = new OperationMetadata("0.0.1", "http://locahost:8081");

            ApiException ex = Assert.Throws<ApiException>(() => controller.Execute(config, metadata, new TestBaseObject()));
            Assert.That(ex.Message, Is.EqualTo("The supplied field: 'date' is of an unsupported format"));
            Assert.That(ex.ReasonCode, Is.EqualTo("INVALID_TYPE"));
            Assert.That(ex.Source, Is.EqualTo("validation"));
            Assert.That(ex.Recoverable, Is.EqualTo(false));
            Assert.That(ex.RawErrorData.Get("source").ToString(),  Is.EqualTo("validation"));
            Assert.That(ex.RawErrorData.Get("Source").ToString(), Is.EqualTo("validation"));
        }


        [Test]
		public void Test401_AuthenticationException ()
		{

			RequestMap responseMap = new RequestMap ("{\"Errors\":{\"Error\":[{\"Source\":\"OAuth.ConsumerKey\",\"ReasonCode\":\"INVALID_CLIENT_ID\",\"Description\":\"Oauth customer key invalid\",\"Recoverable\":false,\"Details\":null}]}}");
			TestApiController controller = new TestApiController ();

			controller.SetRestClient (mockClient (HttpStatusCode.Unauthorized, responseMap));

            // new Tuple<string, string, List<string>, List<string>>("/test1", null, headerList, queryList);
            var config = new OperationConfig("/test1", "create", headerList, queryList);
            var metadata = new OperationMetadata("0.0.1", "http://locahost:8081");

            ApiException ex = Assert.Throws<ApiException> (() => controller.Execute ( config, metadata, new TestBaseObject (responseMap)));
            Assert.That(ex.Message, Is.EqualTo("Oauth customer key invalid"));
            Assert.That(ex.ReasonCode, Is.EqualTo("INVALID_CLIENT_ID"));
            Assert.That(ex.Source, Is.EqualTo("OAuth.ConsumerKey"));
            Assert.That(ex.Recoverable, Is.EqualTo(false));
        }


		[Test]
		public void Test500_InvalidRequestException ()
		{

			RequestMap responseMap = new RequestMap ("{\"Errors\":{\"Error\":[{\"Source\":\"OAuth.ConsumerKey\",\"ReasonCode\":\"INVALID_CLIENT_ID\",\"Description\":\"Something went wrong\",\"Recoverable\":false,\"Details\":null}]}}");
			TestApiController controller = new TestApiController ();

			controller.SetRestClient (mockClient (HttpStatusCode.InternalServerError, responseMap));

            // new Tuple<string, string, List<string>, List<string>>("/test1", null, headerList, queryList);
            var config = new OperationConfig("/test1", "create", headerList, queryList);
            var metadata = new OperationMetadata("0.0.1", "http://locahost:8081");

            ApiException ex = Assert.Throws<ApiException> (() => controller.Execute ( config, metadata, new TestBaseObject (responseMap)));
            Assert.That(ex.Message, Is.EqualTo("Something went wrong"));
            Assert.That(ex.ReasonCode, Is.EqualTo("INVALID_CLIENT_ID"));
            Assert.That(ex.Source, Is.EqualTo("OAuth.ConsumerKey"));
            Assert.That(ex.Recoverable, Is.EqualTo(false));
        }


		[Test]
		public void Test200ShowById ()
		{

			RequestMap requestMap = new RequestMap ("{\n\"id\":\"1\"\n}");
			RequestMap responseMap = new RequestMap ("{\"Account\":{\"Status\":\"true\",\"Listed\":\"true\",\"ReasonCode\":\"S\",\"Reason\":\"STOLEN\"}}");
			TestApiController controller = new TestApiController ();

			controller.SetRestClient (mockClient (HttpStatusCode.OK, responseMap));

            // new Tuple<string, string, List<string>, List<string>>("/test1", null, headerList, queryList);
            var config = new OperationConfig("/test1", "read", headerList, queryList);
            var metadata = new OperationMetadata("0.0.1", "http://locahost:8081");


            IDictionary<String,Object> result = controller.Execute ( config, metadata,new TestBaseObject (requestMap));
			RequestMap responseMapFromResponse = new RequestMap (result);

			Assert.AreEqual("true", responseMapFromResponse["Account.Status"]);
			Assert.AreEqual("STOLEN", responseMapFromResponse["Account.Reason"]);
		}

        [Test]
        public void TestContentTypeOnGet()
        {

            RequestMap requestMap = new RequestMap("{\n\"id\":\"1\"\n}");
            RequestMap responseMap = new RequestMap("{\"Account\":{\"Status\":\"true\",\"Listed\":\"true\",\"ReasonCode\":\"S\",\"Reason\":\"STOLEN\"}}");
            TestApiController controller = new TestApiController();

            controller.SetRestClient(mockClient(HttpStatusCode.OK, responseMap));

            // new Tuple<string, string, List<string>, List<string>>("/test1", null, headerList, queryList);
            var config = new OperationConfig("/test1", "read", headerList, queryList);
            var metadata = new OperationMetadata("0.0.1", "http://locahost:8081");

            RestyRequest request = controller.GetRequest(config, metadata, new TestBaseObject(requestMap));

            Assert.AreEqual("http://locahost:8081/test1?id=1&Format=JSON", request.AbsoluteUrl.ToString());
            Assert.AreEqual(false, request.HasBody);
            Assert.AreEqual("GET", request.Method.ToString());
            Assert.AreEqual(false, request.Parameters.Exists(i => i.Name.Equals("Content-Type")));
            Assert.AreEqual(true, request.Parameters.Exists(i => i.Name.Equals("Accept")));
            String authentication = request.Parameters.Find(i => i.Name.Equals("Authorization")).Value.ToString();
            Assert.AreEqual(false, authentication.Contains("oauth_body_hash"));
        }

        [Test]
        public void TestContentTypeOnPost()
        {

            RequestMap requestMap = new RequestMap("{\n\"id\":\"1\"\n}");
            RequestMap responseMap = new RequestMap("{\"Account\":{\"Status\":\"true\",\"Listed\":\"true\",\"ReasonCode\":\"S\",\"Reason\":\"STOLEN\"}}");
            TestApiController controller = new TestApiController();

            controller.SetRestClient(mockClient(HttpStatusCode.OK, responseMap));

            // new Tuple<string, string, List<string>, List<string>>("/test1", null, headerList, queryList);
            var config = new OperationConfig("/test1", "create", headerList, queryList);
            var metadata = new OperationMetadata("0.0.1", "http://locahost:8081");

            RestyRequest request = controller.GetRequest(config, metadata, new TestBaseObject(requestMap));

            Assert.AreEqual("http://locahost:8081/test1?Format=JSON", request.AbsoluteUrl.ToString());
            Assert.AreEqual(true, request.HasBody);
            Assert.AreEqual("POST", request.Method.ToString());
            Assert.AreEqual(true, request.Parameters.Exists(i => i.Name.Equals("Content-Type")));
            Assert.AreEqual(true, request.Parameters.Exists(i => i.Name.Equals("Accept")));
            String authentication = request.Parameters.Find(i => i.Name.Equals("Authorization")).Value.ToString();
            Assert.AreEqual(true, authentication.Contains("oauth_body_hash"));
        }

        [Test]
        public void TestContentTypeOverride()
        {

            RequestMap requestMap = new RequestMap("{\n\"id\":\"1\"\n}");
            RequestMap responseMap = new RequestMap("{\"Account\":{\"Status\":\"true\",\"Listed\":\"true\",\"ReasonCode\":\"S\",\"Reason\":\"STOLEN\"}}");
            TestApiController controller = new TestApiController();

            controller.SetRestClient(mockClient(HttpStatusCode.OK, responseMap));

            // new Tuple<string, string, List<string>, List<string>>("/test1", null, headerList, queryList);
            var config = new OperationConfig("/test1", "create", headerList, queryList);
            var metadata = new OperationMetadata("0.0.1", "http://locahost:8081", null, true, "text/json");

            RestyRequest request = controller.GetRequest(config, metadata, new TestBaseObject(requestMap));

            Assert.AreEqual("http://locahost:8081/test1", request.AbsoluteUrl.ToString());
            Assert.AreEqual(true, request.HasBody);
            Assert.AreEqual("POST", request.Method.ToString());
            Assert.AreEqual(true, request.Parameters.Exists(i => i.Name.Equals("Content-Type")));
            Assert.AreEqual(true, request.Parameters.Exists(i => i.Name.Equals("Content-Type")));

            Assert.AreEqual("text/json; charset=utf-8", request.Parameters.Find(i => i.Name.Equals("Accept")).Value.ToString());
            Assert.AreEqual("text/json; charset=utf-8", request.Parameters.Find(i => i.Name.Equals("Content-Type")).Value.ToString());



            String authentication = request.Parameters.Find(i => i.Name.Equals("Authorization")).Value.ToString();
            Assert.AreEqual(true, authentication.Contains("oauth_body_hash"));
        }


        [Test]
		public void TestEnvironments ()
		{

			TestApiController controller = new TestApiController();


            ResourceConfig instance = ResourceConfig.Instance;
            ApiConfig.SetEnvironment(Environment.SANDBOX);

			// new Tuple<string, string, List<string>, List<string>>("/test1", null, headerList, queryList);
            var config = new OperationConfig("/atms/v1/#env/locations", "read", headerList, queryList);
            var metadata = new OperationMetadata("0.0.1", instance.GetHost(), instance.GetContext());

			//default
			Assert.AreEqual("https://sandbox.api.mastercard.com/atms/v1/locations?Format=JSON", controller.GetURL(config, new OperationMetadata("0.0.1", instance.GetHost(), instance.GetContext()), new RequestMap()).ToString());

            ApiConfig.SetEnvironment(Environment.PRODUCTION_ITF);
            Assert.AreEqual("https://api.mastercard.com/atms/v1/itf/locations?Format=JSON", controller.GetURL(config, new OperationMetadata("0.0.1", instance.GetHost(), instance.GetContext()), new RequestMap()).ToString());

            ApiConfig.SetEnvironment(Environment.PRODUCTION_MTF);
            Assert.AreEqual("https://api.mastercard.com/atms/v1/mtf/locations?Format=JSON", controller.GetURL(config, new OperationMetadata("0.0.1", instance.GetHost(), instance.GetContext()), new RequestMap()).ToString());

            ApiConfig.SetEnvironment(Environment.SANDBOX);
            Assert.AreEqual("https://sandbox.api.mastercard.com/atms/v1/locations?Format=JSON", controller.GetURL(config, new OperationMetadata("0.0.1", instance.GetHost(), instance.GetContext()), new RequestMap()).ToString());

            ApiConfig.SetEnvironment(Environment.PRODUCTION);
            Assert.AreEqual("https://api.mastercard.com/atms/v1/locations?Format=JSON", controller.GetURL(config, new OperationMetadata("0.0.1", instance.GetHost(), instance.GetContext()), new RequestMap()).ToString());

            ApiConfig.SetEnvironment(Environment.STAGE);
            Assert.AreEqual("https://stage.api.mastercard.com/atms/v1/locations?Format=JSON", controller.GetURL(config, new OperationMetadata("0.0.1", instance.GetHost(), instance.GetContext()), new RequestMap()).ToString());


            ApiConfig.SetEnvironment(Environment.STAGE);
            Assert.AreEqual("https://stage.api.mastercard.com/atms/v1/locations", controller.GetURL(config, new OperationMetadata("0.0.1", instance.GetHost(), instance.GetContext(), true), new RequestMap()).ToString());

            instance.setHostOverride();

        }
	}
}

