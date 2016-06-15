


using System;
using NUnit.Framework;
using System.Text;

using MasterCard.Core;
using System.Collections.Generic;

namespace TestMasterCard
{
	[TestFixture]
	public class UtilTest
	{
		[Test]
		public void TestNormalizeUrl ()
		{
			String baseUrl = "http://php.net/manual/en/function.parse-url.php";
			Assert.AreEqual (baseUrl, Util.NormalizeUrl (baseUrl));


			String url2WithParams = "http://php.net/manual/en/function.parse-url.php?some=parameter&some1=parameter2";
			Assert.AreEqual (baseUrl, Util.NormalizeUrl (url2WithParams));

			url2WithParams = "http://php.net/manual/en/function.parse-url.php?some=parameter&some1=parameter2";
			Assert.AreEqual(baseUrl, Util.NormalizeUrl(url2WithParams));

		}


		[Test]
		public void TestNormalizeParameter()
		{
			String url = "http://php.net/manual/en/function.parse-url.php";
			String parameters = "some=parameter&some1=parameter2";

			Assert.AreEqual (parameters, Util.NormalizeParameters (url + "?" + parameters, new SortedDictionary<string, string> ()));

			parameters = "paramNameFromArray1=paramValueFromArray1&paramNameFromArray2=paramValueFromArray2&some=parameter&some1=parameter2";
			Assert.AreEqual (parameters, Util.NormalizeParameters (url + "?" + parameters, new SortedDictionary<string, string> ()));

		}

		[Test]
		public void TestBase64Encode()
		{
			Assert.AreEqual ("cGFzc3dvcmQ=", Util.Base64Encode (System.Text.Encoding.UTF8.GetBytes("password")));
		}


		[Test]
		public void TestSha1Encode()
		{
			//$this->assertEquals("5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8", Util::sha1Encode("password"));
			Assert.AreEqual("5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8", HexStringFromBytes(Util.Sha1Encode("password")));
		}


		[Test]
		public void TestSubMap()
		{
			List<String> listOfKeys = new List<String> { "one", "three" };

			Dictionary<string, object> inputMap = new Dictionary<string, object>
			{
				{ "one", "1" },
				{ "two", "2" },
				{ "three", "3" },
				{ "four", "4" }
			};

			IDictionary<String,Object> subMap = Util.SubMap (inputMap, listOfKeys);

			Assert.AreEqual (2, subMap.Count);
			Assert.AreEqual (2, inputMap.Count);

			Assert.AreEqual(true, subMap.ContainsKey("one"));
			Assert.AreEqual(true, subMap.ContainsKey("three"));

			Assert.AreEqual("1", subMap["one"]);
			Assert.AreEqual("3", subMap["three"]);

			Assert.AreEqual(true, inputMap.ContainsKey("two"));
			Assert.AreEqual(true, inputMap.ContainsKey("four"));

			Assert.AreEqual("2", inputMap["two"]);
			Assert.AreEqual("4", inputMap["four"]);
		}


		[Test]
		public void TestGetPathWithReplacedPath()
		{
			Dictionary<string, object> inputMap = new Dictionary<string, object>
			{
				{ "name", "andrea" },
				{ "surname", "rizzini" },
				{ "three", "3" },
				{ "four", "4" }
			};

			String path = "begin/nome/{name}/cognome/{surname}/end";

			String resolvedPath = Util.GetReplacedPath (path, inputMap);

			Assert.AreEqual ("begin/nome/andrea/cognome/rizzini/end", resolvedPath);

		}



		static string HexStringFromBytes (byte[] bytes)
		{
			var sb = new StringBuilder ();
			foreach (byte b in bytes) {
				var hex = b.ToString ("x2");
				sb.Append (hex);
			}
			return sb.ToString ();
		}
	}
}


