using System;
using NUnit.Framework;
using System.Text;

using MasterCard.Core;
using System.Collections.Generic;

namespace MasterCard.Test
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


		public void TestSha1Encode()
		{
			//$this->assertEquals("5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8", Util::sha1Encode("password"));
			Assert.AreEqual("5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8", HexStringFromBytes(Util.Sha1Encode("password")));
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

