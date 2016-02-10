using System;
using System.Text;
using NUnit.Framework;
using Mastercard.SDK;

[TestFixture ()]
class BaseTest
{

	[SetUp]
	public void setup ()
	{
		MasterCardApiConfig.setP12 ("../../Test/prod_key.p12", "password");
		MasterCardApiConfig.setClientId("gVaoFbo86jmTfOB4NUyGKaAchVEU8ZVPalHQRLTxeaf750b6!414b543630362f426b4f6636415a5973656c33735661383d");
	}

	[Test ()]
	public void TestSHA1 ()
	{
		String value = "password";
		byte[] encodedValueAsBytes = OAuthUtil.Sha1Encode (value);
		String hexEncodedValue = HexStringFromBytes (encodedValueAsBytes);
		Assert.AreEqual ("5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8", hexEncodedValue);

	}

	[Test ()]
	public void TestBase64 ()
	{
		String value = "password";
		UTF8Encoding encoder = new UTF8Encoding ();
		String encodedValue = OAuthUtil.Base64Encode (encoder.GetBytes (value));
		Assert.AreEqual ("cGFzc3dvcmQ=", encodedValue);
	}


	[Test ()]
	public void TestGenerateSignature ()
	{
		String body = "{ \"name\":\"andrea\", \"surname\":\"rizzini\" }";
		String method = "POST";
		String url = "http://www.andrea.rizzini.com/simple_service";

		String signature = OAuthUtil.GenerateSignature (url, method, body );
		Assert.IsTrue (signature.IndexOf ("oauth_body_hash=\"apwbAT6IoMRmB9wE9K4fNHDsaMo%3D\"") > 0);
		Assert.IsTrue (signature.IndexOf ("oauth_consumer_key=\"gVaoFbo86jmTfOB4NUyGKaAchVEU8ZVPalHQRLTxeaf750b6%21414b543630362f426b4f6636415a5973656c33735661383d\"") > 0);
	}


	public static string HexStringFromBytes(byte[] bytes)
	{
		var sb = new StringBuilder();
		foreach (byte b in bytes)
		{
			var hex = b.ToString("x2");
			sb.Append(hex);
		}
		return sb.ToString();
	}

}
