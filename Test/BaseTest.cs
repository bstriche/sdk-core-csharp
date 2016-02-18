using System;
using System.Collections.Generic;
using System.Text;
using NUnit.Framework;

namespace MasterCard.SDK.Core.Security
{
	
	[TestFixture]
	class BaseTest
	{

		[SetUp]
		public void setup ()
		{
			MasterCardApiConfig.setP12 ("../../Test/prod_key.p12", "password");
			MasterCardApiConfig.setClientId ("gVaoFbo86jmTfOB4NUyGKaAchVEU8ZVPalHQRLTxeaf750b6!414b543630362f426b4f6636415a5973656c33735661383d");
		}

		[Test]
		public void TestSHA1 ()
		{
			String value = "password";
			byte[] encodedValueAsBytes = OAuthUtil.Sha1Encode (value);
			String hexEncodedValue = HexStringFromBytes (encodedValueAsBytes);
			Assert.AreEqual ("5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8", hexEncodedValue);

		}

		[Test]
		public void TestBase64 ()
		{
			String value = "password";
			UTF8Encoding encoder = new UTF8Encoding ();
			String encodedValue = OAuthUtil.Base64Encode (encoder.GetBytes (value));
			Assert.AreEqual ("cGFzc3dvcmQ=", encodedValue);
		}


		[Test]
		public void TestGenerateSignature ()
		{

			String body = "{ \"name\":\"andrea\", \"surname\":\"rizzini\" }";
			String method = "POST";
			String url = "http://www.andrea.rizzini.com/simple_service";

			OAuthParameters oAuthParameters = new OAuthParameters ();
			oAuthParameters.setOAuthConsumerKey (MasterCardApiConfig.getClientId ());
			oAuthParameters.setOAuthNonce ("NONCE");
			oAuthParameters.setOAuthTimestamp ("TIMESTAMP");
			oAuthParameters.setOAuthSignatureMethod ("RSA-SHA1");


			if (body != null && body.Length > 0) {
				String encodedHash = OAuthUtil.Base64Encode (OAuthUtil.Sha1Encode (body));
				oAuthParameters.setOAuthBodyHash (encodedHash);
			}


			String baseString = OAuthUtil.GetBaseString (url, method, oAuthParameters.getBaseParameters ());
			Assert.AreEqual ("POST&http%3A%2F%2Fwww.andrea.rizzini.com%2Fsimple_service&oauth_body_hash%3DapwbAT6IoMRmB9wE9K4fNHDsaMo%253D%26oauth_consumer_key%3DgVaoFbo86jmTfOB4NUyGKaAchVEU8ZVPalHQRLTxeaf750b6%2521414b543630362f426b4f6636415a5973656c33735661383d%26oauth_nonce%3DNONCE%26oauth_signature_method%3DRSA-SHA1%26oauth_timestamp%3DTIMESTAMP", baseString);

			String signature = OAuthUtil.RsaSign (baseString, MasterCardApiConfig.getPrivateKey ());
			oAuthParameters.setOAuthSignature (signature);
			Assert.AreEqual ("CQJfOX6Yebd7KPPsG7cRopzt+4/QB+GiMQhgcFMw+ew2bWtBLj+t8i6mSe26eEVurxzF4mp0uvjXZzz8Ik5YLjP1byr0v+wsMmAQbWUTj4dO7k8W2+a4AISmKFfbSEUaDgBpPyCl72cL29+hoTNo/usD0EYpaX6P1Vo+EYLbZjK3ZJRtDSd8VZnjxKInUoNI8VvJuGgZ3u7nh5caXvVk6RlCbgwdVEKAv/BsfLSQEgc0/DCCKhX2ZnNOqJJ3FRS6s4bAbqYbui5ouWN5SGkcRaYPt7Fi8oTu561oNZ02HlAWL9m0fp8MK6ZDGQjkeC+zWeo/o0Gbc+/kKGPdOrCNFA==", signature);


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