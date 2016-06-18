

using System;
using System.Text;
using NUnit.Framework;
using MasterCard.Core;
using MasterCard.Core.Security.OAuth;

using System.Collections.Generic;


namespace TestMasterCard
{
	
	[TestFixture]
	class OAuthUtilTest
	{

		[SetUp]
		public void setup ()
		{

            var currentPath = MasterCard.Core.Util.GetCurrenyAssemblyPath();
            var authentication = new OAuthAuthentication("L5BsiPgaF-O3qA36znUATgQXwJB6MRoMSdhjd7wt50c97279!50596e52466e3966546d434b7354584c4975693238513d3d", currentPath + "\\Test\\mcapi_sandbox_key.p12", "alias", "password");
			ApiConfig.setAuthentication (authentication);
		}



		[Test]
		public void TestGenerateSignature ()
		{

			String body = "{ \"name\":\"andrea\", \"surname\":\"rizzini\" }";
			String method = "POST";
			String url = "http://www.andrea.rizzini.com/simple_service";

			OAuthParameters oAuthParameters = new OAuthParameters ();
			oAuthParameters.setOAuthConsumerKey (((OAuthAuthentication) ApiConfig.getAuthentication()).ClientId);
			oAuthParameters.setOAuthNonce ("NONCE");
			oAuthParameters.setOAuthTimestamp ("TIMESTAMP");
			oAuthParameters.setOAuthSignatureMethod ("RSA-SHA1");


			if (!string.IsNullOrEmpty (body)) {
				String encodedHash = Util.Base64Encode (Util.Sha1Encode (body));
				oAuthParameters.setOAuthBodyHash (encodedHash);
			}

			String baseString = OAuthUtil.GetBaseString (url, method, oAuthParameters.getBaseParameters ());
			Assert.AreEqual ("POST&http%3A%2F%2Fwww.andrea.rizzini.com%2Fsimple_service&oauth_body_hash%3DapwbAT6IoMRmB9wE9K4fNHDsaMo%253D%26oauth_consumer_key%3DgVaoFbo86jmTfOB4NUyGKaAchVEU8ZVPalHQRLTxeaf750b6%2521414b543630362f426b4f6636415a5973656c33735661383d%26oauth_nonce%3DNONCE%26oauth_signature_method%3DRSA-SHA1%26oauth_timestamp%3DTIMESTAMP", baseString);

			String signature = OAuthUtil.RsaSign (baseString);
			Assert.AreEqual ("CQJfOX6Yebd7KPPsG7cRopzt+4/QB+GiMQhgcFMw+ew2bWtBLj+t8i6mSe26eEVurxzF4mp0uvjXZzz8Ik5YLjP1byr0v+wsMmAQbWUTj4dO7k8W2+a4AISmKFfbSEUaDgBpPyCl72cL29+hoTNo/usD0EYpaX6P1Vo+EYLbZjK3ZJRtDSd8VZnjxKInUoNI8VvJuGgZ3u7nh5caXvVk6RlCbgwdVEKAv/BsfLSQEgc0/DCCKhX2ZnNOqJJ3FRS6s4bAbqYbui5ouWN5SGkcRaYPt7Fi8oTu561oNZ02HlAWL9m0fp8MK6ZDGQjkeC+zWeo/o0Gbc+/kKGPdOrCNFA==", signature);
			oAuthParameters.setOAuthSignature (signature);

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

