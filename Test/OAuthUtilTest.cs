

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
            var authentication = new OAuthAuthentication("TESTING00-O3qA36znUATgQXwJB6MRoMSdhjd7wt50c9TEST!50596e52466e3966546d434b7354584c497569323851TEST", currentPath + "\\Test\\certs\\fake-key.p12", "fake-key", "fakepassword",  System.Security.Cryptography.X509Certificates.X509KeyStorageFlags.MachineKeySet);
			ApiConfig.SetAuthentication (authentication);
		}



		[Test]
		public void TestGenerateSignature ()
		{

			String body = "{ \"name\":\"example\", \"surname\":\"user\" }";
			String method = "POST";
			String url = "http://www.example.com/simple_service";

			OAuthParameters oAuthParameters = new OAuthParameters ();
			oAuthParameters.setOAuthConsumerKey (((OAuthAuthentication) ApiConfig.GetAuthentication()).ClientId);
			oAuthParameters.setOAuthNonce ("NONCE");
			oAuthParameters.setOAuthTimestamp ("TIMESTAMP");
			oAuthParameters.setOAuthSignatureMethod ("RSA-SHA256");


			if (!string.IsNullOrEmpty (body)) {
				String encodedHash = Util.Base64Encode (Util.Sha1Encode (body));
				oAuthParameters.setOAuthBodyHash (encodedHash);
			}

			String baseString = OAuthUtil.GetBaseString (url, method, oAuthParameters.getBaseParameters ());
			Assert.AreEqual ("POST&http%3A%2F%2Fwww.example.com%2Fsimple_service&oauth_body_hash%3DJwGxCFckV%252FsBA44aVfOJQ%252BWaIuo%253D%26oauth_consumer_key%3DTESTING00-O3qA36znUATgQXwJB6MRoMSdhjd7wt50c9TEST%252150596e52466e3966546d434b7354584c497569323851TEST%26oauth_nonce%3DNONCE%26oauth_signature_method%3DRSA-SHA256%26oauth_timestamp%3DTIMESTAMP", baseString);

			String signature = OAuthUtil.RsaSign (baseString);
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

