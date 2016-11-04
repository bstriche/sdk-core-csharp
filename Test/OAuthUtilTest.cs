

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
            var authentication = new OAuthAuthentication("L5BsiPgaF-O3qA36znUATgQXwJB6MRoMSdhjd7wt50c97279!50596e52466e3966546d434b7354584c4975693238513d3d", currentPath + "\\Test\\mcapi_sandbox_key.p12", "test", "password");
			ApiConfig.SetAuthentication (authentication);
		}



		[Test]
		public void TestGenerateSignature ()
		{

			String body = "{ \"name\":\"andrea\", \"surname\":\"rizzini\" }";
			String method = "POST";
			String url = "http://www.andrea.rizzini.com/simple_service";

			OAuthParameters oAuthParameters = new OAuthParameters ();
			oAuthParameters.setOAuthConsumerKey (((OAuthAuthentication) ApiConfig.GetAuthentication()).ClientId);
			oAuthParameters.setOAuthNonce ("NONCE");
			oAuthParameters.setOAuthTimestamp ("TIMESTAMP");
			oAuthParameters.setOAuthSignatureMethod ("RSA-SHA1");


			if (!string.IsNullOrEmpty (body)) {
				String encodedHash = Util.Base64Encode (Util.Sha1Encode (body));
				oAuthParameters.setOAuthBodyHash (encodedHash);
			}

			String baseString = OAuthUtil.GetBaseString (url, method, oAuthParameters.getBaseParameters ());
			Assert.AreEqual ("POST&http%3A%2F%2Fwww.andrea.rizzini.com%2Fsimple_service&oauth_body_hash%3DapwbAT6IoMRmB9wE9K4fNHDsaMo%253D%26oauth_consumer_key%3DL5BsiPgaF-O3qA36znUATgQXwJB6MRoMSdhjd7wt50c97279%252150596e52466e3966546d434b7354584c4975693238513d3d%26oauth_nonce%3DNONCE%26oauth_signature_method%3DRSA-SHA1%26oauth_timestamp%3DTIMESTAMP", baseString);

			String signature = OAuthUtil.RsaSign (baseString);
			//Assert.AreEqual ("QcjTdnu6CQETgu3czDyURblLsYGIWgsWbnhENB0U0EqgXtoc50lTCvpfPQHT8pPBJ6y6USUgTxShcDXDzDrM4FWMkz0FnQtpTyo4c0ZOInrn9DwDKEOgFtw3BpHxJ1jZ5NSfGwOLXdUThWvS7JylYHod0u4D0381/9y/PkataSX5AdSBEZAT943AIrwHEVWKaGKzt6ABW+GA7GboyhGUWxEVZWXZwT1WURHtUwCOsSbEGPiiURs2+HzOkvLs4tkuMGCNF/9tkEnEcjOHefN1mSVLiv2poJQJQQLps1iOk8v4MwSsnZ8RxlEUET690R0TZ1FhEBJJ25CmwarsUpI3DQ==", signature);
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

