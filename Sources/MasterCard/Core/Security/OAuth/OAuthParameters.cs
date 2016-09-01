using System;
using System.Collections.Generic;

namespace MasterCard.Core.Security.OAuth
{

	internal class OAuthParameters
	{

		public static readonly String OAUTH_BODY_HASH_KEY = "oauth_body_hash";
		public static readonly String OAUTH_CALLBACK_KEY = "oauth_callback";
		public static readonly String OAUTH_CONSUMER_KEY = "oauth_consumer_key";
		public static readonly String OAUTH_CONSUMER_SECRET = "oauth_consumer_secret";
		public static readonly String OAUTH_NONCE_KEY = "oauth_nonce";
		public static readonly String OAUTH_KEY = "OAuth";
		public static readonly String OAUTH_SIGNATURE_KEY = "oauth_signature";
		public static readonly String OAUTH_SIGNATURE_METHOD_KEY = "oauth_signature_method";
		public static readonly String OAUTH_TIMESTAMP_KEY = "oauth_timestamp";
		public static readonly String OAUTH_TOKEN_KEY = "oauth_token";
		public static readonly String OAUTH_TOKEN_SECRET_KEY = "oauth_token_secret";
		public static readonly String OAUTH_VERIFIER_KEY = "oauth_verifier";
		public static readonly String OAUTH_VERSION = "oauth_version";
		public static readonly String REALM_KEY = "realm";
		public static readonly String XOAUTH_REQUESTOR_ID_KEY = "xoauth_requestor_id";


		protected SortedDictionary<String, String> baseParameters;

		internal OAuthParameters ()
		{
			this.baseParameters = new SortedDictionary<String,String>();
		}

		private void Put(String key, String value, SortedDictionary<String, String> dictionary) {
			dictionary.Add(key, value);
		}

		public void setOAuthConsumerKey(String consumerKey) {
			this.Put(OAUTH_CONSUMER_KEY, consumerKey, this.baseParameters);
		}

		public void setOAuthNonce(String oauthNonce) {
			this.Put(OAUTH_NONCE_KEY, oauthNonce, this.baseParameters);
		}

		public void setOAuthTimestamp(String timestamp) {
			this.Put(OAUTH_TIMESTAMP_KEY, timestamp, this.baseParameters);
		}

		public void setOAuthSignatureMethod(String signatureMethod) {
			this.Put(OAUTH_SIGNATURE_METHOD_KEY, signatureMethod, this.baseParameters);
		}

		public void setOAuthSignature(String signature) {
			this.Put(OAUTH_SIGNATURE_KEY, signature, this.baseParameters);
		}

		public void setOAuthBodyHash(String bodyHash) {
			this.Put(OAUTH_BODY_HASH_KEY, bodyHash, this.baseParameters);
		}

		public void setOAuthVersion (String version) {
			this.Put(OAUTH_VERSION, version, this.baseParameters);
		}

		public SortedDictionary<String, String> getBaseParameters() {
			return new SortedDictionary<String,String> (this.baseParameters);
		}


	}
}

