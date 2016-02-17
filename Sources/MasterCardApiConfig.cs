using System;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;

namespace MasterCard.SDK
{
	/// <summary>
	/// Master card API config.
	/// </summary>
	public class MasterCardApiConfig
	{
		private static String CLIENT_ID;
		private static Boolean SANDBOX = true;
		private static Boolean DEBUG = false;
		private static AsymmetricAlgorithm PRIVATE_KEY;

		/// <summary>
		/// Sets the p12.
		/// </summary>
		/// <param name="filePath">File path.</param>
		/// <param name="password">Password.</param>
		public static void setP12(String filePath, String password){
			X509Certificate2 cert = new X509Certificate2(filePath, password);
			MasterCardApiConfig.PRIVATE_KEY = cert.PrivateKey;
		}

		/// <summary>
		/// Gets the client identifier.
		/// </summary>
		/// <returns>The client identifier.</returns>
		public static String getClientId() {
			return MasterCardApiConfig.CLIENT_ID;
		}

		/// <summary>
		/// Gets the private key.
		/// </summary>
		/// <returns>The private key.</returns>
		public static AsymmetricAlgorithm getPrivateKey() {
			return PRIVATE_KEY;
		}

		/// <summary>
		/// Sets the client identifier.
		/// </summary>
		/// <param name="clientId">Client identifier.</param>
		public static void setClientId(String clientId) {
			MasterCardApiConfig.CLIENT_ID = clientId;
		}


		/// <summary>
		/// Sets the debug.
		/// </summary>
		/// <param name="debug">If set to <c>true</c> debug.</param>
		public static void setDebug(Boolean debug) {
			MasterCardApiConfig.DEBUG = debug;
		}

		/// <summary>
		/// Ises the debug.
		/// </summary>
		/// <returns><c>true</c>, if debug was ised, <c>false</c> otherwise.</returns>
		public static Boolean isDebug() {
			return MasterCardApiConfig.DEBUG;
		}

		/// <summary>
		/// Sets the sandbox.
		/// </summary>
		/// <param name="debug">If set to <c>true</c> debug.</param>
		public static void setSandbox(Boolean debug) {
			MasterCardApiConfig.SANDBOX = debug;
		}

		/// <summary>
		/// Ises the sandbox.
		/// </summary>
		/// <returns><c>true</c>, if sandbox was ised, <c>false</c> otherwise.</returns>
		public static Boolean isSandbox() {
			return MasterCardApiConfig.SANDBOX;
		}
	}

}
