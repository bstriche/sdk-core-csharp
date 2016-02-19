/*
 * Copyright 2016 MasterCard International.
 *
 * Redistribution and use in source and binary forms, with or without modification, are 
 * permitted provided that the following conditions are met:
 *
 * Redistributions of source code must retain the above copyright notice, this list of 
 * conditions and the following disclaimer.
 * Redistributions in binary form must reproduce the above copyright notice, this list of 
 * conditions and the following disclaimer in the documentation and/or other materials 
 * provided with the distribution.
 * Neither the name of the MasterCard International Incorporated nor the names of its 
 * contributors may be used to endorse or promote products derived from this software 
 * without specific prior written permission.
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY 
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES 
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT 
 * SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, 
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
 * TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; 
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER 
 * IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING 
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF 
 * SUCH DAMAGE.
 *
 */

using System;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;

namespace MasterCard
{
	/// <summary>
	/// Master card API config.
	/// </summary>
	public static class ApiConfig
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
			ApiConfig.PRIVATE_KEY = cert.PrivateKey;
		}

		/// <summary>
		/// Gets the client identifier.
		/// </summary>
		/// <returns>The client identifier.</returns>
		public static String getClientId() {
			return ApiConfig.CLIENT_ID;
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
			ApiConfig.CLIENT_ID = clientId;
		}


		/// <summary>
		/// Sets the debug.
		/// </summary>
		/// <param name="debug">If set to <c>true</c> debug.</param>
		public static void setDebug(Boolean debug) {
			ApiConfig.DEBUG = debug;
		}

		/// <summary>
		/// Ises the debug.
		/// </summary>
		/// <returns><c>true</c>, if debug was ised, <c>false</c> otherwise.</returns>
		public static Boolean isDebug() {
			return ApiConfig.DEBUG;
		}

		/// <summary>
		/// Sets the sandbox.
		/// </summary>
		/// <param name="debug">If set to <c>true</c> debug.</param>
		public static void setSandbox(Boolean debug) {
			ApiConfig.SANDBOX = debug;
		}

		/// <summary>
		/// Ises the sandbox.
		/// </summary>
		/// <returns><c>true</c>, if sandbox was ised, <c>false</c> otherwise.</returns>
		public static Boolean isSandbox() {
			return ApiConfig.SANDBOX;
		}
	}

}
