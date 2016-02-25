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
using MasterCard.Core.Security;

namespace MasterCard
{
	/// <summary>
	/// Master card API config.
	/// </summary>
	public static class ApiConfig
	{
		private static Boolean SANDBOX = true;
		private static Boolean DEBUG = false;
		private static AuthenticationInterface authentication;

		/// <summary>
		/// The VERSIO.
		/// </summary>
		public const string VERSION = "1.0.0";

		/// <summary>
		/// The AP i BAS e LIV e UR.
		/// </summary>
		public const string API_BASE_LIVE_URL = "https://api.mastercard.com";

		/// <summary>
		/// The AP i BAS e SANDBO x UR.
		/// </summary>
		public const string API_BASE_SANDBOX_URL = "https://sandbox.api.mastercard.com";


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
		/// Gets the authentication.
		/// </summary>
		/// <returns>The authentication.</returns>
		public static AuthenticationInterface getAuthentication() {
			return ApiConfig.authentication;
		}


		/// <summary>
		/// Sets the authentication.
		/// </summary>
		/// <param name="authentication">Authentication.</param>
		public static void setAuthentication(AuthenticationInterface authentication) {
			ApiConfig.authentication = authentication;
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
