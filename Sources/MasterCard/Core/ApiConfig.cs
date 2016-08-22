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
using MasterCard.Core.Security;
using System.Collections.Generic;

namespace MasterCard.Core
{
    /// <summary>
    /// Master card API config.
    /// </summary>
    public static class ApiConfig
    {
        private static Boolean SANDBOX = true;
        private static Boolean DEBUG = false;
        private static AuthenticationInterface authentication;
        private static Dictionary<String, Object> cryptographyMap = new Dictionary<String, Object>();

        /// <summary>
        /// The AP i BAS e LIV e UR.
        /// </summary>
        private static string API_BASE_LIVE_URL = "https://api.mastercard.com";

        /// <summary>
        /// The AP i BAS e SANDBO x UR.
        /// </summary>
        private static string API_BASE_SANDBOX_URL = "https://sandbox.api.mastercard.com";

        /// <summary>
        /// Gets the live URL.
        /// </summary>
        /// <returns>The live URL.</returns>
        public static string GetLiveUrl()
        {
            return API_BASE_LIVE_URL;
        }

        /// <summary>
        /// Gets the sandbox URL.
        /// </summary>
        /// <returns>The sandbox URL.</returns>
        public static string GetSandboxUrl()
        {
            return API_BASE_SANDBOX_URL;
        }

        /// <summary>
        /// Sets the debug.
        /// </summary>
        /// <param name="debug">If set to <c>true</c> debug.</param>
        public static void SetDebug(Boolean debug)
        {
            ApiConfig.DEBUG = debug;
        }

        /// <summary>
        /// Ises the debug.
        /// </summary>
        /// <returns><c>true</c>, if debug was ised, <c>false</c> otherwise.</returns>
        public static Boolean IsDebug()
        {
            return ApiConfig.DEBUG;
        }

        /// <summary>
        /// Sets the sandbox.
        /// </summary>
        /// <param name="debug">If set to <c>true</c> debug.</param>
        public static void SetSandbox()
        {
            ApiConfig.SANDBOX = true;
        }

        /// <summary>
        /// Gets the sandbox.
        /// </summary>
        /// <returns><c>true</c>, if sandbox was ised, <c>false</c> otherwise.</returns>
        public static Boolean IsSandbox()
        {
            return ApiConfig.SANDBOX;
        }

        /// <summary>
        /// Sets the productioction
        /// </summary>
        public static void SetProduction()
        {
            ApiConfig.SANDBOX = false;
        }


        /// <summary>
        /// get the production
        /// </summary>
        /// <returns></returns>
        public static Boolean IsProduction()
        {
            return !ApiConfig.SANDBOX;
        }


        /// <summary>
        /// Gets the authentication.
        /// </summary>
        /// <returns>The authentication.</returns>
        public static AuthenticationInterface GetAuthentication()
        {
            return ApiConfig.authentication;
        }


        /// <summary>
        /// Sets the authentication.
        /// </summary>
        /// <param name="authentication">Authentication.</param>
        public static void SetAuthentication(AuthenticationInterface authentication)
        {
            ApiConfig.authentication = authentication;
        }


        /// <summary>
        /// Adds the cryptography interceptor.
        /// </summary>
        /// <param name="cryptographyInterceptor">Cryptography interceptor.</param>
        public static void AddCryptographyInterceptor(CryptographyInterceptor cryptographyInterceptor)
        {
            if (!cryptographyMap.ContainsKey(cryptographyInterceptor.GetTriggeringPath()))
            {
                cryptographyMap.Add(cryptographyInterceptor.GetTriggeringPath(), cryptographyInterceptor);
            }
        }

        public static CryptographyInterceptor GetCryptographyInterceptor(String basePath)
        {
            foreach (var entry in cryptographyMap)
            {
                if (entry.Key.Contains(basePath) || basePath.Contains(entry.Key))
                {
                    return (CryptographyInterceptor)entry.Value;
                }
            }
            return null;
        }







    }

}
