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
using NUnit.Framework;
using System.Text;

using MasterCard.Core;
using MasterCard.Core.Security;
using MasterCard.Core.Security.OAuth;
using System.Collections.Generic;
using MasterCard.Core.Model;
using log4net;
using log4net.Config;


namespace Test
{
	public class BaseTest
	{

        private static readonly ILog log = LogManager.GetLogger(typeof(BaseTest));

        public static Dictionary<String,RequestMap> responses = new Dictionary<String,RequestMap>();
        public static Dictionary<String,AuthenticationInterface> authentications = new Dictionary<String,AuthenticationInterface>();

        static BaseTest() {
            var path = MasterCard.Core.Util.GetCurrenyAssemblyPath();

            authentications.Add("default", new OAuthAuthentication("L5BsiPgaF-O3qA36znUATgQXwJB6MRoMSdhjd7wt50c97279!50596e52466e3966546d434b7354584c4975693238513d3d", path + "\\Test\\mcapi_sandbox_key.p12", "test", "password"));
            
        }

        public static void assert(String s, Object o) {
            if (o is Double) {
                double d1 = double.Parse(s);
                double d2 = (double) o;

                Assert.AreEqual(d1, d2);
            }
            else if (o is DateTime) {
                DateTime dt1 = DateTime.Parse(s);
                DateTime dt2 = (DateTime) o;

                Assert.AreEqual(dt1, dt2);
            }
            else {
                Assert.That(s, Is.EqualTo(o.ToString()).IgnoreCase);
            }
        }

        public static void putResponse(String name, RequestMap response)
        {
            responses.Add(name, response);
        }


        public static void assertEqual(List<string> ignoreAsserts, RequestMap response, String key, String expectedValue)
        {
            if (!ignoreAsserts.Contains(key)) {
                BaseTest.assert(expectedValue, response.Get(key));
            }
        }

        public static Object resolveResponseValue(String overrideValue)
        {
            //arizzini: if plain value, return it
            if (overrideValue.StartsWith("val:")) {
                return overrideValue.Substring(4);
            } else {
                int i = overrideValue.IndexOf(".");

                String name = overrideValue.Substring(0, i);
                String key = overrideValue.Substring(i + 1);

                if  (responses.ContainsKey(name)) {
                    RequestMap response = responses[name];
                    if (response.ContainsKey(key)) {
                        return (Object) response.Get(key);
                    } else {
                        log.Error("Key: "+ key + " is not found in the response");
                    }
                } else {
                     log.Error("Example: " + name+ " is not found in the response");
                }

                return null;
            }

        }

        public static void setAuthentication(String keyId) {
            var authentication = authentications[keyId];

            if (keyId == null) {
                throw new Exception("No authentication found for keyId: " + keyId);
            }

            ApiConfig.SetAuthentication(authentication);
        }

        public static void resetAuthentication() {
            setAuthentication("default");
        }
    }
}