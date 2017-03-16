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
using System.Collections.Generic;
using MasterCard.Core.Model;
using MasterCard.Core;
using Environment = MasterCard.Core.Model.Constants.Environment;

namespace TestMasterCard
{
    public class ResourceConfig : ResourceConfigInterface
    {
        private string hostOverride = null;
        private string host = null;
        private string context = null;
        private string version = "1.0.1";
        private static ResourceConfig instance = null;

        private ResourceConfig() {

        }
        
        public static ResourceConfig Instance
        {
            get 
            {
                if (instance == null)
                {
                    instance = new ResourceConfig();
                    ApiConfig.RegisterResourceConfig(instance);
                    instance.SetEnvironment(ApiConfig.GetEnvironment());
                }
                return instance;
            }
        }

        public string GetHost()
        {
            return (hostOverride != null) ? hostOverride: host;
        }

        public string GetContext() {
            return this.context;
        }

        public string GetVersion()
        {
            return this.version;
        }

        public void SetEnvironment(Environment environment)
        {
            if (Constants.MAPPINGS.ContainsKey(environment)) {
                List<String> tuple = Constants.MAPPINGS[environment];
                this.host = tuple[0];
                this.context = tuple[1];
            }
        }

        public void SetEnvironment(string host, string context)
        {
            this.host = host;
            this.context = context;
        }

        public void clearHostOverride()
        {
            this.hostOverride = null;
        }

        public void setHostOverride()
        {
            this.hostOverride = "http://localhost:8081";
        }

    }

}
