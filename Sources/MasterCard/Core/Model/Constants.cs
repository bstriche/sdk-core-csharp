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

namespace MasterCard.Core.Model
{
    public class Constants {

        public const String SDK = "MasterCard-Core";
        public const String VERSION = "1.4.10";

        public static String getCoreVersion() {
            return SDK+":"+VERSION;
        }

        public enum Environment {PRODUCTION,SANDBOX,SANDBOX_STATIC,SANDBOX_MTF,SANDBOX_ITF,STAGE,DEV,PRODUCTION_MTF,PRODUCTION_ITF,STAGE_MTF,STAGE_ITF,LOCALHOST,OTHER};

        public static readonly Dictionary<Environment, List<string>> MAPPINGS = new Dictionary<Environment, List<string>>
        {
        {Environment.PRODUCTION, new List<String> { "https://api.mastercard.com", null } },
        {Environment.SANDBOX, new List<String> { "https://sandbox.api.mastercard.com", null } },
        {Environment.SANDBOX_STATIC, new List<String> { "https://sandbox.api.mastercard.com", "static" } },
        {Environment.SANDBOX_MTF, new List<String> { "https://sandbox.api.mastercard.com", "mtf" } },
        {Environment.SANDBOX_ITF, new List<String> { "https://sandbox.api.mastercard.com", "itf" } },
        {Environment.STAGE, new List<String> { "https://stage.api.mastercard.com", null } },
        {Environment.DEV, new List<String> { "https://dev.api.mastercard.com", null } },
        {Environment.PRODUCTION_MTF, new List<String> { "https://api.mastercard.com", "mtf" } },
        {Environment.PRODUCTION_ITF, new List<String> { "https://api.mastercard.com", "itf" } },
        {Environment.STAGE_MTF, new List<String> { "https://stage.api.mastercard.com", "mtf" } },
        {Environment.STAGE_ITF, new List<String> { "https://stage.api.mastercard.com", "itf" } },
        {Environment.LOCALHOST, new List<String> { "http://localhost:8081", null } }
        };

    }

}