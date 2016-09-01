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
using MasterCard.Core;
using MasterCard.Core.Exceptions;
using MasterCard.Core.Model;
using MasterCard.Core.Security;


namespace TestMasterCard
{
    public class MerchantCategories : BaseObject
    {

        public MerchantCategories(RequestMap bm) : base(bm)
        {
		}

        public MerchantCategories() : base()
        {
        }

        protected override OperationConfig GetOperationConfig(string operationUUID)
        {
            switch (operationUUID)
            {
                case "uuid":
                    return new OperationConfig("/merchants/v1/category", "query", new List<string>(), new List<string>());
                default:
                    throw new System.ArgumentException("Invalid operationUUID supplied: " + operationUUID);
            }
        }

        protected override OperationMetadata GetOperationMetadata()
        {
            return new OperationMetadata("0.0.1", null);
        }
        


        
        
        
        
        
        
        
        
        /// <summary>
        /// Query and Returns one object of type <code>MerchantCategories</code>
        /// </summary>
        /// <param name = "parameters">This is the optional paramter which can be passed to the request.</param>
        /// <returns> A MerchantCategories object </returns>
        /// <exception cref="ApiCommunicationException"> </exception>
        /// <exception cref="AuthenticationException"> </exception>
        /// <exception cref="InvalidRequestException"> </exception>
        /// <exception cref="NotAllowedException"> </exception>
        /// <exception cref="ObjectNotFoundException"> </exception>
        /// <exception cref="SystemException"> </exception>
        public static MerchantCategories Query(RequestMap parameters)
        {
            return BaseObject.Execute("uuid", new MerchantCategories(parameters));
        }
        
        
    }
}


