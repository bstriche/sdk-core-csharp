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
    public class UserPostHeader : BaseObject
    {

        public UserPostHeader(RequestMap bm) : base(bm)
        {
		}

        public UserPostHeader() : base()
        {
        }

        private static readonly Dictionary<string, OperationConfig> _store = new Dictionary<string, OperationConfig>
        {
        {"e73cc3dc-243e-4e28-b614-d4cc7971f801", new OperationConfig("/mock_crud_server/users/posts", "list", new List<String> {  }, new List<String> { "user_id" })},
        
        };

        protected override OperationConfig GetOperationConfig(string operationUUID)
        {
            if (!_store.ContainsKey(operationUUID))
            {
                throw new System.ArgumentException("Invalid operationUUID supplied: " + operationUUID);
            }
            return _store[operationUUID];
        }

        protected override OperationMetadata GetOperationMetadata()
        {
            return new OperationMetadata(ResourceConfig.Instance.GetVersion(), ResourceConfig.Instance.GetHost(), ResourceConfig.Instance.GetContext());
        }

        
        
        
        
        
        /// <summary>
        /// Retrieves a list of type <code>UserPostHeader</code>
        /// </summary>
        /// <returns> A list UserPostHeader of objects </returns>
        /// <exception cref="ApiCommunicationException"> </exception>
        /// <exception cref="AuthenticationException"> </exception>
        /// <exception cref="InvalidRequestException"> </exception>
        /// <exception cref="NotAllowedException"> </exception>
        /// <exception cref="ObjectNotFoundException"> </exception>
        /// <exception cref="SystemException"> </exception>
        public static List<UserPostHeader> List()
        {
            return BaseObject.ExecuteForList("e73cc3dc-243e-4e28-b614-d4cc7971f801", new UserPostHeader());
        }

        /// <summary>
        /// Retrieves a list of type <code>UserPostHeader</code> using the specified criteria
        /// </summary>
        /// <param name="criteria">The criteria set of values which is used to identify the set of records of UserPostHeader object to return</praram>
        /// <returns>  a List of UserPostHeader objects which holds the list objects available. </returns>
        /// <exception cref="ApiCommunicationException"> </exception>
        /// <exception cref="AuthenticationException"> </exception>
        /// <exception cref="InvalidRequestException"> </exception>
        /// <exception cref="NotAllowedException"> </exception>
        /// <exception cref="ObjectNotFoundException"> </exception>
        /// <exception cref="SystemException"> </exception>
        public static List<UserPostHeader> List(RequestMap criteria)
        {
            return BaseObject.ExecuteForList("e73cc3dc-243e-4e28-b614-d4cc7971f801", new UserPostHeader(criteria));
        }
        
        
        
        
        
    }
}


