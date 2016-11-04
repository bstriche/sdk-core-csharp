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
    public class User : BaseObject
    {

        public User(RequestMap bm) : base(bm)
        {
		}

        public User() : base()
        {
        }

        private static readonly Dictionary<string, OperationConfig> _store = new Dictionary<string, OperationConfig>
        {
        {"9a3e3a35-8aab-4696-90ce-df458a2c5fee", new OperationConfig("/mock_crud_server/users", "list", new List<String> {  }, new List<String> {  })},
        {"a6d7c23b-4b03-4e41-bdbd-6c7c6902d72f", new OperationConfig("/mock_crud_server/users", "create", new List<String> {  }, new List<String> {  })},
        {"008b48e2-a8b1-47ab-9b2d-6228a61d5dee", new OperationConfig("/mock_crud_server/users/{id}", "read", new List<String> {  }, new List<String> {  })},
        {"4a114425-0aed-4805-b820-50e7e3985450", new OperationConfig("/mock_crud_server/users/{id}", "update", new List<String> {  }, new List<String> {  })},
        {"db10ab01-2198-4abf-ade1-3868cfb3d01c", new OperationConfig("/mock_crud_server/users/{id}", "delete", new List<String> {  }, new List<String> {  })},
        {"f6048a68-7ad7-46a4-8bd9-670641c219ac", new OperationConfig("/mock_crud_server/users200/{id}", "delete", new List<String> {  }, new List<String> {  })},
        {"1bce28cd-c900-41b6-ac86-3232903ada1f", new OperationConfig("/mock_crud_server/users204/{id}", "delete", new List<String> {  }, new List<String> {  })},
        
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
            return new OperationMetadata(SDKConfig.GetVersion(), SDKConfig.GetHost());
        }

        
        
        
        
        
        /// <summary>
        /// Retrieves a list of type <code>User</code>
        /// </summary>
        /// <returns> A list User of objects </returns>
        /// <exception cref="ApiCommunicationException"> </exception>
        /// <exception cref="AuthenticationException"> </exception>
        /// <exception cref="InvalidRequestException"> </exception>
        /// <exception cref="NotAllowedException"> </exception>
        /// <exception cref="ObjectNotFoundException"> </exception>
        /// <exception cref="SystemException"> </exception>
        public static List<User> List()
        {
            return BaseObject.ExecuteForList("9a3e3a35-8aab-4696-90ce-df458a2c5fee", new User());
        }

        /// <summary>
        /// Retrieves a list of type <code>User</code> using the specified criteria
        /// </summary>
        /// <param name="criteria">The criteria set of values which is used to identify the set of records of User object to return</praram>
        /// <returns>  a List of User objects which holds the list objects available. </returns>
        /// <exception cref="ApiCommunicationException"> </exception>
        /// <exception cref="AuthenticationException"> </exception>
        /// <exception cref="InvalidRequestException"> </exception>
        /// <exception cref="NotAllowedException"> </exception>
        /// <exception cref="ObjectNotFoundException"> </exception>
        /// <exception cref="SystemException"> </exception>
        public static List<User> List(RequestMap criteria)
        {
            return BaseObject.ExecuteForList("9a3e3a35-8aab-4696-90ce-df458a2c5fee", new User(criteria));
        }
        
        
        
        
        
        /// <summary>
        /// Creates an object of type <code>User</code>
        /// </summary>
        /// <param name="map">A RequestMap containing the required parameters to create a new object</praram>
        /// <returns> A User object </returns>
        /// <exception cref="ApiCommunicationException"> </exception>
        /// <exception cref="AuthenticationException"> </exception>
        /// <exception cref="InvalidRequestException"> </exception>
        /// <exception cref="NotAllowedException"> </exception>
        /// <exception cref="SystemException"> </exception>
        public static User Create(RequestMap map)
        {
            return BaseObject.Execute("a6d7c23b-4b03-4e41-bdbd-6c7c6902d72f", new User(map));
        }
        
        
        
        
        
        
        
        
        
        
        
        /// <summary>
        /// Retrieves one object of type <code>User</code>
        /// </summary>
        /// <param name="id">The unique identifier which is used to identify an User object.</param>
        /// <param name = "parameters">This is the optional parameter which can be passed to the request.</param>
        /// <returns> A User object </returns>
        /// <exception cref="ApiCommunicationException"> </exception>
        /// <exception cref="AuthenticationException"> </exception>
        /// <exception cref="InvalidRequestException"> </exception>
        /// <exception cref="NotAllowedException"> </exception>
        /// <exception cref="ObjectNotFoundException"> </exception>
        /// <exception cref="SystemException"> </exception>
        public static User Read(String id, RequestMap parameters = null)
        {
            RequestMap map = new RequestMap();
            map.Set("id", id);
		    if (parameters != null && parameters.Count > 0) {
		        map.AddAll (parameters);
            }
            return BaseObject.Execute("008b48e2-a8b1-47ab-9b2d-6228a61d5dee", new User(map));
        }
        
        
        
        
        /// <summary>
        /// Updates an object of type <code>User</code>
        /// </summary>
        /// <returns> A User object </returns>
        /// <exception cref="ApiCommunicationException"> </exception>
        /// <exception cref="AuthenticationException"> </exception>
        /// <exception cref="InvalidRequestException"> </exception>
        /// <exception cref="NotAllowedException"> </exception>
        /// <exception cref="ObjectNotFoundException"> </exception>
        /// <exception cref="SystemException"> </exception>
        public User Update()
        {
            return  BaseObject.Execute("4a114425-0aed-4805-b820-50e7e3985450",this);
        }

        
        
        
        
        
        
        
        
        
        /// <summary>
        /// Delete this object of type <code>User</code>
        /// </summary>
        /// <returns> A User object </returns>
        /// <exception cref="ApiCommunicationException"> </exception>
        /// <exception cref="AuthenticationException"> </exception>
        /// <exception cref="InvalidRequestException"> </exception>
        /// <exception cref="NotAllowedException"> </exception>
        /// <exception cref="ObjectNotFoundException"> </exception>
        /// <exception cref="SystemException"> </exception>
        public User Delete()
        {
            return BaseObject.Execute("db10ab01-2198-4abf-ade1-3868cfb3d01c", this);
        }

        /// <summary>
        /// Delete an object of type <code>User</code>
        /// </summary>
        /// <param name="id">The unique identifier which is used to identify an User object.</param>
        /// <returns> A User object </returns>
        /// <exception cref="ApiCommunicationException"> </exception>
        /// <exception cref="AuthenticationException"> </exception>
        /// <exception cref="InvalidRequestException"> </exception>
        /// <exception cref="NotAllowedException"> </exception>
        /// <exception cref="ObjectNotFoundException"> </exception>
        /// <exception cref="SystemException"> </exception>
        public static User Delete(String id)
        {
            return BaseObject.Execute("db10ab01-2198-4abf-ade1-3868cfb3d01c", new User(new RequestMap("id", id)));
        }

        /// <summary>
        /// Delete an object of type <code>User</code>
        /// </summary>
        /// <param name="id">The unique identifier which is used to identify an User object.</param>
        /// <param name="parameters">additional parameters</param>
        /// <returns> A User object </returns>
        /// <exception cref="ApiCommunicationException"> </exception>
        /// <exception cref="AuthenticationException"> </exception>
        /// <exception cref="InvalidRequestException"> </exception>
        /// <exception cref="NotAllowedException"> </exception>
        /// <exception cref="ObjectNotFoundException"> </exception>
        /// <exception cref="SystemException"> </exception>
        public static User Delete(String id, RequestMap parameters)
        {
            RequestMap map = new RequestMap();
            map.Set("id", id);
            map.AddAll (parameters);
            return BaseObject.Execute("db10ab01-2198-4abf-ade1-3868cfb3d01c", new User(map));
        }
        
        
        
        
        
        
        
        /// <summary>
        /// Delete this object of type <code>User</code>
        /// </summary>
        /// <returns> A User object </returns>
        /// <exception cref="ApiCommunicationException"> </exception>
        /// <exception cref="AuthenticationException"> </exception>
        /// <exception cref="InvalidRequestException"> </exception>
        /// <exception cref="NotAllowedException"> </exception>
        /// <exception cref="ObjectNotFoundException"> </exception>
        /// <exception cref="SystemException"> </exception>
        public User delete200()
        {
            return BaseObject.Execute("f6048a68-7ad7-46a4-8bd9-670641c219ac", this);
        }

        /// <summary>
        /// Delete an object of type <code>User</code>
        /// </summary>
        /// <param name="id">The unique identifier which is used to identify an User object.</param>
        /// <returns> A User object </returns>
        /// <exception cref="ApiCommunicationException"> </exception>
        /// <exception cref="AuthenticationException"> </exception>
        /// <exception cref="InvalidRequestException"> </exception>
        /// <exception cref="NotAllowedException"> </exception>
        /// <exception cref="ObjectNotFoundException"> </exception>
        /// <exception cref="SystemException"> </exception>
        public static User delete200(String id)
        {
            return BaseObject.Execute("f6048a68-7ad7-46a4-8bd9-670641c219ac", new User(new RequestMap("id", id)));
        }

        /// <summary>
        /// Delete an object of type <code>User</code>
        /// </summary>
        /// <param name="id">The unique identifier which is used to identify an User object.</param>
        /// <param name="parameters">additional parameters</param>
        /// <returns> A User object </returns>
        /// <exception cref="ApiCommunicationException"> </exception>
        /// <exception cref="AuthenticationException"> </exception>
        /// <exception cref="InvalidRequestException"> </exception>
        /// <exception cref="NotAllowedException"> </exception>
        /// <exception cref="ObjectNotFoundException"> </exception>
        /// <exception cref="SystemException"> </exception>
        public static User delete200(String id, RequestMap parameters)
        {
            RequestMap map = new RequestMap();
            map.Set("id", id);
            map.AddAll (parameters);
            return BaseObject.Execute("f6048a68-7ad7-46a4-8bd9-670641c219ac", new User(map));
        }
        
        
        
        
        
        
        
        /// <summary>
        /// Delete this object of type <code>User</code>
        /// </summary>
        /// <returns> A User object </returns>
        /// <exception cref="ApiCommunicationException"> </exception>
        /// <exception cref="AuthenticationException"> </exception>
        /// <exception cref="InvalidRequestException"> </exception>
        /// <exception cref="NotAllowedException"> </exception>
        /// <exception cref="ObjectNotFoundException"> </exception>
        /// <exception cref="SystemException"> </exception>
        public User delete204()
        {
            return BaseObject.Execute("1bce28cd-c900-41b6-ac86-3232903ada1f", this);
        }

        /// <summary>
        /// Delete an object of type <code>User</code>
        /// </summary>
        /// <param name="id">The unique identifier which is used to identify an User object.</param>
        /// <returns> A User object </returns>
        /// <exception cref="ApiCommunicationException"> </exception>
        /// <exception cref="AuthenticationException"> </exception>
        /// <exception cref="InvalidRequestException"> </exception>
        /// <exception cref="NotAllowedException"> </exception>
        /// <exception cref="ObjectNotFoundException"> </exception>
        /// <exception cref="SystemException"> </exception>
        public static User delete204(String id)
        {
            return BaseObject.Execute("1bce28cd-c900-41b6-ac86-3232903ada1f", new User(new RequestMap("id", id)));
        }

        /// <summary>
        /// Delete an object of type <code>User</code>
        /// </summary>
        /// <param name="id">The unique identifier which is used to identify an User object.</param>
        /// <param name="parameters">additional parameters</param>
        /// <returns> A User object </returns>
        /// <exception cref="ApiCommunicationException"> </exception>
        /// <exception cref="AuthenticationException"> </exception>
        /// <exception cref="InvalidRequestException"> </exception>
        /// <exception cref="NotAllowedException"> </exception>
        /// <exception cref="ObjectNotFoundException"> </exception>
        /// <exception cref="SystemException"> </exception>
        public static User delete204(String id, RequestMap parameters)
        {
            RequestMap map = new RequestMap();
            map.Set("id", id);
            map.AddAll (parameters);
            return BaseObject.Execute("1bce28cd-c900-41b6-ac86-3232903ada1f", new User(map));
        }
        
        
        
        
    }
}


