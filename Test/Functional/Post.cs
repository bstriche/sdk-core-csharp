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
    public class Post : BaseObject
    {

        public Post(RequestMap bm) : base(bm)
        {
		}

        public Post() : base()
        {
        }

        private static readonly Dictionary<string, OperationConfig> _store = new Dictionary<string, OperationConfig>
        {
        {"87e0af1c-a316-44c9-ac77-87ff2a093e3f", new OperationConfig("/mock_crud_server/posts", "list", new List<String> { "max" }, new List<String> {  })},
        {"6b3326ff-f5b8-4c12-bb45-8929177ad8e6", new OperationConfig("/mock_crud_server/posts", "create", new List<String> {  }, new List<String> {  })},
        {"5347cde5-c964-43dc-b316-8f53d0c662c5", new OperationConfig("/mock_crud_server/posts/{id}", "read", new List<String> {  }, new List<String> {  })},
        {"e697bda0-15f1-4894-9e53-b06b8929122e", new OperationConfig("/mock_crud_server/posts/{id}", "update", new List<String> {  }, new List<String> {  })},
        {"dff1a901-b80d-4cdf-a04b-ae5b084f95fb", new OperationConfig("/mock_crud_server/posts/{id}", "delete", new List<String> {  }, new List<String> {  })},
        
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
        /// Retrieves a list of type <code>Post</code>
        /// </summary>
        /// <returns> A list Post of objects </returns>
        /// <exception cref="ApiCommunicationException"> </exception>
        /// <exception cref="AuthenticationException"> </exception>
        /// <exception cref="InvalidRequestException"> </exception>
        /// <exception cref="NotAllowedException"> </exception>
        /// <exception cref="ObjectNotFoundException"> </exception>
        /// <exception cref="SystemException"> </exception>
        public static List<Post> List()
        {
            return BaseObject.ExecuteForList("87e0af1c-a316-44c9-ac77-87ff2a093e3f", new Post());
        }

        /// <summary>
        /// Retrieves a list of type <code>Post</code> using the specified criteria
        /// </summary>
        /// <param name="criteria">The criteria set of values which is used to identify the set of records of Post object to return</praram>
        /// <returns>  a List of Post objects which holds the list objects available. </returns>
        /// <exception cref="ApiCommunicationException"> </exception>
        /// <exception cref="AuthenticationException"> </exception>
        /// <exception cref="InvalidRequestException"> </exception>
        /// <exception cref="NotAllowedException"> </exception>
        /// <exception cref="ObjectNotFoundException"> </exception>
        /// <exception cref="SystemException"> </exception>
        public static List<Post> List(RequestMap criteria)
        {
            return BaseObject.ExecuteForList("87e0af1c-a316-44c9-ac77-87ff2a093e3f", new Post(criteria));
        }
        
        
        
        
        
        /// <summary>
        /// Creates an object of type <code>Post</code>
        /// </summary>
        /// <param name="map">A RequestMap containing the required parameters to create a new object</praram>
        /// <returns> A Post object </returns>
        /// <exception cref="ApiCommunicationException"> </exception>
        /// <exception cref="AuthenticationException"> </exception>
        /// <exception cref="InvalidRequestException"> </exception>
        /// <exception cref="NotAllowedException"> </exception>
        /// <exception cref="SystemException"> </exception>
        public static Post Create(RequestMap map)
        {
            return BaseObject.Execute("6b3326ff-f5b8-4c12-bb45-8929177ad8e6", new Post(map));
        }
        
        
        
        
        
        
        
        
        
        
        
        /// <summary>
        /// Retrieves one object of type <code>Post</code>
        /// </summary>
        /// <param name="id">The unique identifier which is used to identify an Post object.</param>
        /// <param name = "parameters">This is the optional parameter which can be passed to the request.</param>
        /// <returns> A Post object </returns>
        /// <exception cref="ApiCommunicationException"> </exception>
        /// <exception cref="AuthenticationException"> </exception>
        /// <exception cref="InvalidRequestException"> </exception>
        /// <exception cref="NotAllowedException"> </exception>
        /// <exception cref="ObjectNotFoundException"> </exception>
        /// <exception cref="SystemException"> </exception>
        public static Post Read(String id, RequestMap parameters = null)
        {
            RequestMap map = new RequestMap();
            map.Set("id", id);
		    if (parameters != null && parameters.Count > 0) {
		        map.AddAll (parameters);
            }
            return BaseObject.Execute("5347cde5-c964-43dc-b316-8f53d0c662c5", new Post(map));
        }
        
        
        
        
        /// <summary>
        /// Updates an object of type <code>Post</code>
        /// </summary>
        /// <returns> A Post object </returns>
        /// <exception cref="ApiCommunicationException"> </exception>
        /// <exception cref="AuthenticationException"> </exception>
        /// <exception cref="InvalidRequestException"> </exception>
        /// <exception cref="NotAllowedException"> </exception>
        /// <exception cref="ObjectNotFoundException"> </exception>
        /// <exception cref="SystemException"> </exception>
        public Post Update()
        {
            return  BaseObject.Execute("e697bda0-15f1-4894-9e53-b06b8929122e",this);
        }

        
        
        
        
        
        
        
        
        
        /// <summary>
        /// Delete this object of type <code>Post</code>
        /// </summary>
        /// <returns> A Post object </returns>
        /// <exception cref="ApiCommunicationException"> </exception>
        /// <exception cref="AuthenticationException"> </exception>
        /// <exception cref="InvalidRequestException"> </exception>
        /// <exception cref="NotAllowedException"> </exception>
        /// <exception cref="ObjectNotFoundException"> </exception>
        /// <exception cref="SystemException"> </exception>
        public Post Delete()
        {
            return BaseObject.Execute("dff1a901-b80d-4cdf-a04b-ae5b084f95fb", this);
        }

        /// <summary>
        /// Delete an object of type <code>Post</code>
        /// </summary>
        /// <param name="id">The unique identifier which is used to identify an Post object.</param>
        /// <returns> A Post object </returns>
        /// <exception cref="ApiCommunicationException"> </exception>
        /// <exception cref="AuthenticationException"> </exception>
        /// <exception cref="InvalidRequestException"> </exception>
        /// <exception cref="NotAllowedException"> </exception>
        /// <exception cref="ObjectNotFoundException"> </exception>
        /// <exception cref="SystemException"> </exception>
        public static Post Delete(String id)
        {
            return BaseObject.Execute("dff1a901-b80d-4cdf-a04b-ae5b084f95fb", new Post(new RequestMap("id", id)));
        }

        /// <summary>
        /// Delete an object of type <code>Post</code>
        /// </summary>
        /// <param name="id">The unique identifier which is used to identify an Post object.</param>
        /// <param name="parameters">additional parameters</param>
        /// <returns> A Post object </returns>
        /// <exception cref="ApiCommunicationException"> </exception>
        /// <exception cref="AuthenticationException"> </exception>
        /// <exception cref="InvalidRequestException"> </exception>
        /// <exception cref="NotAllowedException"> </exception>
        /// <exception cref="ObjectNotFoundException"> </exception>
        /// <exception cref="SystemException"> </exception>
        public static Post Delete(String id, RequestMap parameters)
        {
            RequestMap map = new RequestMap();
            map.Set("id", id);
            map.AddAll (parameters);
            return BaseObject.Execute("dff1a901-b80d-4cdf-a04b-ae5b084f95fb", new Post(map));
        }
        
        
        
        
    }
}


