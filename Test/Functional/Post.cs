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

        protected override OperationConfig GetOperationConfig(string operationUUID)
        {
            switch (operationUUID)
            {
                case "list":
                    return new OperationConfig("/mock_crud_server/posts", "list", new List<string>(), new List<string>());
                case "create":
                    return new OperationConfig("/mock_crud_server/posts", "create", new List<string>(), new List<string>());
                case "read":
                    return new OperationConfig("/mock_crud_server/posts/{id}", "read", new List<string>(), new List<string>());
                case "update":
                    return new OperationConfig("/mock_crud_server/posts/{id}", "update", new List<string>(), new List<string>());
                case "delete":
                    return new OperationConfig("/mock_crud_server/posts/{id}", "delete", new List<string>(), new List<string>());
                default:
                    throw new System.ArgumentException("Invalid operationUUID supplied: " + operationUUID);
            }
        }

        protected override OperationMetadata GetOperationMetadata()
        {
            return new OperationMetadata("0.0.1", "http://localhost:8081");
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
            return BaseObject.ExecuteForList("list", new Post());
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
            return BaseObject.ExecuteForList("list", new Post(criteria));
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
            return BaseObject.Execute("create",new Post(map));
        }
        
        
        
        
        
        
        
        
        
        
        
        /// <summary>
        /// Retrieves one object of type <code>Post</code>
        /// </summary>
        /// <param name="id">The unique identifier which is used to identify an Post object.</param>
        /// <param name = "parameters">This is the optional paramter which can be passed to the request.</param>
        /// <returns> A Post object </returns>
        /// <exception cref="ApiCommunicationException"> </exception>
        /// <exception cref="AuthenticationException"> </exception>
        /// <exception cref="InvalidRequestException"> </exception>
        /// <exception cref="NotAllowedException"> </exception>
        /// <exception cref="ObjectNotFoundException"> </exception>
        /// <exception cref="SystemException"> </exception>
        public static Post Read(String id,  RequestMap parameters = null)
        {
            RequestMap map = new RequestMap();
            map.Set("id", id);
		    if (parameters != null && parameters.Count > 0) {
		        map.AddAll (parameters);
            }
            return BaseObject.Execute("read",new Post(map));
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
            return  BaseObject.Execute("update", this);
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
            return BaseObject.Execute("delete", this);
        }

        /// <summary>
        /// Delete an object of type <code>Post</code>
        /// </summary>
        /// <param name="id">The unique identifier which is used to identify an Post object.</praram>
        /// <returns> A Post object </returns>
        /// <exception cref="ApiCommunicationException"> </exception>
        /// <exception cref="AuthenticationException"> </exception>
        /// <exception cref="InvalidRequestException"> </exception>
        /// <exception cref="NotAllowedException"> </exception>
        /// <exception cref="ObjectNotFoundException"> </exception>
        /// <exception cref="SystemException"> </exception>
        public static Post Delete(String id)
        {
            Post currentObject = new Post(new RequestMap("id", id));
            return currentObject.Delete();
        }
        
        
        
        
    }
}



