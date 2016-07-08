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

        public override string GetResourcePath(string action) {
            
            if (action == "list") {
               return "/mock_crud_server/posts";
            }
            if (action == "create") {
                return "/mock_crud_server/posts";
            }
            if (action == "read") {
                return "/mock_crud_server/posts/{id}";
            }
            if (action == "update") {
                return "/mock_crud_server/posts/{id}";
            }
            if (action == "delete") {
                return "/mock_crud_server/posts/{id}";
            }
            throw new System.ArgumentException("Invalid action supplied: " + action);
        }


        public override List<string> GetHeaderParams(string action) {
            
            if (action == "list") {
               return new List<String> {  };
            }
            if (action == "create") {
                return new List<String> {  };
            }
            if (action == "read") {
                return new List<String> {  };
            }
            if (action == "update") {
                return new List<String> {  };
            }
            if (action == "delete") {
                return new List<String> {  };
            }
            throw new System.ArgumentException("Invalid action supplied: " + action);
        }

        public override List<string> GetQueryParams(string action)
        {

            if (action == "list")
            {
                return new List<String> { };
            }
            if (action == "create")
            {
                return new List<String> { };
            }
            if (action == "read")
            {
                return new List<String> { };
            }
            if (action == "update")
            {
                return new List<String> { };
            }
            if (action == "delete")
            {
                return new List<String> { };
            }
            throw new System.ArgumentException("Invalid action supplied: " + action);
        }

        public override string GetApiVersion()
        {
            return "0.0.1";
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
        public static List<Post> doList()
        {
            return BaseObject.listObjects(new Post());
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
        public static List<Post> doList(RequestMap criteria)
        {
            return BaseObject.listObjects(new Post(criteria));
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
        public static Post doCreate(RequestMap map)
        {
            return (Post) BaseObject.createObject(new Post(map));
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
        public static Post doFind(String id,  RequestMap parameters = null)
        {
            RequestMap map = new RequestMap();
            map.Set("id", id);
		    if (parameters != null && parameters.Count > 0) {
		        map.AddAll (parameters);
            }
            return (Post) BaseObject.readObject(new Post(map));
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
        public Post doUpdate()
        {
            return  this.updateObject(this);
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
        public Post doDelete()
        {
            return this.deleteObject(this);
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
        public static Post doDelete(String id)
        {
            Post currentObject = new Post(new RequestMap("id", id));
            return currentObject.doDelete();
        }
        
        
        
        
    }
}



