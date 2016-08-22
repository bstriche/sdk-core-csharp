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


        protected override OperationConfig GetOperationConfig(string operationUUID)
        {
            switch (operationUUID)
            {
                case "list":
                    return new OperationConfig("/mock_crud_server/users", "list", new List<string>(), new List<string>());
                case "create":
                    return new OperationConfig("/mock_crud_server/users", "create", new List<string>(), new List<string>());
                case "read":
                    return new OperationConfig("/mock_crud_server/users/{id}", "read", new List<string>(), new List<string>());
                case "update":
                    return new OperationConfig("/mock_crud_server/users/{id}", "update", new List<string>(), new List<string>());
                case "delete":
                    return new OperationConfig("/mock_crud_server/users/{id}", "delete", new List<string>(), new List<string>());
                default:
                    throw new System.ArgumentException("Invalid operationUUID supplied: " + operationUUID);
            }
        }

        protected override OperationMetadata GetOperationMetadata()
        {
            return new OperationMetadata("0.0.1", "http://localhost:8081");
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
            return BaseObject.ExecuteForList("list",new User());
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
            return BaseObject.ExecuteForList("list",new User(criteria));
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
            return (User) BaseObject.Execute("create",new User(map));
        }
        
        
        
        
        
        
        
        
        
        
        
        /// <summary>
        /// Retrieves one object of type <code>User</code>
        /// </summary>
        /// <param name="id">The unique identifier which is used to identify an User object.</param>
        /// <param name = "parameters">This is the optional paramter which can be passed to the request.</param>
        /// <returns> A User object </returns>
        /// <exception cref="ApiCommunicationException"> </exception>
        /// <exception cref="AuthenticationException"> </exception>
        /// <exception cref="InvalidRequestException"> </exception>
        /// <exception cref="NotAllowedException"> </exception>
        /// <exception cref="ObjectNotFoundException"> </exception>
        /// <exception cref="SystemException"> </exception>
        public static User Read(String id,  RequestMap parameters = null)
        {
            RequestMap map = new RequestMap();
            map.Set("id", id);
		    if (parameters != null && parameters.Count > 0) {
		        map.AddAll (parameters);
            }
            return BaseObject.Execute("read",new User(map));
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
            return  BaseObject.Execute("update",this);
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
            return BaseObject.Execute("delete",this);
        }

        /// <summary>
        /// Delete an object of type <code>User</code>
        /// </summary>
        /// <param name="id">The unique identifier which is used to identify an User object.</praram>
        /// <returns> A User object </returns>
        /// <exception cref="ApiCommunicationException"> </exception>
        /// <exception cref="AuthenticationException"> </exception>
        /// <exception cref="InvalidRequestException"> </exception>
        /// <exception cref="NotAllowedException"> </exception>
        /// <exception cref="ObjectNotFoundException"> </exception>
        /// <exception cref="SystemException"> </exception>
        public static User Delete(String id)
        {
            User currentObject = new User(new RequestMap("id", id));
            return currentObject.Delete();
        }
        
        
        
        
    }
}



