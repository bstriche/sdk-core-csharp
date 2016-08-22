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
using System.Collections;
using System.Collections.Generic;

namespace MasterCard.Core.Model
{

	public abstract class BaseObject : RequestMap
	{

		protected BaseObject() : base()
		{
		}

		protected BaseObject(RequestMap bm) : base(bm) {
		}

		protected BaseObject (IDictionary<String, Object> map) : base(map)
		{
		}

        protected abstract OperationConfig GetOperationConfig(string operationUUID);

        protected abstract OperationMetadata GetOperationMetadata();


        /// <summary>
        /// Execute operation expecting to return a list
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="operationUUID"></param>
        /// <param name="inputObject"></param>
        /// <returns></returns>
        protected static ResourceList<T> ExecuteForList<T>(string operationUUID, T inputObject) where T : BaseObject
        {
            T tmpObjectWithList = Execute(operationUUID, inputObject);
            return new ResourceList<T>(tmpObjectWithList);
        }



        /// <summary>
        /// Execute operation expecting to return an Object
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="operationUUID"></param>
        /// <param name="inputObject"></param>
        /// <returns></returns>
        protected static T Execute<T>(string operationUUID, T inputObject) where T : BaseObject {
            ApiController apiController = new ApiController(inputObject.GetOperationMetadata().Version);

            IDictionary<String,Object> response = apiController.Execute (inputObject.GetOperationConfig(operationUUID), inputObject.GetOperationMetadata(), inputObject);

			if (response != null) {
				inputObject.Clear ();
				inputObject.AddAll (response);
			} else {
				inputObject = (T) Activator.CreateInstance (inputObject.GetType ());
				inputObject.AddAll (response);
			}
			return inputObject;
		}


			
	}

}