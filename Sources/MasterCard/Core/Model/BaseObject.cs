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

		public abstract string GetResourcePath(string action);

		public abstract List<string> GetHeaderParams (string action);

        public abstract List<string> GetQueryParams(string action);

        public abstract string GetApiVersion();


        /// <summary>
        /// Updates the object.
        /// </summary>
        /// <returns>The object.</returns>
        /// <param name="inputObject">request object.</param>
        protected internal static T queryObject<T> (T inputObject) where T : BaseObject
		{
			return execute ("query", inputObject);
		}

		/// <summary>
		/// Finds the object.
		/// </summary>
		/// <returns>The object.</returns>
		/// <param name = "inputObject"></param>
		protected internal static T readObject<T> (T inputObject) where T : BaseObject 
		{
			return execute ("read", inputObject);
		}


		/// <summary>
		/// Lists the objects.
		/// </summary>
		/// <returns>The objects.</returns>
		/// <param name="inputObject"></param>
		/// <typeparam name="T">The 1st type parameter.</typeparam>
		protected internal static ResourceList<T> listObjects<T> (T inputObject) where T : BaseObject
		{
			T tmpObjectWithList =  execute ("list", inputObject);
			return new ResourceList<T> (tmpObjectWithList);
		}

		/// <summary>
		/// Creates the object.
		/// </summary>
		/// <returns>The object.</returns>
		/// <param name="inputObject">request object.</param>
		protected internal static T createObject<T> (T inputObject) where T : BaseObject
		{
			return execute ("create", inputObject);
		}

		/// <summary>
		/// Updates the object.
		/// </summary>
		/// <returns>The object.</returns>
		/// <param name="inputObject">request object.</param>
		protected internal virtual T updateObject<T> (T inputObject) where T : BaseObject
		{
			return execute ("update", inputObject);
		}


		/// <summary>
		/// Deletes the object.
		/// </summary>
		/// <returns>The object.</returns>
		/// <param name="inputObject">request object.</param>
		protected internal virtual T deleteObject<T> (T inputObject) where T : BaseObject
		{
			return execute ("delete", inputObject);
		}


		/// <summary>
		/// Execute the specified action and inputObject.
		/// </summary>
		/// <param name="action">Action.</param>
		/// <param name="inputObject">Input object.</param>
		static T execute<T>(String action, T inputObject) where T : BaseObject {
            ApiController apiController = new ApiController(inputObject.GetApiVersion());
			IDictionary<String,Object> response = apiController.execute (action, inputObject.GetResourcePath(action), inputObject, inputObject.GetHeaderParams(action), inputObject.GetQueryParams(action));

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