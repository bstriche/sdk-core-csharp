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
using MasterCard.Core.Security;
using MasterCard.Core.Exceptions;
using System.Reflection;

namespace MasterCard.Core.Model
{

	public abstract class BaseObject : BaseMap
	{
		protected internal abstract string ObjectType { get; }
		protected internal abstract String BasePath { get; }


		protected BaseObject() : base()
		{
		}

		protected BaseObject(BaseMap bm) : base(bm) {
		}

		protected BaseObject (IDictionary<String, Object> map) : base(map)
		{
		}


		/// <summary>
		/// Finds the object.
		/// </summary>
		/// <returns>The object.</returns>
		/// <param name = "inputObject"></param>
		protected internal static BaseObject findObject (BaseObject inputObject)
		{
			return execute ("show", inputObject);
		}


		/// <summary>
		/// Lists the objects.
		/// </summary>
		/// <returns>The objects.</returns>
		/// <param name="template">Template.</param>
		/// <param name="criteria">Criteria.</param>
		/// <typeparam name="T">The 1st type parameter.</typeparam>
		protected internal static ResourceList<T> listObjects<T> (T template, BaseObject criteria) where T : BaseObject
		{

			ResourceList<T> listResults = new ResourceList<T> ();

			ApiController apiController = new ApiController (template.BasePath);

			IDictionary<String, Object> response = apiController.execute (template.ObjectType, "list", criteria);
			listResults.AddAll (response);


			IList<T> val = null;
			if (listResults.ContainsKey ("list")) {
				IList<IDictionary<string, object>> rawList = (IList<IDictionary<string, object>>)listResults.Get ("list");

				val = new List<T> (((IList)rawList).Count);
				foreach (object o in (IList) rawList) {
					if (o is IDictionary) {
						T item = (T)template.Clone ();
						item.AddAll ((IDictionary<String, Object>)o);
						val.Add (item);
					}
				}
			} else {
				val = new List<T> ();
			}
			listResults.Add ("list", val);
			return listResults;

		}

		/// <summary>
		/// Creates the object.
		/// </summary>
		/// <returns>The object.</returns>
		/// <param name="inputObject">Payments object.</param>
		protected internal static BaseObject createObject (BaseObject inputObject)
		{

			return execute ("create", inputObject);

		}

		/// <summary>
		/// Updates the object.
		/// </summary>
		/// <returns>The object.</returns>
		/// <param name="inputObject">Payments object.</param>
		protected internal virtual BaseObject updateObject (BaseObject inputObject)
		{

			return execute ("update", inputObject);

		}


		/// <summary>
		/// Deletes the object.
		/// </summary>
		/// <returns>The object.</returns>
		/// <param name="inputObject">Payments object.</param>
		protected internal virtual BaseObject deleteObject (BaseObject inputObject)
		{

			return execute ("delete", inputObject);
		}


		/// <summary>
		/// Execute the specified action and inputObject.
		/// </summary>
		/// <param name="action">Action.</param>
		/// <param name="inputObject">Input object.</param>
		private static BaseObject execute(String action, BaseObject inputObject) {
			ApiController apiController = new ApiController (inputObject.BasePath);
			IDictionary<String,Object> response = apiController.execute (inputObject.ObjectType, action, inputObject);

			if (response != null)
				inputObject.AddAll (response);

			return inputObject;
		}


			
	}

}