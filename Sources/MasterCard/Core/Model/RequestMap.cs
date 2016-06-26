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
using Newtonsoft.Json;
using Newtonsoft.Json.Converters;
using Newtonsoft.Json.Linq;
using System.Text.RegularExpressions;

namespace MasterCard.Core.Model
{


	/// <summary>
	/// Map object that extends the LinkedHashMap map with support for insertion and retrieval of keys using special
	/// key path values.  The key path support nested maps and array values.
	/// <para>
	/// A key path consists of a sequence of key values separated by '.' characters.  Each part of the key path
	/// consists of a separate map.  For example a key path of 'k1.k2.k3' is a map containing a key 'k1' whose
	/// value is a map containing a key 'k2' whose values is a map containing a key 'k3'.   A key path can also
	/// contain an array notation '[<number'] in which case the value of 'a' in the map is a list containing
	/// a map.  For example 'a[1].k2' refers to the key value 'k2' in the 2nd element of the list referred to by
	/// the value of key 'a' in the map.  If no index value is given (i.e., '[]') then a put() method appends
	/// to the list while a get() method returns the last value in the list.
	/// </para>
	/// <para>
	/// When using the array index notation the value inserted must be a map; inserting values is not permitted.
	/// For example using <code>put("a[3].k1", 1)</code> is permitted while <code>put("a[3]", 1)</code> results
	/// in an <code>IllegalArgumentException</code>.
	/// </para>
	/// <para>
	/// 
	/// Examples:
	/// <pre>
	/// BaseMap map  = new BaseMap();
	/// map.put("card.number", "5555555555554444");
	/// map.put("card.cvc", "123");
	/// map.put("card.expMonth", 5);
	/// map.put("card.expYear", 15);
	/// map.put("currency", "USD");
	/// map.put("amount", 1234);
	/// </pre>
	/// There is also an set() method which is similar to put() but returns the map providing a fluent map builder.
	/// <pre>
	/// BaseMap map = new BaseMap()
	///      .set("card.number", "5555555555554444")
	///      .set("card.cvc", "123")
	///      .set("card.expMonth", 5)
	///      .set("card.expYear", 15)
	///      .set("currency", "USD")
	///      .set("amount", 1234);
	/// </pre>
	/// Both of these examples construct a BaseMap containing the keys 'currency', 'amount' and 'card'.  The
	/// value for the 'card' key is a map containing the key 'number', 'cvc', 'expMonth' and 'expYear'.
	/// 
	/// </para>
	/// </summary>
	public class RequestMap : IDictionary<String, Object>
	{


		//VARIABLES.
		private static readonly Regex arrayIndexPattern = new Regex ("(.*)\\[(.*)\\]");
		private Dictionary<String, Object> __storage;


		/// <summary>
		/// Constructs an empty map with the default capacity and load factor.
		/// </summary>
		public RequestMap ()
		{
			__storage = new Dictionary<String, Object> ();
		}


		/// <summary>
		/// Constructs an empty map with the default capacity and load factor.
		/// </summary>
		public RequestMap (RequestMap bm)
		{
			__storage = bm.__storage;
		}

		/// <summary>
		/// Constructs a map with the same mappings as in the specifed map. </summary>
		/// <param name="map"> the map whose mappings are to be placed in this map </param>
		public RequestMap (IDictionary<String, Object> map)
		{
			__storage = new Dictionary<String, Object> ();
			AddAll (map);
		}

		/// <summary>
		/// Consturcts a map based of the speficied JSON string. </summary>
		/// <param name="jsonMapString"> the JSON string used to construct the map </param>
		public RequestMap (string jsonMapString)
		{
			__storage = new Dictionary<String, Object> ();
			AddAll (RequestMap.AsDictionary(jsonMapString));
		}


		/// <summary>
		/// Constructs a map with an initial mapping of keyPath to value. </summary>
		/// <param name = "key">key path with which the specified value is to be associated.</param>
		/// <param name="value"> value to be associated with the specified key path. </param>
		public RequestMap (String key, Object value)
		{
			__storage = new Dictionary<String, Object> ();
			__storage.Add (key, value);
		}

		protected internal void UpdateFromBaseMap(RequestMap baseMapToSet)
		{
			__storage = baseMapToSet.__storage;
		}

		public RequestMap Clone()
		{
			return new RequestMap (__storage);
		}

		/// <summary>
		/// Gets the count.
		/// </summary>
		/// <value>The count.</value>
		public int Count {
			get {
				return __storage.Count;
			}
		}

		/// <summary>
		/// Clear this instance.
		/// </summary>
		public void Clear() {
			__storage.Clear ();
		}


		/// <summary>
		/// Gets or sets the <see cref="MasterCard.Core.Model.BaseMap`2"/> with the specified key.
		/// </summary>
		/// <param name="key">Key.</param>
		public Object this [String key] {
			get {
				return Get (key);
			}
			set {
				Add(key,  value);
			}
		}



		/// <summary>
		/// Associates the specified value to the specified key path. </summary>
		/// <exception cref="IllegalArgumentException"> if part of the key path does not match the expected type. </exception>
		/// <exception cref="IndexOutOfBoundsException"> if using an array index in the key path is out of bounds. </exception>
		public void AddAll (IDictionary<string, object> data)
		{
			foreach (String key in data.Keys) {
				Add (key, data [key]);
			}
		}
			


		/// <summary>
		/// Associates the specified value to the specified key path. </summary>
		/// <param name="keyPath"> key path to which the specified value is to be associated. </param>
		/// <param name="value"> the value which is to be associated with the specified key path. </param>
		/// <exception cref="IllegalArgumentException"> if part of the key path does not match the expected type. </exception>
		/// <exception cref="IndexOutOfBoundsException"> if using an array index in the key path is out of bounds. </exception>
		public void Add (String keyPath, Object value)
		{
			string[] properties = keyPath.Split ('.');
			IDictionary<string, object> destinationObject = __storage;

			if (properties.Length > 1) {
				for (int i = 0; i < (properties.Length - 1); i++) {
					string property = properties [i];
					if (property.Contains ("[")) {
						destinationObject = getDestinationMap (property, destinationObject);
					} else {
						destinationObject = getPropertyMapFrom (property, destinationObject);
					}
				}
			} else if (keyPath.Contains ("[")) {
				destinationObject = getDestinationMap (keyPath, destinationObject);
			}

			// TODO: need to take care of the case where we are inserting a value into an array rather than
			// map ( eg map.put("a[2]", 123);

			if (destinationObject == __storage) {
				__storage [keyPath] = value;
			} else if (value is IDictionary) { // if putting a map, call put all
				destinationObject.Clear ();
				RequestMap newMap = new RequestMap ((Dictionary<String,Object>) value);
				destinationObject [properties [properties.Length - 1]] = newMap;
			} else {
			 	destinationObject [properties [properties.Length - 1]] = value;
			}
		}


		/// <summary>
		/// Associates the specified value to the specified key path and returns a reference to
		/// this map. </summary>
		/// <param name="key"> key path to which the specified value is to be associated. </param>
		/// <param name="value"> the value which is to be associated with the specified key path. </param>
		/// <returns> this map </returns>
		/// <exception cref="IllegalArgumentException"> if part of the key path does not match the expected type. </exception>
		/// <exception cref="IndexOutOfBoundsException"> if using an array index in the key path is out of bounds. </exception>
		public virtual RequestMap Set (string key, object value)
		{
			Add (key, value);
			return this;
		}


		/// <summary>
		/// Returns the value associated with the specified key path or null if there is no associated value. </summary>
		/// <param name="keyPath"> key path whose associated value is to be returned </param>
		/// <returns> the value to which the specified key is mapped </returns>
		/// <exception cref="IllegalArgumentException"> if part of the key path does not match the expected type. </exception>
		/// <exception cref="IndexOutOfBoundsException"> if using an array index in the key path is out of bounds. </exception>
		public Object Get (String keyPath)
		{
			string[] keys = ((string)keyPath).Split ('.');

			if (keys.Length <= 1) {
				Match matcher1 = arrayIndexPattern.Match (keys [0]);
				if (!matcher1.Success) { // handles keyPath: "x"
					Object o;
					__storage.TryGetValue ((String)keys [0], out o);
					return o;
				} else { // handle the keyPath: "x[]"
					string key = matcher1.Groups[1].ToString(); // gets the key to retrieve from the matcher
					Object o;
					__storage.TryGetValue (key, out o); // get the list from the map
					if (!(o is IList)) {
						throw new System.ArgumentException ("Property '" + key + "' is not an array");
					}

					//IList l =  ((IList) o);
					IList l = (IList)o;

					int? index = l.Count - 1; //get last item if none specified
					if (!"".Equals (matcher1.Groups[2].ToString())) {
						index = int.Parse (matcher1.Groups [2].ToString());
					}

					return l[index ?? 0]; // retrieve the map from the list

				}
			}

			IDictionary<String, Object> map = findLastMapInKeyPath (keyPath); // handles keyPaths beyond 'root' keyPath. i.e. "x.y OR x.y[].z, etc."

			// retrieve the value at the end of the object path i.e. x.y.z, this retrieves whatever is in 'z'

            String lastKey = keys[keys.Length - 1];
            Match matcher2 = arrayIndexPattern.Match(lastKey);
            if (!matcher2.Success)
            {
                return map[lastKey];
            }
            else
            {
                string key = matcher2.Groups[1].ToString(); // gets the key to retrieve from the matcher
				Object o;
				map.TryGetValue (key, out o); // get the list from the map
				if (!(o is IList)) {
					throw new System.ArgumentException ("Property '" + key + "' is not an array");
				}

				//IList l =  ((IList) o);
				IList l = (IList)o;

				int? index = l.Count - 1; //get last item if none specified
				if (!"".Equals (matcher2.Groups[2].ToString())) {
					index = int.Parse (matcher2.Groups [2].ToString());
				}

				return l[index ?? 0]; // retrieve the map from the list
            }
            

		}

		/// <summary>
		/// Returns true if there is a value associated with the specified key path. </summary>
		/// <param name="keyPath"> key path whose associated value is to be tested </param>
		/// <returns> true if this map contains an value associated with the specified key path </returns>
		/// <exception cref="IllegalArgumentException"> if part of the key path does not match the expected type. </exception>
		/// <exception cref="IndexOutOfBoundsException"> if using an array index in the key path is out of bounds. </exception>
		public bool ContainsKey (String keyPath)
		{
			string[] keys = ((string)keyPath).Split ('.');

			if (keys.Length <= 1) {
				Match m = arrayIndexPattern.Match (keys [0]);
				if (!m.Success) { // handles keyPath: "x"
					return __storage.ContainsKey (keys [0]);
				} else { // handle the keyPath: "x[]"
					string key = m.Groups[1].ToString();
					Object o;
					__storage.TryGetValue (key, out o); // get the list from the map
					if (!(o is IList)) {
						throw new System.ArgumentException ("Property '" + key + "' is not an array");
					}
					//IList l =  ((IList) o);
					IList<IDictionary<String, Object>> l = (IList<IDictionary<String, Object>>)o;

					int? index = l.Count - 1;
					if (!"".Equals (m.Groups[2].ToString())) {
						index = int.Parse (m.Groups[2].ToString());
					}
					return index >= 0 && index < l.Count;
				}
			}

			IDictionary<String, Object> map = findLastMapInKeyPath (keyPath);
			if (map == null) {
				return false;
			}
			return map.ContainsKey (keys [keys.Length - 1]);
		}


		/// <summary>
		/// Removes the value associated with the specified key path from the map. </summary>
		/// <param name="keyPath"> key path whose associated value is to be removed </param>
		/// <exception cref="IllegalArgumentException"> if part of the key path does not match the expected type. </exception>
		/// <exception cref="IndexOutOfBoundsException"> if using an array index in the key path is out of bounds. </exception>
		public bool Remove (String keyPath)
		{

			string[] keys = ((string)keyPath).Split ('.');

			if (keys.Length <= 1) {
				Match m = arrayIndexPattern.Match (keys [0]);
				if (!m.Success) {
					return __storage.Remove ((String)keys [0]);
				} else { // handle the keyPath: "x[]"
					string key = m.Groups[1].ToString(); // gets the key to retrieve from the matcher
					Object o;
					__storage.TryGetValue ((String)key, out o); // get the list from the map
					if (!(o is IList)) {
						throw new System.ArgumentException ("Property '" + key + "' is not an array");
					}

					//IList l =  ((IList) o);// get the list from the map

					IList<IDictionary<String, Object>> l = (IList<IDictionary<String, Object>>)o;

					int? index = (l.Count - 1); //get last item if none specified
					if (!"".Equals (m.Groups[2].ToString())) {
						index = int.Parse (m.Groups[2].ToString());
					}

					if (index != null) {
						l.RemoveAt (index ?? 0);
					}

				}
			}

			IDictionary<string, object> map = findLastMapInKeyPath (keyPath);

			return map.Remove (keys [keys.Length - 1]);
		}

		/// <summary>
		/// Finds the last map in key path.
		/// </summary>
		/// <returns>The last map in key path.</returns>
		/// <param name="keyPath">Key path.</param>
		private IDictionary<string, object> findLastMapInKeyPath (String keyPath)
		{
			string[] keys = ((string)keyPath).Split ('.');

			IDictionary<string, object> map = null;
			for (int i = 0; i <= (keys.Length - 2); i++) {
				Match m = arrayIndexPattern.Match (keys [i]);
				string thisKey = keys [i];
				if (m.Success) {
					thisKey = m.Groups[1].ToString();

					Object o = null;
					if (null == map) { // if we are at the "root" of the object path
						__storage.TryGetValue ((String)thisKey, out o);
					} else {
						o = map [thisKey];
					}

					if (!(o is IList)) {
						throw new System.ArgumentException ("Property '" + thisKey + "' is not an array");
					}

					IList l = (IList)  o;


					int? index = l.Count - 1; //get last item if none specified

					if (!"".Equals (m.Groups[2].ToString())) {
						index = int.Parse (m.Groups[2].ToString());
					}

					map = (IDictionary<String, Object>)l[index ?? 0];

				} else {
					if (null == map) {
						try {
							Object tmpOut = __storage [thisKey];
							if(tmpOut.GetType() == typeof(JObject)) {
                                map = ((JObject)tmpOut).ToObject<Dictionary<string, object>>();
							} else {
								map = (IDictionary<String, Object>)tmpOut;
							}
						} catch  {
							return null;
						}

					} else {
                        Object tmpOut = map[thisKey];
                        if (tmpOut.GetType() == typeof(JObject))
                        {
                            map = ((JObject)tmpOut).ToObject<Dictionary<string, object>>();
                        }
                        else
                        {
                            map = (IDictionary<String, Object>)tmpOut;
                        }
					}

				}

			}

			return map;
		}

		/// <summary>
		/// Gets the destination map.
		/// </summary>
		/// <returns>The destination map.</returns>
		/// <param name="property">Property.</param>
		/// <param name="destinationObject">Destination object.</param>
		private static IDictionary<string, object> getDestinationMap (string property, IDictionary<string, object> destinationObject)
		{

			Match m = arrayIndexPattern.Match (property);
			if (m.Success) {
				string propName = m.Groups[1].ToString();
				int? index = null;
				if (!"".Equals (m.Groups[2].ToString())) {
					index = int.Parse (m.Groups[2].ToString());
				}
				return findOrAddToList (destinationObject, propName, index);
			}

			return destinationObject;

		}

		/// <summary>
		/// Finds the or add to list.
		/// </summary>
		/// <returns>The or add to list.</returns>
		/// <param name="destinationObject">Destination object.</param>
		/// <param name="propName">Property name.</param>
		/// <param name="index">Index.</param>
		private static IDictionary<String, Object> findOrAddToList (IDictionary<String, Object> destinationObject, string propName, int? index)
		{
			//

			IList<IDictionary<String, Object>> list = new List<IDictionary<String, Object>> ();
			// find existing list or put the new list
			if (destinationObject.ContainsKey (propName)) {
				object o = destinationObject [propName];
				if (!(o is IList)) {
					throw new System.ArgumentException ("Property '" + propName + "' is not an array");
				}
				list = (IList<IDictionary<string, object>>)o;
			} else {
				destinationObject [propName] = list;
			}

			// get the existing object in the list at the index
			IDictionary<String, Object> propertyValue = null;
			if (index != null && list.Count > index) {
				propertyValue = list [index ?? 0];
			}

			// no object at the index, create a new map and add it
			if (null == propertyValue) {
				propertyValue = new Dictionary<String, Object> ();
				if (null == index) {
					list.Add (propertyValue);
				} else {
					list.Insert (index ?? 0, propertyValue);
				}
			}

			// return the map retrieved from or added to the list
			destinationObject = propertyValue;

			return destinationObject;
		}

		/// <summary>
		/// Gets the property map from.
		/// </summary>
		/// <returns>The property map from.</returns>
		/// <param name="property">Property.</param>
		/// <param name="object">Object.</param>
		private static IDictionary<String, Object> getPropertyMapFrom (string property, IDictionary<String, Object> @object)
		{
			// create a new map at the key specified if it doesnt already exist
			if (!@object.ContainsKey (property)) {
				IDictionary<string, object> val = new Dictionary<string, object> ();
				@object [property] = val;
			}

			object o = @object [property];
			if (o is IDictionary) {
				return (IDictionary<string, object>)o;
			} else {
				throw new System.ArgumentException ("cannot change nested property to map");
			}
		}

		/// <summary>
		/// Deserializes json nested maps in a proppery nested dictionary<String,Object>.
		/// </summary>
		/// <returns>The deep.</returns>
		/// <param name="json">Json.</param>
		public static IDictionary<String,Object> AsDictionary(String json)
		{
			try {
				return JsonConvert.DeserializeObject<IDictionary<string, object>>(
					json, new JsonConverter[] {new CustomDictionaryConverter()});
			} catch (Exception) {
				List<Dictionary<String,Object>> intermediaryResult = JsonConvert.DeserializeObject<List<Dictionary<String,Object>>> (json);
				return new Dictionary<String,Object>() { { "list", intermediaryResult} };
			}
		}


		/// <summary>
		/// Gets the enumerator.
		/// </summary>
		/// <returns>The enumerator.</returns>
		IEnumerator<KeyValuePair<string, object>> IEnumerable<KeyValuePair<string, object>>.GetEnumerator ()
		{
			return __storage.GetEnumerator ();
		}


		/// <summary>
		/// Gets the enumerator.
		/// </summary>
		/// <returns>The enumerator.</returns>
		public IEnumerator GetEnumerator ()
		{
			//throw new NotImplementedException ();
			return GetEnumerator();
		}

		/// <summary>
		/// Gets the enumerator.
		/// </summary>
		/// <returns>The enumerator.</returns>
		IEnumerator IEnumerable.GetEnumerator ()
		{
			//throw new NotImplementedException ();
			return __storage.GetEnumerator ();
		}

		/// <summary>
		/// Gets the keys.
		/// </summary>
		/// <value>The keys.</value>
		ICollection<string> IDictionary<string, object>.Keys {
			get {
				return __storage.Keys;
			}
		}

		/// <summary>
		/// Gets the values.
		/// </summary>
		/// <value>The values.</value>
		ICollection<object> IDictionary<string, object>.Values {
			get {
				return __storage.Values;
			}
		}

		/// <summary>
		/// Tries the get value.
		/// </summary>
		/// <returns><c>true</c>, if get value was tryed, <c>false</c> otherwise.</returns>
		/// <param name="key">Key.</param>
		/// <param name="value">Value.</param>
		bool IDictionary<string, object>.TryGetValue (string key, out object value)
		{
				value = Get (key) ;
				return true;
		}

		/// <summary>
		/// Add the specified item.
		/// </summary>
		/// <param name="item">Item.</param>
		void ICollection<KeyValuePair<string, object>>.Add (KeyValuePair<string, object> item)
		{
			Add(item.Key, item.Value);
		}

		/// <summary>
		/// Clear this instance.
		/// </summary>
		void ICollection<KeyValuePair<string, object>>.Clear ()
		{
			__storage.Clear ();
		}

		/// <summary>
		/// Contains the specified item.
		/// </summary>
		/// <param name="item">Item.</param>
		bool ICollection<KeyValuePair<string, object>>.Contains (KeyValuePair<string, object> item)
		{
			return __storage.ContainsKey (item.Key);
		}

		/// <summary>
		/// Copies to.
		/// </summary>
		/// <param name="array">Array.</param>
		/// <param name="arrayIndex">Array index.</param>
		void ICollection<KeyValuePair<string, object>>.CopyTo (KeyValuePair<string, object>[] array, int arrayIndex)
		{
			((ICollection<KeyValuePair<string, object>>)__storage).CopyTo (array, arrayIndex);
		}

		/// <summary>
		/// Remove the specified item.
		/// </summary>
		/// <param name="item">Item.</param>
		bool ICollection<KeyValuePair<string, object>>.Remove (KeyValuePair<string, object> item)
		{
			return ((ICollection<KeyValuePair<string, object>>)__storage).Remove (item);
		}

		/// <summary>
		/// Gets a value indicating whether this instance is read only.
		/// </summary>
		/// <value><c>true</c> if this instance is read only; otherwise, <c>false</c>.</value>
		bool ICollection<KeyValuePair<string, object>>.IsReadOnly {
			get {
				return ((ICollection<KeyValuePair<string, object>>)__storage).IsReadOnly;
			}
		}


        private class MyConverter : CustomCreationConverter<IDictionary<string, object>>
        {
            public override IDictionary<string, object> Create(Type objectType)
            {
                return new Dictionary<string, object>();
            }

            public override bool CanConvert(Type objectType)
            {
                // in addition to handling IDictionary<string, object>
                // we want to handle the deserialization of dict value
                // which is of type object
                return objectType == typeof(object) || base.CanConvert(objectType);
            }

            public override object ReadJson(JsonReader reader, Type objectType, object existingValue, JsonSerializer serializer)
            {
                if (reader.TokenType == JsonToken.StartObject
                    || reader.TokenType == JsonToken.Null)
                    return base.ReadJson(reader, objectType, existingValue, serializer);

                // if the next token is not an object
                // then fall back on standard deserializer (strings, numbers etc.)
                return serializer.Deserialize(reader);
            }
        }

        /// <summary>
        /// Json custom converter.
        /// </summary>
        private class CustomDictionaryConverter : CustomCreationConverter<IDictionary<string, object>>
		{
			public override IDictionary<string, object> Create(Type objectType)
			{
				return new Dictionary<string, object>();
			}

			public override bool CanConvert(Type objectType)
			{
				// in addition to handling IDictionary<string, object>
				// we want to handle the deserialization of dict value
				// which is of type object

				bool isDictionary = objectType.IsGenericType && objectType.GetGenericTypeDefinition() == typeof(IDictionary<,>);
				bool isObject = objectType == typeof(object);

				return isObject || base.CanConvert(objectType);
			}

			public override object ReadJson(JsonReader reader, Type objectType, object existingValue, JsonSerializer serializer)
			{
				if (reader.TokenType == JsonToken.StartObject || reader.TokenType == JsonToken.Null) {
					var result1 =  base.ReadJson(reader, objectType, existingValue, serializer);
					return result1;
				}
					

				// if the next token is not an object
				// then fall back on standard deserializer (strings, numbers etc.)
				var result2 = serializer.Deserialize(reader);
				if (result2.GetType() == typeof(JArray)) {
                    if (((JArray)result2).First.Type.ToString() == "String")
                    {
                        result2 = ((JArray)result2).ToObject<List<object>>();
                    } else
                    {
                        result2 = ((JArray)result2).ToObject<List<Dictionary<string, object>>>();
                    }
					
				}

                if (result2.GetType() == typeof(JObject))
                {
                    result2 = ((JObject)result2).ToObject<Dictionary<string,object>>();
                }

                return result2;
			}
		}
			
	}


}