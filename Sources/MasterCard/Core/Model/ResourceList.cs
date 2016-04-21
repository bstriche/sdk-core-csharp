using System;
using System.Collections.Generic;

namespace MasterCard.Core.Model
{
	public class ResourceList<T> : List<T> where T : BaseObject
	{

		public ResourceList (IDictionary<String, Object> map) : base()
		{
			if (map.ContainsKey ("list") && typeof(List<Dictionary<String,Object>>) == map["list"].GetType ()) {
				List<Dictionary<String,Object>> list = (List<Dictionary<String,Object>>) map["list"];
				Type type = this.GetType ().GetGenericArguments () [0];
				foreach (Dictionary<String,Object> item in list) {
					T tmpObject = (T) Activator.CreateInstance (type);
					tmpObject.AddAll (item);
					this.Add (tmpObject);
				}
			}
		}

	}
}

