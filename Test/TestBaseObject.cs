

using System;
using MasterCard.Core.Model;
using System.Collections.Generic;

namespace TestMasterCard
{
	/// <summary>
	/// Test base object.
	/// </summary>
	public class TestPathBaseObject : BaseObject
	{
		public TestPathBaseObject(RequestMap bm) : base(bm)
		{
		}

		public TestPathBaseObject() : base()
		{
		}

		public override string GetResourcePath (String action)
		{
			return "/group/{group_id}/user/{user_id}";
		}

		public override List<string> GetHeaderParams(string action) 
		{
			return new List<String> {  };
		}

        public override List<string> GetQueryParams(string action)
        {
            return new List<String> { };
        }

        public override string GetApiVersion()
        {
            return "0.0.1";
        }
    }
}


