

using System;
using MasterCard.Core.Model;
using System.Collections.Generic;

namespace TestMasterCard
{
	/// <summary>
	/// Test base object.
	/// </summary>
	public class TestBaseObject : BaseObject
	{
		public TestBaseObject(RequestMap bm) : base(bm)
		{
		}

		public TestBaseObject() : base()
		{
		}



		public override string GetResourcePath (String action)
		{
			return "/testurl/test-base-object";
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


