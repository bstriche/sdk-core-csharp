

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

        protected override OperationConfig GetOperationConfig(string operationUUID)
        {
            return new OperationConfig("/testurl/test-base-object", "create", new List<string>(), new List<string>());
        }

        protected override OperationMetadata GetOperationMetadata()
        {
            return new OperationMetadata("0.0.1", null);
        }
    }
}


