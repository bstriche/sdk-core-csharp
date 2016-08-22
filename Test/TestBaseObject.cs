

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

        protected override OperationConfig GetOperationConfig(string operationUUID)
        {
            return new OperationConfig("/group/{group_id}/user/{user_id}", "create", new List<string>(), new List<string>());
        }

        protected override OperationMetadata GetOperationMetadata()
        {
            return new OperationMetadata("0.0.1", null);
        }
    }
}


