

using System;
using MasterCard.Core.Model;
using System.Collections.Generic;

namespace TestMasterCard {
  /// <summary>
  /// Test base object.
  /// </summary>
  public class TestReadBaseObject : BaseObject {
    public TestReadBaseObject(RequestMap bm) : base(bm) {
    }

    public TestReadBaseObject() : base() {
    }

    protected override OperationConfig GetOperationConfig(string operationUUID) {
      return new OperationConfig("/test1", "read", new List<string>(), new List<string>());
    }

    protected override OperationMetadata GetOperationMetadata() {
      return new OperationMetadata(ResourceConfig.Instance.GetVersion(), ResourceConfig.Instance.GetHost(), ResourceConfig.Instance.GetContext());
    }

    public static TestReadBaseObject Read() {
      // null is passed in for inputObject, but notice that we do specify the generic type here
      return BaseObject.Execute<TestReadBaseObject>("uuid", null);
    }

    public static TestReadBaseObject Read(RequestMap parameters) {
      return BaseObject.Execute("uuid", new TestReadBaseObject(parameters));
    }
  }
}


