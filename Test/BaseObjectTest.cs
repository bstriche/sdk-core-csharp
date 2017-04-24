using System;
using System.Net;
using System.Collections.Generic;
using NUnit.Framework;
using Newtonsoft.Json;
using RestSharp;
using Moq;


using MasterCard.Core;
using MasterCard.Core.Model;
using MasterCard.Core.Security.OAuth;
using MasterCard.Core.Exceptions;
using Environment = MasterCard.Core.Model.Constants.Environment;

namespace TestMasterCard {

  [TestFixture()]
  public class BaseObjectTest {

    [SetUp]
    public void setup() {
      var currentPath = MasterCard.Core.Util.GetCurrenyAssemblyPath();
      var authentication = new OAuthAuthentication(
        "L5BsiPgaF-O3qA36znUATgQXwJB6MRoMSdhjd7wt50c97279!50596e52466e3966546d434b7354584c4975693238513d3d",
        currentPath + @"\Test\mcapi_sandbox_key.p12",
        null, // key alias is not used internally, so passing in null is ok
        "password"
      );
      ApiConfig.SetAuthentication(authentication);

      // set the localhost for testing
      ApiConfig.SetEnvironment(Environment.OTHER);
      ResourceConfig.Instance.setHostOverride();
    }


    [Test]
    public void TestNull_inputObject() {
      // tests for if passing in null for inputObject (see: TestReadBaseObject.Read()) to BaseObject.Execute properly creates a new instance of the object
      TestReadBaseObject response = TestReadBaseObject.Read();

      Assert.IsNotNull(response);
    }

  }
}
