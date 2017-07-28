using System;
using System.Collections.Generic;
using MasterCard.Core.Model;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace TestMasterCard
{
    class TestApiController : MasterCard.Core.ApiController
    {

        public TestApiController() : base()
        {

        }

        public RestyRequest GetRequest(OperationConfig config, OperationMetadata metadata, RequestMap requestMap)
        {
            return base.GetRequest(config, metadata, requestMap);
        }

    }
}
