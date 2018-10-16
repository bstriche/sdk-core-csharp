using RestSharp;
using System;
using System.Collections.Generic;
using System.Text;

namespace Test
{
    class MockRestResponse : RestResponse, IRestResponse
    {
        public new IList<Parameter> Headers { get; set; }

    }
}
