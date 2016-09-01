using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using RestSharp;
using MasterCard.Core.Security;

namespace MasterCard.Core.Model
{
    class RestyRequest : RestRequest
    {
        public Uri AbsoluteUrl { get; set; }
        public Uri BaseUrl { get; set; }
        public CryptographyInterceptor interceptor { get; set; }

        public RestyRequest(Uri url, Method method) : base(url,method)
        {
        }

    }
}
