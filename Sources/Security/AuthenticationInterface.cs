using System;
using RestSharp;


namespace MasterCard.SDK.Core.Security
{
	public interface AuthenticationInterface
	{

		void sign(Uri uri, IRestRequest request);

	}
}

