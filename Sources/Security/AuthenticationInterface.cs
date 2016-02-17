using System;
using RestSharp;


namespace MasterCard.SDK.Security
{
	public interface AuthenticationInterface
	{

		void sign(Uri uri, IRestRequest request);

	}
}

